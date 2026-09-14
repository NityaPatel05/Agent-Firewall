"""Markdown/HTML link extraction and the final-answer sanitizer (rendered images/links are egress sinks)."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict

from firewall.core.canonical import canonicalize, url_parts
from firewall.core.labels import Integrity
from firewall.core.models import (
    ArgRole,
    ArgType,
    Finding,
    OriginClass,
    SanitizedText,
    SideEffect,
    Stage,
    Verdict,
)
from firewall.core.provenance import resolve_origin
from firewall.core.registry import ArgSpec
from firewall.core.session import SessionView
from firewall.core.sinks import _allowlisted_url, url_param_findings

if TYPE_CHECKING:
    from firewall.core.policy.loader import CompiledPolicy

LinkKind = Literal["inline", "image", "reference", "reference_image", "autolink", "bare", "html_a", "html_img"]

_URL = r"<?(?P<url>[^)\s>]+)>?(?:\s+[\"'(][^\"')]*[\"')])?"
INLINE_RE = re.compile(r"(?P<bang>!?)\[(?P<text>[^\]\n]*)\]\(\s*" + _URL + r"\s*\)")
REF_USE_RE = re.compile(r"(?P<bang>!?)\[(?P<text>[^\]\n]*)\]\[(?P<id>[^\]\n]*)\]")
REF_DEF_RE = re.compile(r"(?m)^[ \t]{0,3}\[(?P<id>[^\]\n]+)\]:[ \t]*<?(?P<url>\S+?)>?(?:[ \t]+[\"'(].*)?[ \t]*$\n?")
AUTOLINK_RE = re.compile(r"<(?P<url>https?://[^>\s]+)>", re.IGNORECASE)
BARE_RE = re.compile(r"(?i)\bhttps?://[^\s<>\"'`\]\[)(]+")
HTML_A_RE = re.compile(r"(?is)<a\s[^>]*?href\s*=\s*[\"'](?P<url>[^\"']+)[\"'][^>]*>(?P<text>.*?)</a>")
HTML_IMG_RE = re.compile(r"(?is)<img\s[^>]*?src\s*=\s*[\"'](?P<url>[^\"']+)[\"'][^>]*>")
_IMAGE_KINDS = frozenset({"image", "reference_image", "html_img"})


class LinkRef(BaseModel):
    model_config = ConfigDict(frozen=True)
    kind: LinkKind
    text: str
    url: str
    span: tuple[int, int]
    ref_id: str | None = None


def _overlaps(span: tuple[int, int], taken: list[tuple[int, int]]) -> bool:
    return any(a < span[1] and span[0] < b for a, b in taken)


def reference_definitions(md: str) -> dict[str, tuple[str, tuple[int, int]]]:
    return {m.group("id").strip().lower(): (m.group("url"), m.span()) for m in REF_DEF_RE.finditer(md)}


def extract_links(md: str) -> list[LinkRef]:
    """Inline, image, reference(-image), autolink, bare URL, <a href> and <img src> links (sorted by position)."""
    defs = reference_definitions(md)
    taken: list[tuple[int, int]] = [span for _, span in defs.values()]
    out: list[LinkRef] = []
    for m in HTML_IMG_RE.finditer(md):
        out.append(LinkRef(kind="html_img", text="", url=m.group("url"), span=m.span()))
        taken.append(m.span())
    for m in HTML_A_RE.finditer(md):
        out.append(LinkRef(kind="html_a", text=m.group("text"), url=m.group("url"), span=m.span()))
        taken.append(m.span())
    for m in INLINE_RE.finditer(md):
        if _overlaps(m.span(), taken):
            continue
        out.append(LinkRef(kind="image" if m.group("bang") else "inline", text=m.group("text"), url=m.group("url"),
                           span=m.span()))
        taken.append(m.span())
    for m in REF_USE_RE.finditer(md):
        if _overlaps(m.span(), taken):
            continue
        ref_id = (m.group("id") or m.group("text")).strip().lower()
        if ref_id in defs:
            kind: LinkKind = "reference_image" if m.group("bang") else "reference"
            out.append(LinkRef(kind=kind, text=m.group("text"), url=defs[ref_id][0], span=m.span(), ref_id=ref_id))
            taken.append(m.span())
    for m in AUTOLINK_RE.finditer(md):
        if not _overlaps(m.span(), taken):
            out.append(LinkRef(kind="autolink", text=m.group("url"), url=m.group("url"), span=m.span()))
            taken.append(m.span())
    for m in BARE_RE.finditer(md):
        if not _overlaps(m.span(), taken):
            url = m.group(0).rstrip(".,;:!?")
            out.append(LinkRef(kind="bare", text=url, url=url, span=(m.start(), m.start() + len(url))))
    out.sort(key=lambda link: link.span)
    return out


def _f(rule: str, reason: str, url: str) -> Finding:
    return Finding(rule_id=rule, stage=Stage.SINK, verdict=Verdict.BLOCK, reason=reason, evidence={"url": url})


def _host_origin(host: str, session: SessionView) -> OriginClass:
    return resolve_origin(session.ledger, arg="host", spec=ArgSpec(type=ArgType.HOST, role=ArgRole.AUTHORITY),
                          value=host, task_spec=session.task_spec, approvals=None, side_effect=SideEffect.FETCH,
                          constants=None).origin_class


def _url_origin(url: str, session: SessionView) -> OriginClass:
    return resolve_origin(session.ledger, arg="url", spec=ArgSpec(type=ArgType.URL, role=ArgRole.AUTHORITY),
                          value=url, task_spec=session.task_spec, approvals=None, side_effect=SideEffect.FETCH,
                          constants=None).origin_class


def sanitize_final_answer(text: str, *, session: SessionView, policy: CompiledPolicy) -> SanitizedText:
    """Strip non-allow-listed images, neutralize exfiltrating links, de-link untrusted hosts in tainted sessions."""
    links = extract_links(text)
    if not links:
        return SanitizedText(text=text, changed=False)
    tainted = session.ledger.ctx_label().integrity == Integrity.UNTRUSTED
    replacements: list[tuple[tuple[int, int], str]] = []
    removed_refs: set[str] = set()
    findings: list[Finding] = []
    for link in links:
        p = url_parts(link.url)
        host = p.host if p else None
        exfil = url_param_findings(link.url, session=session, policy=policy,
                                   url_origin=_url_origin(link.url, session)) if p else []
        if exfil:
            findings.append(_f("SYS-MD-EXFIL", "link or image carries private/secret data", link.url))
            label = link.text if link.text and link.kind not in ("bare", "autolink") else "[link]"
            replacements.append((link.span, f"{label} (link removed)"))
            if link.ref_id:
                removed_refs.add(link.ref_id)
            continue
        if link.kind in _IMAGE_KINDS:
            if p is None or not _allowlisted_url(canonicalize(link.url, ArgType.URL) or link.url, host, policy):
                findings.append(_f("SYS-MD-IMAGE", "external image removed", link.url))
                replacements.append((link.span, f"[image removed: {host or 'invalid url'}]"))
                if link.ref_id:
                    removed_refs.add(link.ref_id)
            continue
        if (tainted and host is not None and link.kind in ("inline", "reference", "html_a", "autolink")
                and _host_origin(host, session) == OriginClass.UNTRUSTED_ONLY):
            findings.append(_f("SYS-MD-LINK", "link to an untrusted-origin host rendered as text", link.url))
            label = link.text if link.kind != "autolink" else ""
            replacements.append((link.span, f"{label} <{host}>".strip()))
            if link.ref_id:
                removed_refs.add(link.ref_id)
    defs = reference_definitions(text)
    replaced_spans = {span for span, _ in replacements}
    for ref_id in removed_refs:
        uses = [link for link in links if link.ref_id == ref_id]
        if ref_id in defs and all(u.span in replaced_spans for u in uses):
            replacements.append((defs[ref_id][1], ""))
    if not replacements:
        return SanitizedText(text=text, changed=False)
    out = text
    for (start, end), new in sorted(replacements, key=lambda r: r[0][0], reverse=True):
        out = out[:start] + new + out[end:]
    return SanitizedText(text=out, changed=out != text, findings=tuple(findings))
