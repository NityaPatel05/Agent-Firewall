"""Sink / exfiltration checks: destination classification, URL-parameter taint, content facts, egress budget."""

from __future__ import annotations

import re
from collections.abc import Mapping
from functools import lru_cache
from typing import TYPE_CHECKING, Any

from firewall.core.canonical import canon_path, canonicalize, url_parts
from firewall.core.extract import URL_BODY_RE, extract_typed_values
from firewall.core.labels import Confidentiality, SourceKind
from firewall.core.models import (
    ORIGIN_RANK,
    TRUSTED_ORIGINS,
    ArgOrigin,
    ArgRole,
    ArgType,
    DestinationInfo,
    Finding,
    OriginClass,
    SideEffect,
    Stage,
    Verdict,
)
from firewall.core.policy.conditions import ArgFacts
from firewall.core.provenance import LedgerEntry, fold, resolve_origin
from firewall.core.registry import ArgSpec, ToolSpec
from firewall.core.secrets import find_canaries, find_secrets
from firewall.core.session import SessionView, resource_key

if TYPE_CHECKING:
    from firewall.core.policy.loader import CompiledPolicy

_UNTRUSTED_KINDS_EXCLUDED = frozenset({SourceKind.USER, SourceKind.SYSTEM, SourceKind.POLICY, SourceKind.APPROVAL})
MIN_PARAM_LEN = 4
MIN_PARAM_SUBSTRING = 16
_URL_CONTENT_GROUPS = frozenset({"form", "webhook", "submit"})


def _f(rule: str, verdict: Verdict, reason: str, arg: str | None = None, **ev: Any) -> Finding:
    return Finding.model_construct(rule_id=rule, stage=Stage.SINK, verdict=verdict, reason=reason, arg=arg,
                                   evidence=ev)


# ------------------------------------------------------------------ destinations

def _allowlisted_url(canonical: str, host: str | None, policy: CompiledPolicy) -> bool:
    al = policy.policy.allowlists
    if host is not None and host in al.http_hosts:
        return True
    for cp in _canonical_prefixes(al.http_path_prefixes):
        if canonical.startswith(cp.rstrip("/") + "/") or canonical == cp:
            return True
    return False


@lru_cache(maxsize=64)
def _canonical_prefixes(prefixes: frozenset[str]) -> tuple[str, ...]:
    return tuple(sorted(canonicalize(p, ArgType.URL) or p for p in prefixes))


def classify_value(kind: ArgType, value: str, arg: str, origin_class: OriginClass, session: SessionView,
                   policy: CompiledPolicy) -> DestinationInfo:
    """Classify one destination value as internal / own / allow-listed."""
    al = policy.policy.allowlists
    canonical = canonicalize(value, kind) or value
    internal = own = allowlisted = False
    host: str | None = None
    if kind == ArgType.EMAIL:
        host = canonical.rsplit("@", 1)[-1]
        internal = any(host == d or host.endswith("." + d) for d in al.internal_email_domains)
        own = canonical in al.own_emails or canonical in session.own_emails
    elif kind == ArgType.IBAN:
        own = canonical in al.own_ibans or canonical in session.own_ibans
    elif kind == ArgType.HANDLE:
        internal = canonical in {h.lower() for h in al.slack_workspace_users}
        own = canonical in {h.lower() for h in al.own_handles} or canonical == session.user_handle
    elif kind == ArgType.CHANNEL:
        internal = True
    elif kind == ArgType.URL:
        p = url_parts(canonical)
        host = p.host if p else None
        allowlisted = _allowlisted_url(canonical, host, policy)
        internal = allowlisted
    elif kind == ArgType.CRYPTO_ADDRESS:
        own = canonical in al.own_crypto_addresses
    return DestinationInfo.model_construct(arg=arg, kind=kind, value=canonical, internal=internal, own=own,
                                           allowlisted=allowlisted, host=host, origin_class=origin_class)


def _derived_value(session: SessionView, selector: str, field: str) -> str | None:
    """Value of `field` in the output entry whose ref is `selector` (e.g. sender of email e3)."""
    found: str | None = None
    for e in session.ledger.entries():
        if e.ref == selector and e.field is not None and (e.field == field or e.field.endswith("." + field)):
            found = e.text
    return found


def classify_destinations(spec: ToolSpec, args: Mapping[str, Any], origins: Mapping[str, ArgOrigin],
                          session: SessionView, policy: CompiledPolicy) -> tuple[DestinationInfo, ...]:
    d = spec.destination
    if d is None:
        return ()
    out: list[DestinationInfo] = []
    for arg in d.args:
        value = args.get(arg)
        if value in (None, "", [], ()):
            continue
        origin = origins.get(arg)
        values = value if isinstance(value, (list, tuple)) else [value]
        for i, v in enumerate(values):
            if origin is None:
                cls = OriginClass.UNKNOWN
            elif origin.item_classes and i < len(origin.item_classes):
                cls = origin.item_classes[i]
            else:
                cls = origin.origin_class
            out.append(classify_value(d.kind, str(v), arg, cls, session, policy))
    if d.derived_from is not None:
        sel_arg, field = d.derived_from
        selector = args.get(sel_arg)
        if selector not in (None, ""):
            value = _derived_value(session, str(selector), field)
            if value is None:
                out.append(DestinationInfo.model_construct(arg=sel_arg, kind=d.kind, value=f"<{field} of {selector}>",
                                                           internal=False, own=False, allowlisted=False, host=None,
                                                           origin_class=OriginClass.UNKNOWN))
            else:
                o = resolve_origin(session.ledger, arg=sel_arg, spec=ArgSpec(type=d.kind, role=ArgRole.AUTHORITY),
                                   value=value, task_spec=session.task_spec, approvals=session.approvals,
                                   side_effect=spec.side_effect, constants=session.constants())
                # Bound to an object the user selected: at least USER_NAMED_SOURCE (confirm private flows once).
                cls = o.origin_class if o.origin_class in TRUSTED_ORIGINS else OriginClass.USER_NAMED_SOURCE
                out.append(classify_value(d.kind, value, sel_arg, cls, session, policy))
    return tuple(out)


# ------------------------------------------------------------------ URL-parameter taint

_LIST_SPLIT = re.compile(r"[,;|\n]+")
_TRUSTED_DEST = frozenset({OriginClass.USER_TYPED, OriginClass.APPROVED, OriginClass.OWN_RECORD,
                           OriginClass.POLICY_CONST})


def _url_values(url: str) -> list[str]:
    p = url_parts(url)
    if p is None:
        return []
    vals = [v for _, v in p.query] + [seg for seg in p.path.split("/") if seg] + ([p.fragment] if p.fragment else [])
    return [v for v in vals if len(v) >= MIN_PARAM_LEN]


def _ledger_matches(value: str, session: SessionView, *, min_substring: int) -> list[LedgerEntry]:
    ledger = session.ledger
    found: dict[str, LedgerEntry] = {}
    for t, vals in extract_typed_values(value).items():
        for c in vals:
            for e in ledger.find_typed(t, c):
                found.setdefault(e.entry_id, e)
    key = fold(value)
    for e in ledger.find_exact(key):
        found.setdefault(e.entry_id, e)
    if len(key) >= min_substring:
        for e in ledger.find_text(key, min_len=min_substring):
            found.setdefault(e.entry_id, e)
    return list(found.values())


def _identifier_like(value: str) -> bool:
    """Digits, separators or length >= 16 — plain short words ('products') are not treated as data."""
    return any(c.isdigit() for c in value) or any(c in "-_.@+:=" for c in value) or len(value) >= MIN_PARAM_SUBSTRING


def _user_typed(key: str, session: SessionView) -> bool:
    return any(e.kind == SourceKind.USER and key in fold(e.text) for e in session.ledger.entries())


def private_match(value: str, session: SessionView) -> LedgerEntry | None:
    """A PRIVATE/SECRET ledger entry carrying `value`, unless the user typed the value."""
    if not _identifier_like(value):
        return None
    matches = _ledger_matches(value, session, min_substring=MIN_PARAM_SUBSTRING)
    if not matches or any(e.kind == SourceKind.USER for e in matches) or _user_typed(fold(value), session):
        return None
    for e in matches:
        if e.kind not in _UNTRUSTED_KINDS_EXCLUDED and e.label.confidentiality >= Confidentiality.PRIVATE:
            return e
    return None


def url_param_findings(url: str, *, session: SessionView, policy: CompiledPolicy, url_origin: OriginClass,
                       arg: str | None = None) -> list[Finding]:
    """Secrets, canaries or private values in query values, path segments or the fragment (any host)."""
    out: list[Finding] = []
    canaries = policy.policy.canaries
    if find_canaries(url, canaries):
        out.append(_f("SYS-SINK-CANARY", Verdict.BLOCK, "canary token in outbound URL", arg, url=url))
    for v in _url_values(url):
        if find_secrets(v):
            out.append(_f("SYS-SINK-SECRET", Verdict.BLOCK, "secret in outbound URL", arg, url=url, value=v[:64]))
            continue
        if url_origin == OriginClass.USER_TYPED:
            continue
        hit = private_match(v, session)
        if hit is None:   # a list of private items joined into one parameter ("a, b; c")
            pieces = [s.strip() for s in _LIST_SPLIT.split(v) if len(s.strip()) >= MIN_PARAM_LEN]
            hit = next((h for s in pieces if len(pieces) > 1 for h in [private_match(s, session)] if h), None)
        if hit is not None:
            out.append(_f("SYS-SINK-URLPARAM", Verdict.BLOCK,
                          f"outbound URL carries private data from {hit.tool or hit.kind.value} ({hit.entry_id})",
                          arg, url=url, value=v[:64], entry_id=hit.entry_id))
    return out


# ------------------------------------------------------------------ facts

def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [s for v in value for s in _strings(v)]
    if isinstance(value, Mapping):
        return [s for v in value.values() for s in _strings(v)]
    return []


def _content_conf(text: str, session: SessionView) -> Confidentiality:
    ledger = session.ledger
    best = Confidentiality.PUBLIC
    entries: list[LedgerEntry] = []
    for t, vals in extract_typed_values(text).items():
        for c in vals:
            entries.extend(ledger.find_typed(t, c))
    if len(text) >= 32:
        entries.extend(ledger.find_shingles(text))
    for e in entries:
        if e.kind not in _UNTRUSTED_KINDS_EXCLUDED and e.label.confidentiality > best:
            best = e.label.confidentiality
    return best


def _resource(kind: str, ref: str, session: SessionView) -> tuple[Confidentiality, int]:
    """Confidentiality and byte size of a referenced resource (file path, email/report id)."""
    conf = Confidentiality.PRIVATE  # resources are private unless known otherwise
    size = 0
    key = resource_key(ArgType.PATH, ref) if kind == "file" else f"id:{ref}"
    lab = session.resource_labels.get(key) if key else None
    if lab is not None:
        conf = max(conf, lab.confidentiality)
    for e in session.ledger.entries():
        if e.ref is not None and (e.ref == ref or (kind == "file" and canon_path(e.ref) == ref)):
            conf = max(conf, e.label.confidentiality)
            size += len(e.text)
    return conf, size


_CREDENTIAL_KEY = re.compile(r"(?i)^(pass(word|wd|phrase)?|pin|otp|2fa|mfa|totp|secret|api[_-]?key|token|"
                             r"access[_-]?token|private[_-]?key|seed[_-]?phrase|security[_-]?code)$")


def _credential_fields(value: Any) -> bool:
    """A non-empty value under a credential-named key anywhere in a dict argument (e.g. form fields)."""
    if isinstance(value, Mapping):
        return any((isinstance(k, str) and _CREDENTIAL_KEY.match(k.strip()) and str(v).strip())
                   or _credential_fields(v) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return any(_credential_fields(v) for v in value)
    return False


def compute_facts(spec: ToolSpec, args: Mapping[str, Any], session: SessionView,
                  policy: CompiledPolicy) -> ArgFacts:
    canaries = policy.policy.canaries
    all_strings = _strings(dict(args))
    secret = any(find_secrets(s) for s in all_strings) or any(
        _credential_fields(v) for v in args.values() if isinstance(v, (Mapping, list, tuple)))
    canary = any(find_canaries(s, canaries) for s in all_strings) if canaries else False
    conf = Confidentiality.SECRET if secret else Confidentiality.PUBLIC
    private_bytes = 0
    for name, a in spec.args.items():
        value = args.get(name)
        if value in (None, "", [], ()):
            continue
        item_type = a.value_type
        if item_type == ArgType.PATH and (a.role == ArgRole.CONTENT or a.transfers_content):
            for p in _strings(value):
                c, size = _resource("file", canon_path(p) or p, session)
                conf = max(conf, c)
                private_bytes += size if c >= Confidentiality.PRIVATE else 0
        elif a.transfers_content:
            for ref in _strings(value):
                c, size = _resource("ref", ref, session)
                conf = max(conf, c)
                private_bytes += size if c >= Confidentiality.PRIVATE else 0
        elif a.role == ArgRole.CONTENT:
            for s in _strings(value):
                c = _content_conf(s, session)
                conf = max(conf, c)
                if c >= Confidentiality.PRIVATE:
                    private_bytes += len(s)
    return ArgFacts(secret_in_args=secret, canary_in_args=canary, content_confidentiality=conf,
                    private_bytes=private_bytes)


# ------------------------------------------------------------------ sink findings

def sink_findings(spec: ToolSpec, args: Mapping[str, Any], origins: Mapping[str, ArgOrigin],
                  destinations: tuple[DestinationInfo, ...], facts: ArgFacts, session: SessionView,
                  policy: CompiledPolicy) -> list[Finding]:
    if not spec.sink:
        return []
    out: list[Finding] = []
    for name, a in spec.args.items():
        value = args.get(name)
        if value in (None, "", []) or a.value_type != ArgType.URL:
            continue
        origin = origins.get(name)
        url_origin = origin.origin_class if origin is not None else OriginClass.UNKNOWN
        for url in _strings(value):
            out.extend(url_param_findings(url, session=session, policy=policy, url_origin=url_origin, arg=name))
    if spec.side_effect == SideEffect.FETCH or spec.groups & _URL_CONTENT_GROUPS:
        for name, a in spec.args.items():
            if a.role != ArgRole.CONTENT:
                continue
            for s in _strings(args.get(name)):
                for m in URL_BODY_RE.finditer(s):
                    out.extend(url_param_findings(m.group(0), session=session, policy=policy,
                                                  url_origin=OriginClass.UNKNOWN, arg=name))
    if facts.canary_in_args and not any(f.rule_id == "SYS-SINK-CANARY" for f in out):
        out.append(_f("SYS-SINK-CANARY", Verdict.BLOCK, "canary token in arguments"))
    budget = policy.policy.egress_budget
    counters = session.counters
    tainted = session.flags.read_private and session.flags.ingested_untrusted
    for d in destinations:
        if d.kind != ArgType.URL:
            continue
        if (spec.side_effect != SideEffect.FETCH and not d.allowlisted
                and d.origin_class in (OriginClass.UNTRUSTED_ONLY, OriginClass.UNKNOWN)):
            out.append(_f("SYS-SINK-HOST", Verdict.REVIEW, f"egress to non-allow-listed host {d.host} of "
                          f"{d.origin_class.value} origin", d.arg, host=d.host))
        sent = counters.external_fetches_by_host.get(d.host, 0) if d.host is not None else 0
        if d.host is not None and sent + 1 > budget.max_external_fetches_per_host:
            out.append(_f("SYS-SINK-BUDGET", Verdict.REVIEW, f"egress budget for host {d.host} exceeded", d.arg,
                          host=d.host))
        elif (d.host is not None and tainted and not d.allowlisted and d.origin_class not in _TRUSTED_DEST
              and sent + 1 > budget.max_tainted_fetches_per_host):
            out.append(_f("SYS-SINK-BUDGET-TAINTED", Verdict.REVIEW,
                          f"repeated requests to {d.host} after private data was read in an untrusted context",
                          d.arg, host=d.host))
    if facts.private_bytes and counters.private_bytes_out + facts.private_bytes > budget.max_private_bytes_out:
        out.append(_f("SYS-SINK-BUDGET", Verdict.REVIEW, "private-bytes egress budget exceeded",
                      bytes=counters.private_bytes_out + facts.private_bytes))
    return _dedupe(out)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str | None, str]] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.rule_id, f.arg, str(f.evidence.get("value") or f.evidence.get("host") or ""))
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def least_trusted(classes: list[OriginClass]) -> OriginClass:
    return min(classes, key=ORIGIN_RANK.__getitem__) if classes else OriginClass.UNKNOWN
