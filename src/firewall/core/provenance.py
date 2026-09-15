"""Session ledger (append-only provenance store), output labeling and argument origin resolution."""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator, Mapping, Sequence
from functools import lru_cache
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict

from firewall.core.canonical import canonicalize, normalize_text, skeleton, skeleton_of_normalized
from firewall.core.extract import extract_typed_values
from firewall.core.labels import BOTTOM, Confidentiality, Integrity, Label, Readers, SourceKind, SourceRef
from firewall.core.models import (
    ORIGIN_RANK,
    ArgOrigin,
    ArgType,
    OriginClass,
    OriginMatch,
    SideEffect,
    ToolCall,
)
from firewall.core.registry import ArgSpec, ToolSpec

if TYPE_CHECKING:
    from firewall.core.session import ApprovalStore
    from firewall.core.task_spec import TaskSpec

_FROZEN = ConfigDict(frozen=True)
SHINGLE_LEN = 32
SHINGLE_STEP = 16
EXACT_MAX_LEN = 256
WHOLE_TYPED_MAX_LEN = 128
MIN_TEXT_MATCH = 8
MAX_MATCHES = 8          # OriginMatch objects kept per value (class and label use all matches)
MAX_LABEL_SOURCES = 16   # SourceRefs kept in a joined origin label
_NAMED_RANK = ORIGIN_RANK[OriginClass.USER_NAMED_SOURCE]

# Types that `extract_typed_values` produces (looked up in the typed index).
EXTRACTED_TYPES: frozenset[ArgType] = frozenset(
    {
        ArgType.EMAIL, ArgType.IBAN, ArgType.URL, ArgType.HOST, ArgType.AMOUNT, ArgType.PATH,
        ArgType.HANDLE, ArgType.CHANNEL, ArgType.PHONE, ArgType.DATE, ArgType.CRYPTO_ADDRESS,
    }
)
# Types additionally parsed from short whole-entry texts (e.g. a JSON field holding just "50").
_WHOLE_TYPES = (ArgType.AMOUNT, ArgType.IBAN, ArgType.EMAIL, ArgType.URL, ArgType.DATE, ArgType.CRYPTO_ADDRESS)
_TEXT_TYPES = frozenset({ArgType.TEXT, ArgType.SECRET_TEXT, ArgType.COMMAND})


def fold(text: str) -> str:
    """Matching key for trust decisions: NFKC + invisible-strip + casefold, but NO confusable folding.

    Folding homoglyphs here would let a look-alike value (Cyrillic 'о') inherit the trust of the real one;
    the skeleton is used only for conservative checks (shingles / confidentiality), never to grant trust.
    """
    return normalize_text(text).casefold()


class Signal(BaseModel):
    model_config = _FROZEN
    source: str
    kind: str
    score: float = 1.0
    detail: str = ""


class LedgerEntry(BaseModel):
    model_config = _FROZEN
    entry_id: str
    seq: int
    kind: SourceKind
    text: str
    label: Label
    call_id: str | None = None
    tool: str | None = None
    ref: str | None = None
    ref_aliases: tuple[str, ...] = ()
    author: str | None = None
    field: str | None = None
    signals: tuple[Signal, ...] = ()


class LabeledFragment(BaseModel):
    model_config = _FROZEN
    text: str
    label: Label
    field: str | None = None
    author: str | None = None
    ref: str | None = None
    ref_aliases: tuple[str, ...] = ()


class ValueIndex:
    """Typed canonical values and short exact texts -> entry ids (built at append time)."""

    def __init__(self) -> None:
        self._typed: dict[ArgType, dict[str, list[str]]] = {}
        self._exact: dict[str, list[str]] = {}

    def _put(self, t: ArgType, value: str, entry_id: str) -> None:
        bucket = self._typed.setdefault(t, {}).setdefault(value, [])
        if not bucket or bucket[-1] != entry_id:
            bucket.append(entry_id)

    def add(self, entry: LedgerEntry) -> None:
        text = entry.text
        for t, values in extract_typed_values(text).items():
            for v in values:
                self._put(t, v, entry.entry_id)
        if len(text) <= WHOLE_TYPED_MAX_LEN:
            for t in _WHOLE_TYPES:
                v = canonicalize(text, t)
                if v is not None:
                    self._put(t, v, entry.entry_id)
            if text[:1] in ("@", "#"):
                t = ArgType.HANDLE if text[0] == "@" else ArgType.CHANNEL
                v = canonicalize(text, t)
                if v is not None:
                    self._put(t, v, entry.entry_id)
        if len(text) <= EXACT_MAX_LEN:
            self._exact.setdefault(fold(text), []).append(entry.entry_id)

    def lookup(self, arg_type: ArgType, canonical: str) -> list[str]:
        return list(self._typed.get(arg_type, {}).get(canonical, ()))

    def lookup_exact(self, text_folded: str) -> list[str]:
        return list(self._exact.get(text_folded, ()))


class ShingleIndex:
    """32-char shingles (step 16) of PRIVATE/SECRET entries, for content-confidentiality checks."""

    # Trust-root kinds are never "private data leaving" (the user authored them), so they are not indexed.
    _SKIP_KINDS = frozenset({SourceKind.USER, SourceKind.SYSTEM, SourceKind.POLICY, SourceKind.APPROVAL})

    def __init__(self) -> None:
        # One map per confidentiality level: shingle -> most recent entry id at that level (C-speed updates).
        self._maps: dict[Confidentiality, dict[str, str]] = {Confidentiality.PRIVATE: {}, Confidentiality.SECRET: {}}

    def add(self, entry: LedgerEntry) -> None:
        conf = entry.label.confidentiality
        if conf < Confidentiality.PRIVATE or entry.kind in self._SKIP_KINDS:
            return
        s = skeleton_of_normalized(entry.text)
        if len(s) < SHINGLE_LEN:
            return
        last = len(s) - SHINGLE_LEN
        keys = [s[i : i + SHINGLE_LEN] for i in range(0, last + 1, SHINGLE_STEP)]
        if last % SHINGLE_STEP:
            keys.append(s[last:])
        self._maps[conf].update(dict.fromkeys(keys, entry.entry_id))

    def lookup_text(self, text: str) -> set[str]:
        s = skeleton(text)
        if len(s) < SHINGLE_LEN:
            return set()
        windows = {s[i : i + SHINGLE_LEN] for i in range(len(s) - SHINGLE_LEN + 1)}
        found: set[str] = set()
        for m in self._maps.values():
            hit = windows & m.keys()
            found.update(m[k] for k in hit)
        return found


class _LedgerReader:
    """Read API shared by `Ledger` and its snapshots (entries with seq <= limit)."""

    _entries: list[LedgerEntry]
    _by_id: dict[str, int]
    _folded: list[str]
    _prefix_ctx: list[Label]
    index: ValueIndex
    shingles: ShingleIndex

    @property
    def limit(self) -> int:
        raise NotImplementedError

    def __len__(self) -> int:
        return self.limit

    def entries(self) -> Sequence[LedgerEntry]:
        return self._entries[: self.limit]

    def get(self, entry_id: str) -> LedgerEntry:
        i = self._by_id[entry_id]
        if i >= self.limit:
            raise KeyError(entry_id)
        return self._entries[i]

    def _resolve_ids(self, ids: Iterable[str]) -> list[LedgerEntry]:
        out: list[LedgerEntry] = []
        lim = self.limit
        for eid in ids:
            i = self._by_id.get(eid)
            if i is not None and i < lim:
                out.append(self._entries[i])
        return out

    def find_typed(self, arg_type: ArgType, canonical: str) -> list[LedgerEntry]:
        return self._resolve_ids(self.index.lookup(arg_type, canonical))

    def find_exact(self, text_folded: str) -> list[LedgerEntry]:
        return self._resolve_ids(self.index.lookup_exact(text_folded))

    def find_text(self, text_canonical: str, *, min_len: int = MIN_TEXT_MATCH) -> list[LedgerEntry]:
        """Entries whose folded text contains `text_canonical` (already folded); min length applies."""
        if len(text_canonical) < min_len:
            return []
        lim = self.limit
        return [self._entries[i] for i, s in enumerate(self._folded[:lim]) if text_canonical in s]

    def find_shingles(self, text: str) -> list[LedgerEntry]:
        return self._resolve_ids(sorted(self.shingles.lookup_text(text)))

    def find_user_name(self, value: str) -> list[LedgerEntry]:
        """USER entries containing a short proper name exactly as typed ("Invite Dora to Slack" -> "Dora").
        Only capitalised alphabetic names and only the user's own messages: short common words ("theme") or
        tool-output tokens must not become user-typed."""
        v = value.strip()
        if not (v[:1].isupper() and v.replace(" ", "").replace("-", "").isalpha()):
            return []
        rx = re.compile(rf"(?<!\w){re.escape(v)}(?!\w)")
        lim = self.limit
        return [e for e in self._entries[:lim] if e.kind == SourceKind.USER and rx.search(e.text)]

    def ctx_label(self) -> Label:
        lim = self.limit
        return self._prefix_ctx[lim - 1] if lim else BOTTOM

    def __iter__(self) -> Iterator[LedgerEntry]:
        return iter(self.entries())


class Ledger(_LedgerReader):
    """Append-only session ledger with typed-value and shingle indexes."""

    def __init__(self) -> None:
        self._entries = []
        self._by_id = {}
        self._folded = []
        self._prefix_ctx = []
        self.index = ValueIndex()
        self.shingles = ShingleIndex()

    @property
    def limit(self) -> int:
        return len(self._entries)

    def append(
        self,
        *,
        kind: SourceKind,
        text: str,
        label: Label,
        call_id: str | None = None,
        tool: str | None = None,
        ref: str | None = None,
        ref_aliases: Sequence[str] = (),
        author: str | None = None,
        field: str | None = None,
        signals: Sequence[Signal] = (),
    ) -> LedgerEntry:
        seq = len(self._entries) + 1
        entry = LedgerEntry(
            entry_id=f"e{seq}",
            seq=seq,
            kind=kind,
            text=normalize_text(text),
            label=label,
            call_id=call_id,
            tool=tool,
            ref=ref,
            ref_aliases=tuple(a for a in ref_aliases if a),
            author=author,
            field=field,
            signals=tuple(signals),
        )
        self._by_id[entry.entry_id] = len(self._entries)
        self._entries.append(entry)
        self._folded.append(entry.text.casefold())
        prev = self._prefix_ctx[-1] if self._prefix_ctx else BOTTOM
        self._prefix_ctx.append(prev.join(label))
        self.index.add(entry)
        self.shingles.add(entry)
        return entry

    def extend_fragments(
        self,
        fragments: Sequence[LabeledFragment],
        *,
        kind: SourceKind,
        call_id: str | None,
        tool: str | None,
    ) -> list[LedgerEntry]:
        return [
            self.append(
                kind=kind,
                text=f.text,
                label=f.label,
                call_id=call_id,
                tool=tool,
                ref=f.ref,
                ref_aliases=f.ref_aliases,
                author=f.author,
                field=f.field,
            )
            for f in fragments
        ]

    def add_signal(self, entry_id: str, signal: Signal) -> None:
        i = self._by_id[entry_id]
        old = self._entries[i]
        self._entries[i] = old.model_copy(update={"signals": (*old.signals, signal)})

    def snapshot(self) -> LedgerView:
        return LedgerView(self, len(self._entries))


class LedgerView(_LedgerReader):
    """Read-only view of a ledger frozen at a given length (later appends are invisible)."""

    def __init__(self, ledger: Ledger, limit: int) -> None:
        self._entries = ledger._entries
        self._by_id = ledger._by_id
        self._folded = ledger._folded
        self._prefix_ctx = ledger._prefix_ctx
        self.index = ledger.index
        self.shingles = ledger.shingles
        self._limit = limit

    @property
    def limit(self) -> int:
        return self._limit


LedgerLike = Ledger | LedgerView


# --------------------------------------------------------------------------- output labeling

_TRUST_TRUSTED = ("trusted", "own_record")


@lru_cache(maxsize=1024)
def _field_regex(pattern: str) -> re.Pattern[str]:
    body = re.escape(pattern).replace(r"\[\*\]", r"\[\d+\]")
    return re.compile(rf"^{body}(?:$|[.\[])")


def _flatten(value: Any, path: str = "") -> Iterator[tuple[str, Any]]:
    if isinstance(value, Mapping):
        for k, v in value.items():
            yield from _flatten(v, f"{path}.{k}" if path else str(k))
    elif isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            yield from _flatten(v, f"{path}[{i}]")
    else:
        yield path, value


def _items(output: Any, item_path: str | None) -> list[tuple[str, Mapping[str, Any]]]:
    """(path prefix, item) pairs for list-of-dict outputs described by `item_path`."""
    if not item_path:
        return []
    container: Any = output
    prefix = ""
    head = item_path.removesuffix("[*]")
    if head:
        for part in head.split("."):
            if not isinstance(container, Mapping):
                return []
            container = container.get(part)
            prefix = f"{prefix}.{part}" if prefix else part
    if not isinstance(container, (list, tuple)):
        return []
    return [(f"{prefix}[{i}]", it) for i, it in enumerate(container) if isinstance(it, Mapping)]


def _leaf_text(value: Any) -> str | None:
    if value is None or isinstance(value, bool):
        return None
    text = value if isinstance(value, str) else str(value)
    return text if text.strip() else None


def _str_or_none(v: Any) -> str | None:
    return None if v is None or v == "" else str(v)


def compute_output_labels(
    spec: ToolSpec, call: ToolCall, output: Any, *, user_handle: str
) -> list[LabeledFragment]:
    """Label every leaf of a tool output from registry metadata (never from model output)."""
    out_spec = spec.output
    conf = Confidentiality[out_spec.sensitivity.upper()]
    call_ref = _str_or_none(call.args.get(spec.ref_arg)) if spec.ref_arg else None
    server = None if spec.server == "local" else spec.server
    items = _items(output, out_spec.item_path)
    item_meta: list[tuple[str, str | None, str | None, tuple[str, ...]]] = []
    for prefix, item in items:
        author = _str_or_none(item.get(out_spec.author_field)) if out_spec.author_field else None
        ref = _str_or_none(item.get(out_spec.ref_field)) if out_spec.ref_field else None
        aliases = tuple(a for a in (_str_or_none(item.get(f)) for f in out_spec.alias_fields) if a)
        if call_ref and ref and call_ref != ref:
            aliases = (*aliases, call_ref)
        item_meta.append((prefix, author, ref or call_ref, aliases))
    top_aliases: tuple[str, ...] = ()
    if isinstance(output, Mapping):
        top_aliases = tuple(a for a in (_str_or_none(output.get(f)) for f in out_spec.alias_fields) if a)
    field_rx = [(_field_regex(p), trust) for p, trust in out_spec.fields.items()]
    user_norm = user_handle.lower()

    frags: list[LabeledFragment] = []
    for path, value in _flatten(output):
        text = _leaf_text(value)
        if text is None:
            continue
        author: str | None = None
        ref = call_ref
        aliases = top_aliases
        for prefix, it_author, it_ref, it_aliases in item_meta:
            if path == prefix or path.startswith((prefix + ".", prefix + "[")):
                author, ref, aliases = it_author, it_ref, it_aliases
                break
        trust: str | None = None
        for rx, t in field_rx:
            if rx.match(path):
                trust = t
                break
        if trust is None:
            if author is not None:
                trust = "trusted" if author.lower() == user_norm else "untrusted"
            else:
                trust = out_spec.source_trust
        label = Label.tool(
            trusted=trust in _TRUST_TRUSTED,
            conf=conf,
            tool=spec.qualified_name,
            call_id=call.call_id,
            server=server,
            ref=ref,
            author=author,
            kind=SourceKind.OWN_RECORD if trust == "own_record" else SourceKind.TOOL_OUTPUT,
        )
        frags.append(
            LabeledFragment(text=text, label=label, field=path or None, author=author, ref=ref, ref_aliases=aliases)
        )
    return frags


# --------------------------------------------------------------------------- origin resolution

_UNKNOWN_LABEL = Label(integrity=Integrity.UNTRUSTED, confidentiality=Confidentiality.PUBLIC)
_APPROVAL_LABEL = Label(
    integrity=Integrity.TRUSTED,
    confidentiality=Confidentiality.PRIVATE,
    sources=frozenset({SourceRef(kind=SourceKind.APPROVAL)}),
)
_POLICY_LABEL = Label(
    integrity=Integrity.TRUSTED,
    confidentiality=Confidentiality.PUBLIC,
    sources=frozenset({SourceRef(kind=SourceKind.POLICY)}),
)


def _source_key(s: SourceRef) -> tuple[str, ...]:
    return (s.kind.value, s.tool or "", s.server or "", s.call_id or "", s.author or "", s.ref or "")


def _source_of(entry: LedgerEntry) -> SourceRef | None:
    """Deterministic representative source of an entry (entries normally carry exactly one)."""
    sources = entry.label.sources
    if len(sources) == 1:
        return next(iter(sources))
    return min(sources, key=_source_key) if sources else None


def _entry_class(
    entry: LedgerEntry,
    arg_type: ArgType,
    canonical: str,
    task_spec: TaskSpec | None,
    approvals: ApprovalStore | None,
    side_effect: SideEffect,
) -> OriginClass | None:
    kind = entry.kind
    if kind == SourceKind.USER:
        return OriginClass.USER_TYPED
    if kind in (SourceKind.SYSTEM, SourceKind.POLICY):
        return OriginClass.POLICY_CONST
    if kind == SourceKind.APPROVAL:
        if approvals is not None and approvals.is_approved(side_effect, arg_type, canonical):
            return OriginClass.APPROVED
        return None
    if entry.label.trusted:
        if kind in (SourceKind.SUMMARY, SourceKind.DERIVED, SourceKind.TOOL_DESCRIPTION):
            return None
        return OriginClass.OWN_RECORD
    named = (
        task_spec is not None
        and kind != SourceKind.TOOL_DESCRIPTION
        and task_spec.named_source_for(entry, arg_type) is not None
    )
    return OriginClass.USER_NAMED_SOURCE if named else OriginClass.UNTRUSTED_ONLY


def _match_key(value: Any, arg_type: ArgType, canonical: str) -> str:
    """Folded key used for exact / substring matching (raw text for text-like types)."""
    if arg_type in (ArgType.TEXT, ArgType.SECRET_TEXT) and isinstance(value, str):
        return fold(value)
    return fold(canonical)


def _ledger_candidates(ledger: LedgerLike, arg_type: ArgType, canonical: str, key: str,
                       raw: Any = None) -> list[LedgerEntry]:
    seen: dict[str, LedgerEntry] = {}
    if arg_type in EXTRACTED_TYPES:
        for e in ledger.find_typed(arg_type, canonical):
            seen.setdefault(e.entry_id, e)
    for e in ledger.find_exact(key):
        seen.setdefault(e.entry_id, e)
    if arg_type in _TEXT_TYPES:
        for e in ledger.find_text(key):
            seen.setdefault(e.entry_id, e)
        if arg_type == ArgType.TEXT and isinstance(raw, str) and len(key) < MIN_TEXT_MATCH:
            for e in ledger.find_user_name(raw):
                seen.setdefault(e.entry_id, e)
    return sorted(seen.values(), key=lambda e: e.seq)


def _resolve_one(
    ledger: LedgerLike,
    arg_type: ArgType,
    value: Any,
    *,
    task_spec: TaskSpec | None,
    approvals: ApprovalStore | None,
    side_effect: SideEffect,
    constants: Mapping[ArgType, frozenset[str]] | None,
) -> tuple[str | None, OriginClass, tuple[OriginMatch, ...], Label]:
    canonical = canonicalize(value, arg_type)
    if canonical is None or canonical == "":
        return None, OriginClass.UNKNOWN, (), _UNKNOWN_LABEL
    matches: list[OriginMatch] = []
    labels: list[Label] = []
    if approvals is not None and approvals.is_approved(side_effect, arg_type, canonical):
        matches.append(OriginMatch.model_construct(entry_id="approval", kind=SourceKind.APPROVAL,
                                   source=SourceRef(kind=SourceKind.APPROVAL), origin_class=OriginClass.APPROVED))
        labels.append(_APPROVAL_LABEL)
    if constants is not None and canonical in constants.get(arg_type, frozenset()):
        matches.append(OriginMatch.model_construct(entry_id="policy", kind=SourceKind.POLICY,
                                   source=SourceRef(kind=SourceKind.POLICY), origin_class=OriginClass.POLICY_CONST))
        labels.append(_POLICY_LABEL)
    if task_spec is not None and canonical in task_spec.authorized_values.get(arg_type, frozenset()):
        matches.append(OriginMatch.model_construct(entry_id="task_spec", kind=SourceKind.USER,
                                   source=SourceRef(kind=SourceKind.USER), origin_class=OriginClass.USER_TYPED))
        labels.append(Label.user())
    hits: list[tuple[int, OriginClass, LedgerEntry]] = []
    best = max((ORIGIN_RANK[m.origin_class] for m in matches), default=-1)
    for entry in _ledger_candidates(ledger, arg_type, canonical, _match_key(value, arg_type, canonical), value):
        # Named-source globbing only matters while nothing better than USER_NAMED_SOURCE has been found.
        ts = task_spec if best < _NAMED_RANK else None
        cls = _entry_class(entry, arg_type, canonical, ts, approvals, side_effect)
        if cls is not None:
            rank = ORIGIN_RANK[cls]
            best = max(best, rank)
            hits.append((rank, cls, entry))
    if not matches and not hits:
        label = Label.user() if arg_type in (ArgType.TEXT,) else _UNKNOWN_LABEL
        return canonical, OriginClass.UNKNOWN, (), label
    # Keep the most trusted matches first (stable by sequence); cap what we materialize.
    hits.sort(key=lambda h: (-h[0], h[2].seq))
    for _, cls, entry in hits[:MAX_MATCHES]:
        matches.append(OriginMatch.model_construct(entry_id=entry.entry_id, kind=entry.kind,
                                                   source=_source_of(entry), origin_class=cls))
    matches.sort(key=lambda m: -ORIGIN_RANK[m.origin_class])
    labels.extend(h[2].label for h in hits)
    return canonical, matches[0].origin_class, tuple(matches), _join_capped(labels)


def _join_capped(labels: list[Label]) -> Label:
    """Join of many labels: exact integrity/confidentiality/readers; sources capped at MAX_LABEL_SOURCES."""
    integrity = min(lab.integrity for lab in labels)
    conf = max(lab.confidentiality for lab in labels)
    sources: set[SourceRef] = set()
    readers: Readers = "*"
    for lab in labels:
        if len(sources) < MAX_LABEL_SOURCES:
            sources.update(lab.sources)
        if lab.readers != "*":
            readers = lab.readers if readers == "*" else readers & lab.readers  # type: ignore[operator]
    return Label.model_construct(integrity=integrity, confidentiality=conf, sources=frozenset(sources),
                                 readers=readers)


def resolve_origin(
    ledger: LedgerLike,
    *,
    arg: str,
    spec: ArgSpec,
    value: Any,
    task_spec: TaskSpec | None,
    approvals: ApprovalStore | None,
    side_effect: SideEffect,
    constants: Mapping[ArgType, frozenset[str]] | None = None,
) -> ArgOrigin:
    """Resolve where an argument value came from (PLAN §5.2). Lists take the least-trusted element."""
    kwargs: dict[str, Any] = {"task_spec": task_spec, "approvals": approvals, "side_effect": side_effect,
                              "constants": constants}
    if spec.type == ArgType.LIST:
        item_type = spec.items or ArgType.TEXT
        values = list(value) if isinstance(value, (list, tuple)) else [value]
        if not values:
            return ArgOrigin(arg=arg, role=spec.role, arg_type=item_type, value_canonical=[],
                             origin_class=OriginClass.UNKNOWN, label=_UNKNOWN_LABEL)
        canon_list: list[str] = []
        classes: list[OriginClass] = []
        worst = OriginClass.USER_TYPED
        all_matches: list[OriginMatch] = []
        label: Label | None = None
        for v in values:
            c, cls, m, lab = _resolve_one(ledger, item_type, v, **kwargs)
            canon_list.append(c if c is not None else "")
            classes.append(cls)
            if ORIGIN_RANK[cls] < ORIGIN_RANK[worst]:
                worst = cls
            all_matches.extend(m)
            label = lab if label is None else label.join(lab)
        return ArgOrigin.model_construct(arg=arg, role=spec.role, arg_type=item_type, value_canonical=canon_list,
                                         origin_class=worst, matches=tuple(all_matches),
                                         label=label or _UNKNOWN_LABEL, item_classes=tuple(classes))
    c, cls, m, lab = _resolve_one(ledger, spec.type, value, **kwargs)
    return ArgOrigin.model_construct(arg=arg, role=spec.role, arg_type=spec.type, value_canonical=c,
                                     origin_class=cls, matches=m, label=lab, item_classes=())
