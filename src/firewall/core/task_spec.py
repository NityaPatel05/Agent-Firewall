"""Task spec derived ONLY from the trusted user prompt: scope, authorized values, named sources."""

from __future__ import annotations

import hashlib
import re
from decimal import Decimal
from fnmatch import translate
from functools import cached_property
from typing import TYPE_CHECKING, ClassVar, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from firewall.core.canonical import canon_amount
from firewall.core.extract import extract_typed_values
from firewall.core.models import ArgType
from firewall.core.registry import ToolSpec

if TYPE_CHECKING:
    from firewall.core.provenance import LedgerEntry

_FROZEN = ConfigDict(frozen=True)

_FILE_AUTH = frozenset({ArgType.IBAN, ArgType.AMOUNT, ArgType.TEXT, ArgType.DATE, ArgType.EMAIL})
_EMAIL_AUTH = frozenset({ArgType.IBAN, ArgType.AMOUNT, ArgType.EMAIL, ArgType.TEXT})
_BARE_DOMAIN_RE = re.compile(r"(?<![\w@./])www\.[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}(?:/[\w./-]*)?")
_URL_AUTH = frozenset({ArgType.TEXT, ArgType.URL})
# "You can find her e-mail on her website <url>": only when the prompt asks for an address from the page does a
# user-named page also authorize email values (still confirmed once via named_source_effect).
_URL_EMAIL_AUTH = _URL_AUTH | {ArgType.EMAIL}
_EMAIL_NOUN_RE = re.compile(r"\be-?mail(?:s)?\b(?!\s+(?:me|him|her|them|us))")


class NamedSource(BaseModel):
    """A source the user named for this task; authorizes values of `authorizes` types from it."""

    model_config = _FROZEN
    ref_kind: Literal["file", "email", "url", "message", "channel", "event", "any"]
    pattern: str
    authorizes: frozenset[ArgType]

    @cached_property
    def regex(self) -> re.Pattern[str]:
        return re.compile(translate(self.pattern.lower()))

    def matches(self, entry: LedgerEntry) -> bool:
        rx = self.regex
        if entry.ref and rx.match(entry.ref.lower()):
            return True
        return any(rx.match(r.lower()) for r in entry.ref_aliases)


class TaskSpec(BaseModel):
    model_config = _FROZEN
    task_id: str | None = None
    source: Literal["rule_based", "llm", "fixture", "merged"] = "rule_based"
    prompt_sha256: str = ""
    read_only: bool = False
    allowed_groups: frozenset[str] | None = None
    authorized_values: dict[ArgType, frozenset[str]] = Field(default_factory=dict)
    named_sources: tuple[NamedSource, ...] = ()
    max_amount: Decimal | None = None

    def allows_tool(self, spec: ToolSpec) -> bool:
        """READ tools and unrestricted specs always pass; otherwise the tool's groups must intersect."""
        if not spec.consequential or self.allowed_groups is None:
            return True
        return bool(spec.effective_groups & self.allowed_groups)

    def named_source_for(self, entry: LedgerEntry, arg_type: ArgType) -> NamedSource | None:
        for ns in self.named_sources:
            if arg_type in ns.authorizes and ns.matches(entry):
                return ns
        return None


class TaskSpecExtractor(Protocol):
    def extract(self, prompt: str, *, task_id: str | None = None) -> TaskSpec: ...


def _inflections(word: str) -> list[str]:
    forms = {word, word + "s", word + "es", word + "ed", word + "d", word + "ing"}
    if word.endswith("e"):
        forms.add(word[:-1] + "ing")
    if re.fullmatch(r"[a-z]*[^aeiou][aeiou][bdgmnprt]", word):
        forms |= {word + word[-1] + "ed", word + word[-1] + "ing"}
    if word.endswith("y"):
        forms |= {word[:-1] + "ies", word[:-1] + "ied"}
    return sorted(forms, key=len, reverse=True)


_IRREGULAR = {"pay": ["paid"], "send": ["sent"], "run": ["ran"], "write": ["wrote", "written"],
              "set": ["set"], "forward": [], "dm": ["dms", "dmed", "dm'd"]}

# Words that are often nouns: they count as action verbs only at the start of a clause.
_AMBIGUOUS = frozenset({"email", "message", "post", "book", "test", "schedule", "draft", "transfer", "upload",
                        "download", "submit", "fill", "reply", "cancel", "add", "save", "share", "fix",
                        "run", "set", "remove", "zip", "notify", "refund", "wire", "install", "change", "update",
                        "edit", "move", "rename", "mark", "create", "accept", "decline", "invite", "grant",
                        "execute", "remember", "write", "archive", "encrypt", "reserve", "delete", "forward",
                        "send", "pay"})
_CLAUSE_LEAD = frozenset({"and", "then", "also", "please", "pls", "to", "or", "you", "me", "us", "now", "just",
                          "i", "we", "can", "could", "would", "will", "should", "must", "kindly", "first",
                          "finally", "next", "go", "ahead", "help"})

_PRONOUNS = frozenset({"i", "we", "you"})
_AUX_QUESTION = frozenset({"did", "do", "does", "have", "had", "has"})

_PAY = frozenset({"payment", "banking"})
_EMAIL = frozenset({"external_comm", "email", "email_send"})
_CHAT = frozenset({"external_comm", "slack", "chat_send"})
_WRITE = frozenset({"write"})

VERB_TABLE: dict[str, frozenset[str]] = {
    # payments
    "pay": _PAY, "transfer": _PAY, "send money": _PAY, "wire": _PAY, "refund": _PAY | {"refund"},
    # email / comms
    "send": _EMAIL, "email": _EMAIL, "forward": _EMAIL, "reply": _EMAIL | _CHAT, "bcc": _EMAIL, "cc": _EMAIL,
    "notify": _EMAIL, "respond": _EMAIL,
    # chat
    "dm": _CHAT, "post": _CHAT, "message": _CHAT, "reply in": _CHAT,
    # sharing
    "share": frozenset({"share"}), "grant": frozenset({"share"}), "invite": frozenset({"share", "invite"}),
    # delete
    "delete": frozenset({"delete"}), "remove": frozenset({"delete"}), "clean up": frozenset({"delete"}),
    "cancel": frozenset({"delete"}), "trash": frozenset({"delete"}),
    # booking
    "book": frozenset({"payment", "travel", "booking"}), "reserve": frozenset({"payment", "travel", "booking"}),
    # exec / install
    "run": frozenset({"exec", "install"}), "execute": frozenset({"exec", "install"}),
    "test": frozenset({"exec"}), "install": frozenset({"exec", "install"}),
    # writes
    "save": _WRITE, "write": _WRITE, "fix": _WRITE, "create": _WRITE, "add": _WRITE, "set": _WRITE,
    "set up": _WRITE, "schedule": _WRITE, "accept": _WRITE, "decline": _WRITE, "draft": _WRITE, "zip": _WRITE,
    "download": _WRITE, "update": _WRITE, "change": _WRITE, "edit": _WRITE, "rename": _WRITE, "move": _WRITE,
    "mark": _WRITE, "remind": _WRITE, "encrypt": _WRITE, "archive": _WRITE,
    "upload": frozenset({"write", "external_comm", "upload"}),
    "fill": frozenset({"write", "external_comm", "form", "submit"}),
    "submit": frozenset({"write", "external_comm", "form", "submit"}),
    "log in": frozenset({"write", "auth", "login"}), "login": frozenset({"write", "auth", "login"}),
    "sign in": frozenset({"write", "auth", "login"}),
    "remember": frozenset({"write", "memory"}),
}

_STRIP_QUOTES_RE = re.compile(r"(?:(?<=^)|(?<=[\s:(]))([\"“‘'])(.+?)([\"”’'])(?=$|[\s.,;:!?)])")
_WORD_RE = re.compile(r"[a-z][a-z'’-]*|[.,;:!?()]")
_SEND_AMOUNT_RE = re.compile(r"\bsend\s+(?:[$€£¥]\s?\d|\d[\d,.]*\s?(?:usd|eur|gbp|dollars?|euros?|sol)\b)")
_LOG_IN_RE = re.compile(r"\blog(?:ging|ged|s)?\s+(?:me\s+)?in(?:to)?\b")
_PAYMENT_NOUN_RE = re.compile(r"\b(?:payments?|transfers?|invoices?|bills?|rent|recurring|scheduled|standing orders?)\b")
_CREDENTIAL_NOUN_RE = re.compile(r"\b(?:password|passcode|passphrase|pin|credentials?)\b")
_QUOTED_FILE_RE = re.compile(r"[\"'“‘]([^\"'”’]+\.[A-Za-z0-9]{1,5})[\"'”’]")
_FROM_RE = re.compile(
    r"\b(?:from|reply to|respond to|replying to|the email from|the message from)\s+"
    r"(?:the\s+|my\s+|our\s+|this\s+|that\s+)?([\w.@+\-]+)",
    re.IGNORECASE,
)
# Generic nouns that name a source. "bill" is deliberately absent: "pay my electricity bill" (A07) names no
# source, and a memo containing "bill" must not become authorized.
_SOURCE_NOUNS = {
    "invoice": ("file", "*invoice*", _FILE_AUTH),
    "vendor": ("email", "*vendor*", _EMAIL_AUTH),
    "landlord": ("email", "*landlord*", _EMAIL_AUTH),
}
_STOP_SOURCES = frozenset({
    "me", "my", "the", "a", "an", "it", "this", "that", "here", "there", "now", "today", "tomorrow", "yesterday",
    "profile", "history", "records", "account", "accounts", "latest", "last", "recent", "newest", "first", "next",
    "email", "emails", "message", "messages", "thread", "threads", "all", "everyone", "them", "him", "her",
    "team", "sender", "inbox", "list", "page", "site", "web", "internet", "scratch", "home", "work",
})


def _strip_quoted(prompt: str) -> str:
    return _STRIP_QUOTES_RE.sub(" ", prompt)


def _verb_matches(words: list[str], key: str) -> bool:
    """True if `key` occurs as an action verb in `words` (clause-start rule for ambiguous words)."""
    parts = key.split()
    head = parts[0]
    forms = set(_inflections(head)) | set(_IRREGULAR.get(head, []))
    n = len(parts)
    for i, w in enumerate(words):
        if w not in forms:
            continue
        if n > 1 and words[i + 1 : i + n] != parts[1:]:
            continue
        if n == 1 and head in _AMBIGUOUS:
            prev = words[i - 1] if i > 0 else None
            if prev is not None and prev not in _CLAUSE_LEAD and prev not in ".,;:!?(":
                continue
            if prev in _PRONOUNS and i >= 2 and words[i - 2] in _AUX_QUESTION:
                continue  # "what did I send ...?" is a question, not an instruction
            nxt = words[i + 1] if i + 1 < len(words) else None
            if nxt in {"is", "was", "are", "were", "of", "'s"}:
                continue
        return True
    return False


class RuleBasedTaskSpecExtractor:
    """Deterministic, zero-token task-spec extractor (PLAN §5.4)."""

    VERB_GROUPS: ClassVar[dict[str, frozenset[str]]] = VERB_TABLE
    READ_VERBS: ClassVar[frozenset[str]] = frozenset(
        {"summarize", "what", "show", "list", "check", "find", "look up", "translate", "read", "catch me up",
         "research", "review", "decode", "tell"}
    )

    def extract(self, prompt: str, *, task_id: str | None = None) -> TaskSpec:
        lowered = prompt.lower()
        unquoted = _strip_quoted(lowered)
        words = _WORD_RE.findall(unquoted)
        groups: set[str] = set()
        for key, grp in self.VERB_GROUPS.items():
            if _verb_matches(words, key):
                groups |= grp
        if _SEND_AMOUNT_RE.search(unquoted):
            groups |= _PAY
        if _LOG_IN_RE.search(unquoted):
            groups |= {"write", "auth", "login"}
        read_only = not groups
        if groups and _PAYMENT_NOUN_RE.search(unquoted) and groups & {"write", "payment"}:
            groups |= _PAY
        if "write" in groups and _CREDENTIAL_NOUN_RE.search(unquoted):
            groups |= {"auth", "credentials"}
        typed = extract_typed_values(prompt)
        amounts = [canon_amount(a) for a in typed.get(ArgType.AMOUNT, ())]
        max_amount = max((a for a in amounts if a is not None), default=None)
        return TaskSpec(
            task_id=task_id,
            source="rule_based",
            prompt_sha256=hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
            read_only=read_only,
            allowed_groups=frozenset(groups | {"read", "fetch"}),
            authorized_values={t: frozenset(v) for t, v in typed.items()},
            named_sources=self._named_sources(prompt, typed),
            max_amount=max_amount,
        )

    @staticmethod
    def _named_sources(prompt: str, typed: dict[ArgType, set[str]]) -> tuple[NamedSource, ...]:
        found: dict[tuple[str, str], NamedSource] = {}

        def add(kind: str, pattern: str, auth: frozenset[ArgType]) -> None:
            key = (kind, pattern.lower())
            if key not in found:
                found[key] = NamedSource(ref_kind=kind, pattern=pattern.lower(), authorizes=auth)  # type: ignore[arg-type]

        lowered = prompt.lower()
        for m in _QUOTED_FILE_RE.finditer(prompt):
            add("file", f"*{m.group(1).strip()}*", _FILE_AUTH)
        for path in typed.get(ArgType.PATH, ()):
            base = path.rsplit("/", 1)[-1]
            if "." in base:
                add("file", f"*{base}*", _FILE_AUTH)
        for noun, (kind, pattern, auth) in _SOURCE_NOUNS.items():
            if re.search(rf"\b{noun}s?\b", lowered):
                add(kind, pattern, auth)
        for m in _FROM_RE.finditer(prompt):
            who = m.group(1).strip(".,;:!?").lower()
            if who and who not in _STOP_SOURCES and len(who) >= 3 and ("@" in who or who.isalpha()):
                add("email", f"*{who}*", _EMAIL_AUTH)
        url_auth = _URL_EMAIL_AUTH if _EMAIL_NOUN_RE.search(lowered) else _URL_AUTH
        for url in typed.get(ArgType.URL, ()):
            add("url", f"{url}*", url_auth)
        for m in _BARE_DOMAIN_RE.finditer(lowered):   # "www.dora-website.com" (no scheme)
            add("url", f"*{m.group(0)}*", url_auth)
        return tuple(found.values())


def merge_specs(rule: TaskSpec, llm: TaskSpec, prompt: str) -> TaskSpec:
    """LLM may add groups and named sources; authorized values must literally occur in the prompt."""
    in_prompt = extract_typed_values(prompt)
    values: dict[ArgType, frozenset[str]] = dict(rule.authorized_values)
    for t, vals in llm.authorized_values.items():
        ok = frozenset(v for v in vals if v in in_prompt.get(t, set()))
        if ok:
            values[t] = values.get(t, frozenset()) | ok
    if rule.allowed_groups is None or llm.allowed_groups is None:
        groups = None
    else:
        groups = rule.allowed_groups | llm.allowed_groups
    named = rule.named_sources + tuple(ns for ns in llm.named_sources if ns not in rule.named_sources)
    max_amount = rule.max_amount
    if llm.max_amount is not None and str(llm.max_amount) in {str(canon_amount(a)) for a in in_prompt.get(
            ArgType.AMOUNT, ())}:
        max_amount = llm.max_amount if max_amount is None else max(max_amount, llm.max_amount)
    return TaskSpec(
        task_id=rule.task_id or llm.task_id,
        source="merged",
        prompt_sha256=rule.prompt_sha256,
        read_only=rule.read_only and llm.read_only,
        allowed_groups=groups,
        authorized_values=values,
        named_sources=named,
        max_amount=max_amount,
    )
