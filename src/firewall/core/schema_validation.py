"""Argument normalization + strict validation (types, formats, lengths) and smuggling checks."""

from __future__ import annotations

import json
import re
import threading
import unicodedata
from collections.abc import Callable, Mapping
from decimal import Decimal
from functools import lru_cache
from typing import Any

import fastjsonschema
from pydantic import BaseModel, ConfigDict

from firewall.core.canonical import (
    canon_channel,
    canon_crypto,
    canon_date,
    canon_email,
    canon_handle,
    canon_host,
    canon_iban,
    canon_phone,
    mixed_script,
    normalize_text,
    parse_amount,
    skeleton,
    strip_invisible,
    url_parts,
)
from firewall.core.extract import extract_typed_values
from firewall.core.models import ArgRole, ArgType, Finding, Stage, Verdict
from firewall.core.registry import ArgSpec, ToolRegistry, ToolSpec, arg_json_schema

_BAD_SCHEMES = ("javascript:", "data:", "file:", "vbscript:")
_HANDLE_RE = re.compile(r"^@[a-z0-9._-]{1,64}$")
_CHANNEL_RE = re.compile(r"^#[a-z0-9._-]{1,80}$")
_URL_IN_TEXT_RE = re.compile(r"(?i)\b(?:https?|ftp|javascript|data|file)://|\bwww\.[a-z0-9-]+\.[a-z]{2,}")
_SMUGGLE_RE = re.compile(r"(?i)[;,\n\r]|\bto=|\bbcc\s*:|\bcc\s*:")
_TYPED_SINGLE = {ArgType.EMAIL, ArgType.IBAN, ArgType.HANDLE, ArgType.URL}
_HOMOGLYPH_TYPES = {ArgType.EMAIL, ArgType.HOST, ArgType.URL}


def _amount_ok(v: Any, spec: ArgSpec) -> bool:
    d = parse_amount(v)
    if d is None or d <= 0:
        return False
    max_places = 9 if (spec.minimum is not None and spec.minimum < 0.01) else 2
    exp = d.normalize().as_tuple().exponent
    return not (isinstance(exp, int) and -exp > max_places)


def _url_ok(v: Any) -> bool:
    return isinstance(v, str) and not v.strip().lower().startswith(_BAD_SCHEMES) and url_parts(v) is not None


def _path_ok(v: Any) -> bool:
    return isinstance(v, str) and 0 < len(v) <= 4096 and "\x00" not in v


FORMAT_CHECKS: dict[ArgType, Callable[[Any], bool]] = {
    ArgType.EMAIL: lambda v: canon_email(v) is not None,
    ArgType.IBAN: lambda v: canon_iban(v) is not None,
    ArgType.URL: _url_ok,
    ArgType.HOST: lambda v: canon_host(v) is not None,
    ArgType.DATE: lambda v: canon_date(v) is not None,
    ArgType.HANDLE: lambda v: isinstance(v, str) and bool(_HANDLE_RE.match(v.lower())) and canon_handle(v) is not None,
    ArgType.CHANNEL: lambda v: isinstance(v, str) and bool(_CHANNEL_RE.match(v.lower())) and canon_channel(v) is not None,
    ArgType.PATH: _path_ok,
    ArgType.CRYPTO_ADDRESS: lambda v: canon_crypto(v) is not None,
    ArgType.COMMAND: lambda v: isinstance(v, list) and len(v) > 0 and all(isinstance(x, str) for x in v),
    ArgType.PHONE: lambda v: canon_phone(v) is not None,
}

DEFAULT_MAX_LENGTH: dict[ArgRole, int] = {
    ArgRole.AUTHORITY: 512,
    ArgRole.BOUNDED: 64,
    ArgRole.SELECTOR: 256,
    ArgRole.CONTENT: 20000,
    ArgRole.META: 512,
}

_RULE_FOR_KEYWORD = {
    "type": "SYS-SCHEMA-TYPE",
    "enum": "SYS-SCHEMA-ENUM",
    "const": "SYS-SCHEMA-ENUM",
    "minimum": "SYS-SCHEMA-RANGE",
    "maximum": "SYS-SCHEMA-RANGE",
    "exclusiveMinimum": "SYS-SCHEMA-RANGE",
    "exclusiveMaximum": "SYS-SCHEMA-RANGE",
    "maxLength": "SYS-SCHEMA-LENGTH",
    "minLength": "SYS-SCHEMA-LENGTH",
    "maxItems": "SYS-SCHEMA-LENGTH",
    "minItems": "SYS-SCHEMA-LENGTH",
    "pattern": "SYS-SCHEMA-FORMAT",
    "additionalProperties": "SYS-SCHEMA-TYPE",
}


class ValidationResult(BaseModel):
    model_config = ConfigDict(frozen=True)
    ok: bool
    normalized_args: dict[str, Any]
    findings: tuple[Finding, ...]


def _finding(rule: str, reason: str, arg: str | None = None, **evidence: Any) -> Finding:
    return Finding.model_construct(rule_id=rule, stage=Stage.SCHEMA, verdict=Verdict.BLOCK, reason=reason, arg=arg,
                                   evidence=evidence)


def _normalize(value: Any, *, light: bool) -> Any:
    if isinstance(value, str):
        return strip_invisible(value) if light else normalize_text(value)
    if isinstance(value, list):
        return [_normalize(v, light=light) for v in value]
    if isinstance(value, dict):
        return {k: _normalize(v, light=light) for k, v in value.items()}
    return value


_ASCII_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def _has_control(value: Any) -> bool:
    if isinstance(value, str):
        if value.isascii():
            return _ASCII_CONTROL_RE.search(value) is not None
        return any(unicodedata.category(ch) == "Cc" for ch in value)
    if isinstance(value, list):
        return any(_has_control(v) for v in value)
    return False


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    return []


def _is_nested(value: Any, spec: ArgSpec) -> bool:
    """Object/array where a scalar (or list of scalars) is declared."""
    if spec.type in (ArgType.DICT,):
        return isinstance(value, dict) and any(isinstance(v, (dict, list)) for v in value.values())
    if spec.type == ArgType.LIST and spec.items == ArgType.DICT:   # list of flat records, e.g. attachments
        return isinstance(value, list) and any(
            not isinstance(v, dict) or any(isinstance(x, (dict, list)) for x in v.values()) for v in value)
    if spec.type in (ArgType.LIST, ArgType.COMMAND):
        return isinstance(value, list) and any(isinstance(v, (dict, list)) for v in value)
    return isinstance(value, (dict, list))


def _multi_address(value: str, t: ArgType) -> bool:
    if t == ArgType.URL:
        return value.count("://") > 1 or any(ch.isspace() for ch in value.strip())
    if _SMUGGLE_RE.search(value):
        return True
    if t in (ArgType.EMAIL, ArgType.HANDLE):
        return value.count("@") > 1
    if len(value) <= 34:  # longest IBAN
        return False
    found = extract_typed_values(value).get(t, set())
    return len(found) > 1


def _homoglyph(value: str, spec: ArgSpec, t: ArgType) -> bool:
    if value.isascii():
        return False
    if spec.role == ArgRole.AUTHORITY and any(mixed_script(tok) for tok in re.split(r"[\s@./:_-]+", value)):
        return True
    return t in _HOMOGLYPH_TYPES and skeleton(value) != normalize_text(value).lower()


@lru_cache(maxsize=4096)
def _compiled(schema_json: str) -> Callable[[Any], Any]:
    """fastjsonschema compilation is pure; share compiled validators across gateways (one per episode)."""
    formats = {f"fw-{t.value}": (lambda _v: True) for t in ArgType}
    return fastjsonschema.compile(json.loads(schema_json), formats=formats)


class SchemaValidator:
    """Per-tool compiled validators (lazy, cached by definition hash)."""

    def __init__(self, registry: ToolRegistry | None = None) -> None:
        self.registry = registry
        self._cache: dict[str, dict[str, Callable[[Any], Any]]] = {}
        self._out_cache: dict[str, Callable[[Any], Any]] = {}
        self._lock = threading.Lock()
        self.compile_count = 0

    def _compile(self, schema: dict[str, Any]) -> Callable[[Any], Any]:
        self.compile_count += 1   # per-instance builds; the compiled function itself is shared process-wide
        return _compiled(json.dumps(schema, sort_keys=True))

    def _validators(self, spec: ToolSpec) -> dict[str, Callable[[Any], Any]]:
        key = f"{spec.qualified_name}#{spec.definition_hash()}"
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        with self._lock:
            cached = self._cache.get(key)
            if cached is None:
                cached = {}
                for name, a in spec.args.items():
                    schema = arg_json_schema(a)
                    if a.max_length is None and schema.get("type") == "string":
                        schema["maxLength"] = DEFAULT_MAX_LENGTH[a.role]
                    if a.type == ArgType.LIST and schema["items"].get("type") == "string":
                        schema["items"].setdefault("maxLength", DEFAULT_MAX_LENGTH[a.role])
                    cached[name] = self._compile(schema)
                self._cache[key] = cached
        return cached

    def validate_args(self, spec: ToolSpec, args: Mapping[str, Any]) -> ValidationResult:
        if not isinstance(args, Mapping):
            f = _finding("SYS-SCHEMA-TYPE", "arguments must be a JSON object")
            return ValidationResult(ok=False, normalized_args={}, findings=(f,))
        findings: list[Finding] = []
        normalized: dict[str, Any] = {}
        validators = self._validators(spec)
        for name, raw in args.items():
            a = spec.args.get(name)
            if a is None:
                findings.append(_finding("SYS-SCHEMA-EXTRA-KEY", f"unexpected argument {name!r}", name))
                continue
            if a.role in (ArgRole.AUTHORITY, ArgRole.BOUNDED, ArgRole.SELECTOR) and _has_control(raw):
                findings.append(_finding("SYS-SCHEMA-CONTROL-CHARS", f"{name}: control characters", name))
            value = _normalize(raw, light=a.role == ArgRole.CONTENT)
            normalized[name] = value
        for name, a in spec.args.items():
            if a.required and (name not in normalized or normalized[name] is None):
                findings.append(_finding("SYS-SCHEMA-MISSING", f"missing required argument {name!r}", name))
        for name, value in normalized.items():
            if value is None:
                continue
            findings.extend(self._check_arg(name, spec.args[name], value, validators[name]))
        return ValidationResult(ok=not findings, normalized_args=normalized, findings=tuple(findings))

    def _check_arg(self, name: str, a: ArgSpec, value: Any, validator: Callable[[Any], Any]) -> list[Finding]:
        if _is_nested(value, a):
            return [_finding("SYS-SCHEMA-NESTED", f"{name}: nested structure where a scalar is declared", name)]
        out: list[Finding] = []
        try:
            validator(value)
        except fastjsonschema.JsonSchemaValueException as exc:
            rule = _RULE_FOR_KEYWORD.get(str(exc.rule), "SYS-SCHEMA-TYPE")
            return [_finding(rule, f"{name}: {exc.message}", name)]
        item_type = a.items if a.type == ArgType.LIST else a.type
        values = value if a.type == ArgType.LIST else [value]
        for v in values:
            if item_type is None:
                continue
            if isinstance(v, str) and item_type in _TYPED_SINGLE and _multi_address(v, item_type):
                out.append(_finding("SYS-SCHEMA-MULTI-ADDRESS", f"{name}: more than one address in a single field",
                                    name))
                continue
            check = FORMAT_CHECKS.get(item_type)
            if item_type == ArgType.AMOUNT:
                if not _amount_ok(v, a):
                    out.append(_finding("SYS-SCHEMA-FORMAT", f"{name}: not a valid positive amount", name))
                elif not self._amount_in_range(v, a):
                    out.append(_finding("SYS-SCHEMA-RANGE", f"{name}: amount out of range", name))
            elif check is not None and not check(v):
                out.append(_finding("SYS-SCHEMA-FORMAT", f"{name}: invalid {item_type.value}", name))
            if isinstance(v, str) and _homoglyph(v, a, item_type):
                out.append(_finding("SYS-SCHEMA-HOMOGLYPH", f"{name}: mixed-script / look-alike characters", name))
        if a.type == ArgType.COMMAND and not FORMAT_CHECKS[ArgType.COMMAND](value):
            out.append(_finding("SYS-SCHEMA-FORMAT", f"{name}: command must be a non-empty list of strings", name))
        if not a.allow_urls and any(_URL_IN_TEXT_RE.search(s) for s in _strings(value)):
            out.append(_finding("SYS-SCHEMA-URL-IN-TEXT", f"{name}: URLs are not allowed in this field", name))
        return out

    @staticmethod
    def _amount_in_range(v: Any, a: ArgSpec) -> bool:
        d = parse_amount(v)
        if d is None:
            return False
        if a.minimum is not None and d < Decimal(str(a.minimum)):
            return False
        return a.maximum is None or d <= Decimal(str(a.maximum))

    def validate_output(self, spec: ToolSpec, output: Any) -> tuple[Finding, ...]:
        """Validate against `output.schema` if declared; failures are audit annotations (ALLOW)."""
        schema = spec.output.schema_
        if schema is None:
            return ()
        key = f"{spec.qualified_name}#{spec.definition_hash()}"
        validator = self._out_cache.get(key)
        if validator is None:
            validator = self._compile(schema)
            self._out_cache[key] = validator
        try:
            validator(output)
        except fastjsonschema.JsonSchemaValueException as exc:
            return (Finding(rule_id="SYS-SCHEMA-OUTPUT", stage=Stage.SCHEMA, verdict=Verdict.ALLOW,
                            reason=f"output does not match declared schema: {exc.message}"),)
        return ()
