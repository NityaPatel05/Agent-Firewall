"""Tool registry: per-tool metadata (roles, trust, side effects), hash pinning, collision detection."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import threading
from collections.abc import Iterable, Mapping, Sequence
from decimal import Decimal
from enum import Enum, StrEnum
from functools import cached_property, lru_cache
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from firewall.core.labels import FastConstructModel
from firewall.core.models import ArgRole, ArgType, SideEffect

TrustLevel = Literal["trusted", "untrusted", "own_record"]
_FROZEN = ConfigDict(frozen=True, populate_by_name=True, extra="forbid")

# Side effects that do not change state; everything else is "consequential".
NON_CONSEQUENTIAL: frozenset[SideEffect] = frozenset({SideEffect.READ, SideEffect.FETCH})


class ArgSpec(BaseModel):
    model_config = _FROZEN
    type: ArgType
    role: ArgRole
    required: bool = False
    items: ArgType | None = None
    enum: tuple[str, ...] | None = None
    minimum: float | None = None
    maximum: float | None = None
    max_length: int | None = None
    min_items: int | None = None
    max_items: int | None = None
    pattern: str | None = None
    allow_urls: bool = True
    origin_required: bool = True
    transfers_content: bool = False   # selector whose referenced resource is sent to the sink (forward, share)
    description: str = ""

    @property
    def value_type(self) -> ArgType:
        """Type used for provenance of each value (item type for lists)."""
        if self.type == ArgType.LIST and self.items is not None:
            return self.items
        return self.type


class OutputSpec(BaseModel):
    model_config = _FROZEN
    source_trust: TrustLevel = "untrusted"
    sensitivity: Literal["public", "private", "secret"] = "private"
    fields: dict[str, TrustLevel] = Field(default_factory=dict)
    author_field: str | None = None
    item_path: str | None = None
    ref_field: str | None = None
    alias_fields: tuple[str, ...] = ()
    mask_secrets: bool = False
    schema_: dict[str, Any] | None = Field(None, alias="schema")


class DestinationSpec(BaseModel):
    model_config = _FROZEN
    args: tuple[str, ...] = ()
    kind: ArgType
    derived_from: tuple[str, str] | None = None

    @model_validator(mode="before")
    @classmethod
    def _single_arg(cls, data: Any) -> Any:
        if isinstance(data, dict) and "arg" in data:
            data = dict(data)
            arg = data.pop("arg")
            data["args"] = tuple(data.get("args", ())) + (arg,)
        return data


def _canonical(obj: Any) -> Any:
    """JSON-ready structure with deterministic ordering (sets sorted, enums by value)."""
    if isinstance(obj, BaseModel):
        return _canonical(obj.model_dump(mode="python", by_alias=True))
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, Mapping):
        return {str(k.value if isinstance(k, Enum) else k): _canonical(v) for k, v in obj.items()}
    if isinstance(obj, (set, frozenset)):
        return sorted((_canonical(v) for v in obj), key=lambda x: json.dumps(x, sort_keys=True))
    if isinstance(obj, (list, tuple)):
        return [_canonical(v) for v in obj]
    if isinstance(obj, Decimal):
        return str(obj)
    return obj


def canonical_json(obj: Any) -> str:
    return json.dumps(_canonical(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class ToolSpec(BaseModel):
    model_config = _FROZEN
    name: str
    server: str = "local"
    description: str = ""
    side_effect: SideEffect
    groups: frozenset[str] = frozenset()
    sink: bool = False
    destination: DestinationSpec | None = None
    args: dict[str, ArgSpec] = Field(default_factory=dict)
    output: OutputSpec = OutputSpec()
    ref_arg: str | None = None
    writes_ref_arg: str | None = None
    annotated: bool = True

    @model_validator(mode="after")
    def _check_refs(self) -> ToolSpec:
        for ref in (self.ref_arg, self.writes_ref_arg):
            if ref is not None and ref not in self.args:
                raise ValueError(f"{self.name}: ref arg {ref!r} is not a declared argument")
        if self.destination is not None:
            for a in self.destination.args:
                if a not in self.args:
                    raise ValueError(f"{self.name}: destination arg {a!r} is not a declared argument")
        return self

    @property
    def qualified_name(self) -> str:
        return self.name if self.server == "local" else f"{self.server}__{self.name}"

    @property
    def consequential(self) -> bool:
        return self.side_effect not in NON_CONSEQUENTIAL

    @property
    def effective_groups(self) -> frozenset[str]:
        extra = {self.side_effect.value}
        if self.consequential:
            extra.add("consequential")
        if self.sink:
            extra.add("egress")
        return self.groups | extra

    @cached_property
    def def_hash(self) -> str:
        """Cached SHA-256 of the canonical definition (the model is frozen, so it never changes)."""
        return sha256_hex(canonical_json(self))

    def definition_hash(self) -> str:
        return self.def_hash

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> ToolSpec:
        """Copies must never inherit the cached hash of the original (a changed copy is a rug pull)."""
        new = super().model_copy(update=update, deep=deep)
        new.__dict__.pop("def_hash", None)
        return new

    def to_json_schema(self) -> dict[str, Any]:
        """Strict JSON Schema of the arguments (no extra keys; formats are named `fw-<type>`)."""
        return {
            "type": "object",
            "properties": {name: arg_json_schema(a) for name, a in self.args.items()},
            "required": sorted(n for n, a in self.args.items() if a.required),
            "additionalProperties": False,
        }


_JSON_TYPES: dict[ArgType, Any] = {
    ArgType.AMOUNT: ["number", "string"],
    ArgType.BOOL: "boolean",
    ArgType.INT: "integer",
    ArgType.LIST: "array",
    ArgType.DICT: "object",
    ArgType.COMMAND: "array",
}


def _scalar_schema(t: ArgType) -> dict[str, Any]:
    out: dict[str, Any] = {"type": _JSON_TYPES.get(t, "string")}
    if t == ArgType.COMMAND:
        out["items"] = {"type": "string"}
    elif t == ArgType.DICT:
        out["additionalProperties"] = {"type": ["string", "number", "boolean"]}
    if t not in (ArgType.BOOL, ArgType.INT, ArgType.DICT, ArgType.ENUM, ArgType.TEXT, ArgType.SECRET_TEXT):
        out["format"] = f"fw-{t.value}"
    return out


def arg_json_schema(a: ArgSpec) -> dict[str, Any]:
    """JSON Schema fragment for one argument."""
    if a.type == ArgType.LIST:
        item = _scalar_schema(a.items or ArgType.TEXT)
        if a.max_length is not None and item["type"] == "string":
            item["maxLength"] = a.max_length
        out: dict[str, Any] = {"type": "array", "items": item}
        if a.min_items is not None:
            out["minItems"] = a.min_items
        if a.max_items is not None:
            out["maxItems"] = a.max_items
        return out
    out = _scalar_schema(a.type)
    if a.enum is not None:
        out["enum"] = list(a.enum)
    if a.minimum is not None and a.type == ArgType.INT:
        out["minimum"] = a.minimum
    if a.maximum is not None and a.type == ArgType.INT:
        out["maximum"] = a.maximum
    if a.max_length is not None and out["type"] == "string":
        out["maxLength"] = a.max_length
    if a.pattern is not None:
        out["pattern"] = a.pattern
    return out


class ResolveStatus(StrEnum):
    OK = "ok"
    UNKNOWN = "unknown"
    AMBIGUOUS = "ambiguous"
    PIN_MISMATCH = "pin_mismatch"
    UNAPPROVED = "unapproved"


class ResolveResult(FastConstructModel):
    model_config = ConfigDict(frozen=True)
    status: ResolveStatus
    spec: ToolSpec | None = None
    candidates: tuple[str, ...] = ()


class RegistryError(ValueError):
    pass


class ToolRegistry:
    """Thread-safe registry of tool specs with hash pins and dynamic (MCP) registration."""

    def __init__(
        self,
        specs: Iterable[ToolSpec],
        *,
        pins: Mapping[str, str] | None = None,
        trusted_servers: Iterable[str] = ("local",),
    ) -> None:
        self._lock = threading.RLock()
        self._specs: dict[str, ToolSpec] = {}
        self._by_bare: dict[str, list[str]] = {}
        self._trusted_servers = frozenset(trusted_servers)
        self._unapproved: set[str] = set()
        self._approved_individually: set[str] = set()
        self._hash_cache: str | None = None
        for spec in specs:
            self._add(spec)
        self._pins: dict[str, str] = (
            dict(pins) if pins is not None else {q: s.definition_hash() for q, s in self._specs.items()}
        )

    def _add(self, spec: ToolSpec) -> None:
        q = spec.qualified_name
        if q in self._specs and self._specs[q] != spec:
            raise RegistryError(f"duplicate tool definition: {q}")
        self._specs[q] = spec
        bare = self._by_bare.setdefault(spec.name, [])
        if q not in bare:
            bare.append(q)

    @classmethod
    def from_yaml(
        cls,
        paths: Sequence[Path] | None = None,
        *,
        lock_path: Path | None = None,
        trusted_servers: Iterable[str] | None = None,
    ) -> ToolRegistry:
        """Load registry files (None -> all packaged non-AgentDojo files)."""
        files = list(paths) if paths is not None else default_registry_files()
        specs: list[ToolSpec] = []
        trusted: set[str] = {"local"}
        for path in files:
            file_specs, file_trusted = _load_registry_file(path)
            specs.extend(file_specs)
            trusted |= file_trusted
        pins = cls.read_lock(lock_path) if lock_path is not None else None
        return cls(specs, pins=pins, trusted_servers=trusted if trusted_servers is None else trusted_servers)

    def _status(self, q: str) -> ResolveStatus:
        spec = self._specs[q]
        if q in self._unapproved:
            return ResolveStatus.UNAPPROVED
        if spec.server not in self._trusted_servers and q not in self._approved_individually:
            return ResolveStatus.UNAPPROVED
        if self._pins.get(q) != spec.definition_hash():
            return ResolveStatus.PIN_MISMATCH
        return ResolveStatus.OK

    def resolve(self, name: str, server: str | None = None) -> ResolveResult:
        """Resolve a (possibly unqualified) tool name; unqualified names on >1 server are AMBIGUOUS."""
        with self._lock:
            if server is not None:
                q = name if server == "local" or name.startswith(f"{server}__") else f"{server}__{name}"
                if q not in self._specs:
                    return ResolveResult.model_construct(status=ResolveStatus.UNKNOWN, spec=None, candidates=())
                return ResolveResult.model_construct(status=self._status(q), spec=self._specs[q], candidates=(q,))
            if name in self._specs and "__" in name:
                return ResolveResult.model_construct(status=self._status(name), spec=self._specs[name], candidates=(name,))
            candidates = tuple(self._by_bare.get(name, ()))
            if not candidates:
                return ResolveResult.model_construct(status=ResolveStatus.UNKNOWN, spec=None, candidates=())
            if len(candidates) > 1:
                return ResolveResult.model_construct(status=ResolveStatus.AMBIGUOUS, spec=None, candidates=candidates)
            q = candidates[0]
            return ResolveResult.model_construct(status=self._status(q), spec=self._specs[q], candidates=candidates)

    def get(self, qualified_name: str) -> ToolSpec | None:
        with self._lock:
            return self._specs.get(qualified_name)

    def specs(self) -> tuple[ToolSpec, ...]:
        with self._lock:
            return tuple(self._specs[q] for q in sorted(self._specs))

    def __len__(self) -> int:
        return len(self._specs)

    def observe_definition(self, spec: ToolSpec) -> ResolveStatus:
        """Compare an observed (e.g. MCP-listed) definition to its pin; a change is a rug pull."""
        with self._lock:
            self._hash_cache = None
            q = spec.qualified_name
            if q not in self._specs:
                self._specs[q] = spec
                self._by_bare.setdefault(spec.name, []).append(q)
                self._unapproved.add(q)
                return ResolveStatus.UNAPPROVED
            self._specs[q] = spec
            if self._pins.get(q) == spec.definition_hash():
                return ResolveStatus.OK
            return ResolveStatus.PIN_MISMATCH

    def register_dynamic(self, spec: ToolSpec, *, approved: bool) -> None:
        with self._lock:
            self._hash_cache = None
            q = spec.qualified_name
            self._specs[q] = spec
            bare = self._by_bare.setdefault(spec.name, [])
            if q not in bare:
                bare.append(q)
            if approved:
                self._pins[q] = spec.definition_hash()
                self._unapproved.discard(q)
                self._approved_individually.add(q)
            else:
                self._unapproved.add(q)

    def approve_definition(self, qualified_name: str) -> None:
        with self._lock:
            spec = self._specs.get(qualified_name)
            if spec is None:
                raise RegistryError(f"unknown tool: {qualified_name}")
            self._pins[qualified_name] = spec.definition_hash()
            self._unapproved.discard(qualified_name)
            self._approved_individually.add(qualified_name)

    def pins(self) -> dict[str, str]:
        with self._lock:
            return dict(self._pins)

    def registry_hash(self) -> str:
        cached = self._hash_cache
        if cached is not None:
            return cached
        with self._lock:
            items = sorted((q, s.definition_hash()) for q, s in self._specs.items())
            self._hash_cache = sha256_hex(json.dumps(items, separators=(",", ":")))
            return self._hash_cache

    def write_lock(self, path: Path) -> None:
        with self._lock:
            data = {q: s.definition_hash() for q, s in sorted(self._specs.items())}
        path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    @staticmethod
    def read_lock(path: Path) -> dict[str, str]:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise RegistryError(f"invalid lock file: {path}")
        return {str(k): str(v) for k, v in data.items()}


def _parse_tools(server: str, tools: Mapping[str, Any], path: Path) -> list[ToolSpec]:
    specs: list[ToolSpec] = []
    for name, body in (tools or {}).items():
        body = dict(body or {})
        body.setdefault("name", name)
        body.setdefault("server", server)
        try:
            specs.append(ToolSpec.model_validate(body))
        except ValueError as exc:
            raise RegistryError(f"{path}: tool {name!r}: {exc}") from exc
    return specs


def _load_registry_file(path: Path) -> tuple[list[ToolSpec], set[str]]:
    """Parse one registry file (cached per path + mtime; specs are frozen so they can be shared)."""
    st = path.stat()
    specs, trusted = _load_registry_file_cached(str(path), st.st_mtime_ns, st.st_size)
    return list(specs), set(trusted)


@lru_cache(maxsize=128)
def _load_registry_file_cached(path_str: str, mtime_ns: int, size: int) -> tuple[tuple[ToolSpec, ...], frozenset[str]]:
    specs, trusted = _parse_registry_file(Path(path_str))
    return tuple(specs), frozenset(trusted)


def _parse_registry_file(path: Path) -> tuple[list[ToolSpec], set[str]]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise RegistryError(f"{path}: top level must be a mapping")
    specs: list[ToolSpec] = []
    trusted: set[str] = set()
    if "servers" in data:
        for server, body in data["servers"].items():
            body = body or {}
            if body.get("trusted", True):
                trusted.add(server)
            specs.extend(_parse_tools(server, body.get("tools", {}), path))
    if "tools" in data:
        server = data.get("server", "local")
        if data.get("trusted", True):
            trusted.add(server)
        specs.extend(_parse_tools(server, data["tools"], path))
    return specs, trusted


def load_registry_yaml(path: Path) -> list[ToolSpec]:
    """Parse one registry file: `{server, tools: {...}}` or `{servers: {name: {trusted, tools}}}`."""
    return _load_registry_file(path)[0]


def default_registry_files() -> list[Path]:
    from firewall.resources import data_path

    root = data_path("registry")
    return sorted(p for p in root.glob("*.yaml") if not p.name.startswith("agentdojo_"))


def default_lock_path() -> Path:
    from firewall.resources import data_path

    return data_path("registry", "registry.lock.json")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m firewall.core.registry")
    parser.add_argument("--write-lock", action="store_true", help="regenerate registry.lock.json")
    parser.add_argument("--check", action="store_true", help="verify files load and match the lock")
    args = parser.parse_args(argv)
    reg = ToolRegistry.from_yaml()
    lock = default_lock_path()
    if args.write_lock:
        reg.write_lock(lock)
        print(f"wrote {lock} ({len(reg)} tools)")
    if args.check or not args.write_lock:
        if not lock.exists():
            print(f"FAIL lock file missing: {lock}")
            return 1
        pinned = ToolRegistry.read_lock(lock)
        current = {s.qualified_name: s.definition_hash() for s in reg.specs()}
        if pinned != current:
            diff = sorted(set(pinned.items()) ^ set(current.items()))
            print(f"FAIL lock mismatch for {sorted({k for k, _ in diff})}")
            return 1
        print(f"OK {len(reg)} tools, registry_hash={reg.registry_hash()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
