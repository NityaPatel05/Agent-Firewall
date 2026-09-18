"""Policy loading: YAML -> extends-merge -> validate -> compile -> freeze -> hash."""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
import threading
from collections.abc import Iterable
from dataclasses import dataclass, field
from fnmatch import translate
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from firewall.core.policy.model import Condition, Match, Policy, Rule
from firewall.core.registry import ToolRegistry, ToolSpec, canonical_json, sha256_hex
from firewall.resources import data_path

_SET_KEYS = frozenset({"allowlists"})


class PolicyError(ValueError):
    pass


def _match_spec(m: Match, spec: ToolSpec) -> bool:
    if m.tools and spec.qualified_name not in m.tools and spec.name not in m.tools:
        return False
    if m.groups and not (m.groups & spec.effective_groups):
        return False
    if m.side_effects and spec.side_effect not in m.side_effects:
        return False
    return not (m.servers and spec.server not in m.servers)


def _iter_conditions(cond: Condition | None) -> Iterable[Condition]:
    if cond is None:
        return
    yield cond
    for child in (*(cond.all or ()), *(cond.any or ())):
        yield from _iter_conditions(child)
    if cond.not_ is not None:
        yield from _iter_conditions(cond.not_)


@dataclass(frozen=True, slots=True)
class CompiledPolicy:
    """Merged, validated, frozen policy plus precompiled regexes and a per-tool rule index."""

    policy: Policy
    hash: str
    _regexes: dict[str, re.Pattern[str]] = field(default_factory=dict, repr=False, compare=False)
    _index: dict[str, tuple[Rule, ...]] = field(default_factory=dict, repr=False, compare=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    def rules_for(self, spec: ToolSpec) -> tuple[Rule, ...]:
        key = f"{spec.qualified_name}#{spec.definition_hash()}"
        cached = self._index.get(key)
        if cached is not None:
            return cached
        rules = tuple(r for r in self.policy.rules if _match_spec(r.match, spec))
        with self._lock:
            self._index[key] = rules
        return rules

    def regex(self, pattern: str) -> re.Pattern[str]:
        rx = self._regexes.get(pattern)
        if rx is None:
            rx = re.compile(pattern)
            with self._lock:
                self._regexes[pattern] = rx
        return rx

    def glob(self, pattern: str) -> re.Pattern[str]:
        """Case-insensitive glob compiled to a regex; `**` crosses directories like `*`."""
        key = f"glob:{pattern}"
        rx = self._regexes.get(key)
        if rx is None:
            rx = re.compile(translate(pattern.lower()))
            with self._lock:
                self._regexes[key] = rx
        return rx

    def allowlist(self, name: str) -> frozenset[str]:
        value = getattr(self.policy.allowlists, name, None)
        if value is None:
            raise PolicyError(f"unknown allowlist: {name}")
        return value


def _resolve_path(name_or_path: str | Path) -> Path:
    p = Path(name_or_path)
    if p.suffix in (".yaml", ".yml") and p.exists():
        return p
    if p.suffix in (".yaml", ".yml"):
        candidate = data_path("policies", p.name)
    else:
        candidate = data_path("policies", f"{name_or_path}.yaml")
    if not candidate.exists():
        raise PolicyError(f"policy not found: {name_or_path}")
    return candidate


def _read_raw(path: Path) -> dict[str, Any]:
    """Parsed policy YAML (cached per path + mtime; returns a deep copy the caller may mutate)."""
    st = path.stat()
    data = _read_raw_cached(str(path), st.st_mtime_ns, st.st_size)
    if not isinstance(data, dict):
        raise PolicyError(f"{path}: policy file must be a mapping")
    return copy.deepcopy(data)


@lru_cache(maxsize=256)
def _read_raw_cached(path_str: str, mtime_ns: int, size: int) -> Any:
    return yaml.safe_load(Path(path_str).read_text(encoding="utf-8"))


def _linearize(path: Path, visiting: set[Path], done: dict[Path, dict[str, Any]], order: list[Path]) -> None:
    """DFS post-order over `extends` with cycle detection; each file appears once."""
    path = path.resolve()
    if path in done:
        return
    if path in visiting:
        raise PolicyError(f"extends cycle at {path.name}")
    visiting.add(path)
    raw = _read_raw(path)
    parents = raw.get("extends", ())
    parents = [parents] if isinstance(parents, str) else list(parents)
    base_dir = path.parent
    for parent in parents:
        local = base_dir / f"{parent}.yaml"
        _linearize(local if local.exists() else _resolve_path(parent), visiting, done, order)
    visiting.discard(path)
    done[path] = raw
    order.append(path)


def _merge_raw(parent: dict[str, Any], child: dict[str, Any]) -> dict[str, Any]:
    """rules: parent then child (same id -> child replaces in place); allowlists/canaries: union;
    dicts: deep merge; scalars: child wins."""
    out = dict(parent)
    for key, cval in child.items():
        pval = out.get(key)
        if key == "rules":
            merged = list(pval or [])
            pos = {r["id"]: i for i, r in enumerate(merged)}
            for rule in cval or []:
                if rule["id"] in pos:
                    merged[pos[rule["id"]]] = rule
                else:
                    pos[rule["id"]] = len(merged)
                    merged.append(rule)
            out[key] = merged
        elif key == "canaries":
            seen = list(pval or [])
            out[key] = seen + [c for c in cval or [] if c not in seen]
        elif key in _SET_KEYS and isinstance(pval, dict) and isinstance(cval, dict):
            merged_sets = dict(pval)
            for k, v in cval.items():
                prev = list(merged_sets.get(k, []) or [])
                merged_sets[k] = prev + [x for x in (v or []) if x not in prev]
            out[key] = merged_sets
        elif isinstance(pval, dict) and isinstance(cval, dict):
            out[key] = _merge_raw(pval, cval)
        else:
            out[key] = cval
    return out


def merge_policies(parent: Policy, child: Policy) -> Policy:
    """Merge two validated policies (only fields explicitly set in `child` override)."""
    p = parent.model_dump(mode="json", by_alias=True, exclude_unset=True)
    c = child.model_dump(mode="json", by_alias=True, exclude_unset=True)
    merged = _merge_raw(p, c)
    merged.setdefault("version", 1)
    merged.setdefault("policy_id", child.policy_id)
    return Policy.model_validate(merged)


def _check_refs(policy: Policy, registry: ToolRegistry) -> None:
    names = {s.qualified_name for s in registry.specs()} | {s.name for s in registry.specs()}
    missing = sorted({t for r in policy.rules for t in r.match.tools if t not in names})
    if missing:
        raise PolicyError(f"policy {policy.policy_id!r} references unknown tools: {missing}")


def compile_policy(policy: Policy) -> CompiledPolicy:
    compiled = CompiledPolicy(policy=policy, hash=sha256_hex(canonical_json(policy)))
    for rule in policy.rules:
        for cond in _iter_conditions(rule.when):
            if cond.arg is not None and cond.op in ("regex", "glob"):
                values = cond.value if isinstance(cond.value, (list, tuple)) else [cond.value]
                for v in values:
                    if isinstance(v, str) and not v.startswith("@allowlists."):
                        try:
                            compiled.regex(v) if cond.op == "regex" else compiled.glob(v)
                        except re.error as exc:
                            raise PolicyError(f"{rule.id}: bad pattern {v!r}: {exc}") from exc
    for pattern in policy.allowlists.protected_paths:
        compiled.glob(pattern)
    return compiled


def load_policy(
    name_or_path: str | Path, *, registry: ToolRegistry | None = None, strict_refs: bool = True
) -> CompiledPolicy:
    """Load a policy by name (packaged) or path, resolving `extends` recursively."""
    path = _resolve_path(name_or_path)
    order: list[Path] = []
    done: dict[Path, dict[str, Any]] = {}
    _linearize(path, set(), done, order)
    merged: dict[str, Any] = {}
    for p in order:
        merged = _merge_raw(merged, done[p])
    merged["policy_id"] = done[path.resolve()].get("policy_id", path.stem)
    merged["extends"] = done[path.resolve()].get("extends", [])
    try:
        policy = Policy.model_validate(merged)
    except ValidationError as exc:
        raise PolicyError(f"{path.name}: {exc}") from exc
    if strict_refs:
        _check_refs(policy, registry or ToolRegistry.from_yaml())
    return compile_policy(policy)


def policy_json_schema() -> dict[str, Any]:
    return Policy.model_json_schema(by_alias=True)


def schema_text() -> str:
    return json.dumps(policy_json_schema(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def packaged_policy_files() -> list[Path]:
    return sorted(data_path("policies").glob("*.yaml"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m firewall.core.policy.loader")
    parser.add_argument("--validate", nargs="*", metavar="FILE", help="validate policy files (default: all packaged)")
    parser.add_argument("--export-schema", metavar="PATH", help="write the policy JSON schema")
    parser.add_argument("--show", metavar="NAME", help="print the merged policy as YAML")
    args = parser.parse_args(argv)
    if args.export_schema:
        Path(args.export_schema).write_text(schema_text(), encoding="utf-8")
        print(f"wrote {args.export_schema}")
    if args.show:
        cp = load_policy(args.show)
        print(yaml.safe_dump(cp.policy.model_dump(mode="json", by_alias=True), sort_keys=False))
        print(f"# hash={cp.hash}")
    if args.validate is not None:
        files = [Path(f) for f in args.validate] or packaged_policy_files()
        registry = ToolRegistry.from_yaml()
        errors = 0
        for f in files:
            try:
                load_policy(f, registry=registry)
            except (PolicyError, OSError) as exc:
                errors += 1
                print(f"FAIL {f}: {exc}")
        if errors:
            return 1
        all_hash = load_policy("all", registry=registry).hash
        print(f"OK {len(files)} policies, all={all_hash}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
