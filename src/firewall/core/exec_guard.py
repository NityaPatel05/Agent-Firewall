"""Exec-context checks over (argv, env delta, cwd, files touched) — not just the command name."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from firewall.core.canonical import canon_path, url_parts
from firewall.core.extract import URL_BODY_RE
from firewall.core.models import ArgOrigin, Finding, OriginClass, SideEffect, Stage, Verdict
from firewall.core.registry import ToolSpec

if TYPE_CHECKING:
    from firewall.core.policy.loader import CompiledPolicy

SHELLS = frozenset({"sh", "bash", "zsh", "dash", "fish", "cmd", "powershell", "pwsh"})
SHELL_FLAGS = frozenset({"-c", "/c", "/k", "-command", "-encodedcommand", "-e"})
NET_TOOLS = frozenset({"curl", "wget", "nc", "ncat", "netcat", "invoke-webrequest", "iwr", "invoke-restmethod",
                       "irm", "scp", "ftp", "telnet", "ssh"})
_META_RE = re.compile(r"[;|&`<>]|\$\(")
_SPLIT_RE = re.compile(r"[\s'\"=,()]+")


def _f(rule: str, reason: str, **ev: Any) -> Finding:
    return Finding.model_construct(rule_id=rule, stage=Stage.SINK, verdict=Verdict.BLOCK, reason=reason, arg="argv",
                                   evidence=ev)


def _basename(arg: str) -> str:
    name = arg.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name.removesuffix(".exe")


def _protected(token: str, policy: CompiledPolicy) -> bool:
    path = canon_path(token)
    if not path or ("/" not in path and "." not in path and "~" not in path):
        return False
    base = {path.lower(), "/" + path.lower().lstrip("/")}
    candidates = base | {c + "/" for c in base}
    return any(policy.glob(g).match(c) for g in policy.policy.allowlists.protected_paths for c in candidates)


def exec_findings(spec: ToolSpec, args: Mapping[str, Any], origins: Mapping[str, ArgOrigin],
                  policy: CompiledPolicy) -> list[Finding]:
    if spec.side_effect != SideEffect.EXEC:
        return []
    argv = args.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
        return []
    al = policy.policy.allowlists
    out: list[Finding] = []
    names = [_basename(a) for a in argv]
    if names[0] not in {b.lower() for b in al.exec_binaries}:
        out.append(_f("SYS-EXEC-BINARY", f"binary {names[0]!r} is not allow-listed", binary=names[0]))
    lowered = [a.lower() for a in argv]
    if any(_META_RE.search(a) for a in argv) or (names[0] in SHELLS and any(a in SHELL_FLAGS for a in lowered[1:])):
        out.append(_f("SYS-EXEC-SHELL", "shell metacharacters or `shell -c` invocation"))
    env = args.get("env") or {}
    if isinstance(env, Mapping):
        bad = sorted(k for k in env if str(k).upper() in {e.upper() for e in al.env_denylist})
        if bad:
            out.append(_f("SYS-EXEC-ENV", f"environment variables not allowed: {bad}", env=bad))
    tokens = [t for a in argv for t in _SPLIT_RE.split(a) if t]
    cwd = args.get("cwd")
    if isinstance(cwd, str):
        tokens.append(cwd)
    hits = sorted({t for t in tokens if _protected(t, policy)})
    if hits:
        out.append(_f("SYS-EXEC-PROTECTED", f"command touches protected paths: {hits[:3]}", paths=hits[:5]))
    urls = [m.group(0) for a in argv for m in URL_BODY_RE.finditer(a)]
    token_names = {_basename(t) for t in tokens}
    uses_net = bool(token_names & NET_TOOLS) or (names[0].startswith("python") and "-c" in lowered and urls)
    if uses_net:
        origin = origins.get("argv")
        hosts = [p.host for p in (url_parts(u) for u in urls) if p is not None]
        user_typed = origin is not None and origin.origin_class == OriginClass.USER_TYPED
        if not (hosts and user_typed and all(h in al.http_hosts for h in hosts)):
            out.append(_f("SYS-EXEC-NET", "network access from an exec tool", hosts=hosts))
    return out
