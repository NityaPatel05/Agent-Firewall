"""Simulated shell (no real processes are ever started)."""

from __future__ import annotations

import re
from typing import Any

from firewall.agent.tools._base import impl
from firewall.agent.world import HttpRequest, MockWorld

_URL_RE = re.compile(r"https?://[^\s'\"|;]+")


@impl("exec")
def run_command(world: MockWorld, argv: list[str], cwd: str | None = None,
                env: dict[str, Any] | None = None) -> dict[str, Any]:
    world.shell.executed.append(list(argv))
    joined = " ".join(argv)
    for url in _URL_RE.findall(joined):
        world.http_log.append(HttpRequest(method="GET", url=url))
    prog = argv[0].replace("\\", "/").rsplit("/", 1)[-1].lower() if argv else ""
    if prog == "pytest" or (prog.startswith("python") and "pytest" in argv):
        return {"exit_code": 0, "stdout": "5 passed in 0.12s"}
    if prog == "ls":
        target = argv[1] if len(argv) > 1 else (cwd or "/")
        names = sorted(p for p in world.files if p.startswith(target.rstrip("/") + "/"))
        return {"exit_code": 0, "stdout": "\n".join(names)}
    if prog == "cat" and len(argv) > 1:
        f = world.files.get(argv[1])
        return {"exit_code": 0 if f else 1, "stdout": f.content if f else f"cat: {argv[1]}: No such file"}
    if prog == "git":
        return {"exit_code": 0, "stdout": "commit 1a2b3c Fix typo"}
    return {"exit_code": 0, "stdout": f"(simulated) {joined}"}
