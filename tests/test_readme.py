"""README commands: every `python -m firewall.<module>` exists, and flags shown for key CLIs are real."""

from __future__ import annotations

import importlib
import importlib.util
import re
from pathlib import Path

import pytest

README = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")


def _code_blocks(text: str) -> str:
    out, inside = [], False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            inside = not inside
            continue
        if inside:
            out.append(line)
    return "\n".join(out)


BLOCKS = _code_blocks(README)
COMMANDS = re.findall(r"-m (firewall(?:\.\w+)+)((?:[^\n\\]|\\\n)*)", BLOCKS)
CHECKED = {"firewall.eval.run_scenarios", "firewall.eval.report", "firewall.eval.agentdojo.run",
           "firewall.bench.latency", "firewall.eval.mutations", "firewall.eval.all", "firewall.agent.run"}


def test_readme_mentions_commands() -> None:
    assert len(COMMANDS) >= 10


@pytest.mark.parametrize("module", sorted({m for m, _ in COMMANDS}))
def test_module_importable(module: str) -> None:
    assert importlib.util.find_spec(module) is not None, module


def _help(module: str, capsys: pytest.CaptureFixture[str]) -> str:
    mod = importlib.import_module(module)
    with pytest.raises(SystemExit):
        mod.main(["--help"])
    return capsys.readouterr().out


@pytest.mark.parametrize("module", sorted(CHECKED))
def test_flags_exist(module: str, capsys: pytest.CaptureFixture[str]) -> None:
    flags = {f for m, rest in COMMANDS if m == module for f in re.findall(r"(--[a-z][\w-]*)", rest)}
    if not flags:
        pytest.skip(f"no flags shown for {module}")
    text = _help(module, capsys)
    for f in flags:
        assert f in text, f"{module}: README shows {f} but --help does not list it"
