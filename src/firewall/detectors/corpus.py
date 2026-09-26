"""Benign / attack text corpora for detector calibration (from rendered scenario worlds, or a JSONL file)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    """Rows of {"suite": str, "label": "benign"|"attack", "text": str}."""
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _scenario_texts(kind: str) -> list[tuple[str, str]]:
    """Texts the agent would read in each scenario: attack = the injected strings, benign = untouched content."""
    from firewall.eval.loader import load_scenarios

    out: list[tuple[str, str]] = []
    for sc in load_scenarios(include=("core", "extra", "livepi")):
        if kind == "attack" and sc.kind == "attack":
            out += [(sc.suite, inj.text) for inj in sc.injections]
        elif kind == "benign" and sc.kind == "benign":
            world = sc.build_world()
            for step in sc.script:
                text = _content_of(world, step.tool or "", step.args)
                if text:
                    out.append((sc.suite, text))
    return out


def _content_of(world: Any, tool: str, args: dict[str, Any]) -> str | None:
    if tool == "read_email":
        e = next((m for m in world.inbox if m.id == args.get("email_id")), None)
        return e.body if e else None
    if tool == "read_file":
        f = world.files.get(args.get("path"))
        return f.content if f else None
    if tool == "get_webpage":
        p = world.web.get(args.get("url"))
        return p.text if p else None
    if tool == "read_channel":
        msgs = world.slack.channels.get(str(args.get("channel", "")).lower(), [])
        return "\n".join(m.text for m in msgs) or None
    return None


def benign_texts() -> list[tuple[str, str]]:
    return _scenario_texts("benign")


def attack_texts() -> list[tuple[str, str]]:
    return _scenario_texts("attack")


def corpus_rows(source: str | Path) -> list[dict[str, Any]]:
    """`scenarios` -> rows from the scenario suite; otherwise a JSONL path."""
    if str(source) == "scenarios":
        return ([{"suite": s, "label": "benign", "text": t} for s, t in benign_texts()]
                + [{"suite": s, "label": "attack", "text": t} for s, t in attack_texts()])
    return load_jsonl(Path(source))
