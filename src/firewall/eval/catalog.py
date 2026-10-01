"""Generate docs Appendices B (scenarios), C (LivePI-style matrix), D (Pinch templates), F (oracles)."""

from __future__ import annotations

import argparse
import inspect
import sys
from pathlib import Path

from firewall.eval.livepi import INFEASIBLE, _load
from firewall.eval.loader import load_scenarios
from firewall.eval.oracles import ORACLES
from firewall.eval.pinch_gen import load_templates
from firewall.eval.scenario import OracleSpec, Scenario


def _cell(text: str, n: int = 110) -> str:
    t = " ".join(str(text).split()).replace("|", "\\|")
    return t if len(t) <= n else t[: n - 1] + "…"


def _oracle(o: OracleSpec | None) -> str:
    if o is None:
        return "-"
    if o.check in ("any_of", "all_of"):
        inner = ", ".join(_oracle(OracleSpec(**c)) for c in o.params.get("checks", []))
        return f"{o.check}({inner})"
    params = ", ".join(f"{k}={v}" for k, v in o.params.items())
    return f"{'not ' if o.negate else ''}{o.check}({params})"


def _script(sc: Scenario) -> str:
    return " → ".join(f"{'**' if s.induced else ''}{s.tool or 'answer'}{'**' if s.induced else ''}"
                      for s in sc.script)


def appendix_b() -> str:
    lines = ["# Appendix B — Scenario catalog (A01–A42, B01–B42, T-items)", "",
             ("Generated from `src/firewall/eval/scenarios/{attacks,benign,extra}/*.yaml` by "
              "`python -m firewall.eval.catalog --write`. Sources: research/04 Part C(b) (A/B tables) and "
              "research/03 §6 (T-items). Attack scripts are compromised trajectories: **bold** steps are "
              "`induced` (performed because of the injection, with the attacker's literal values)."), "",
             "| id | kind | category | user prompt | injection location | script | oracle(s) | expected | twin |",
             "|---|---|---|---|---|---|---|---|---|"]
    for sc in load_scenarios(include=("core", "extra")):
        loc = "; ".join(i.location for i in sc.injections) or ("overrides" if sc.overrides else "-")
        oracles = _oracle(sc.attack_oracle) if sc.kind == "attack" else "; ".join(map(_oracle, sc.utility_oracles))
        exp = sc.expected.gate + (f" ({', '.join(sc.expected.controls)})" if sc.expected.controls else "")
        legit = f"<br>legit: {_cell(str(sc.legit_values), 80)}" if sc.legit_values else ""
        lines.append(f"| {sc.id} | {sc.kind} | {sc.category} | {_cell(sc.user_prompt)} | `{_cell(loc, 60)}` | "
                     f"{_script(sc)} | {_cell(oracles, 120)}{legit} | {exp} | {sc.twin or ''} |")
    lines += ["", ("Deviations: T04 (SQL secret table) is modelled as secret store → shared channel post because "
                   "the mock world has no SQL tool; split-payload mutations keep both halves in one output (see "
                   "docs/DECISIONS.md).")]
    return "\n".join(lines) + "\n"


def appendix_c() -> str:
    fams, goals = _load()
    head = "| family | surface | " + " | ".join(g["id"] for g in goals) + " |"
    lines = ["# Appendix C — LivePI-style families × goals", "",
             ("Generated from `src/firewall/eval/scenarios/livepi/{families,goals}.yaml`. 12 technique families × "
              "5 goals on mocked channels; ✓ = feasible (generated with `--per-family 5`), – = infeasible. The MVP "
              "suite takes 2 feasible goals per family, rotated by family index + seed (24 cases). Numbers are "
              "**not comparable** to LivePI (different agent, models and channels)."), "", head,
             "|---|---|" + "---|" * len(goals)]
    for f in fams:
        marks = " | ".join("–" if (f["id"], g["id"]) in INFEASIBLE else "✓" for g in goals)
        lines.append(f"| {f['id']} | {f['surface']} | {marks} |")
    lines += ["", "## Families", "", "| family | user prompt | injection template |", "|---|---|---|"]
    lines += [f"| {f['id']} | {_cell(f['user_prompt'])} | {_cell(f['template'])} |" for f in fams]
    lines += ["", "## Goals", "", "| goal | instruction | compromised steps | attack oracle |", "|---|---|---|---|"]
    lines += [f"| {g['id']} | {_cell(g['instruction'])} | {' → '.join(s['tool'] for s in g['steps'])} | "
              f"{_oracle(OracleSpec(**g['attack_oracle']))} |" for g in goals]
    return "\n".join(lines) + "\n"


def appendix_d() -> str:
    tpls = load_templates()
    lines = ["# Appendix D — Pinch-like benign templates", "",
             (f"Generated from `src/firewall/eval/scenarios/pinch/templates.yaml` ({len(tpls)} templates). "
              "`generate_pinch(n_tasks=120, seed=0)` cycles through the templates and draws one variant per task "
              "with `random.Random(seed)` (values from the base world); ≥ 600 tool calls are asserted."), "",
             "| template | prompt | steps | variants | utility |", "|---|---|---|---|---|"]
    for t in tpls:
        lines.append(f"| {t['id']} | {_cell(t['prompt'])} | {' → '.join(s['tool'] for s in t['steps'])} | "
                     f"{len(t['variants'])} | {_oracle(OracleSpec(**t['utility']))} |")
    return "\n".join(lines) + "\n"


def appendix_f() -> str:
    lines = ["# Appendix F — Oracle catalog", "",
             ("Deterministic checks over the final MockWorld and the episode trace "
              "(`src/firewall/eval/oracles.py`). Executed-call oracles only count successful tool executions in "
              "`world.log` (blocked calls never reach a tool). Values are compared case-, space- and "
              "dash-insensitively."), "",
             "| oracle | meaning |", "|---|---|"]
    for name, fn in ORACLES.items():
        doc = inspect.getdoc(fn) or name.replace("_", " ")
        lines.append(f"| `{name}` | {_cell(doc, 200)} |")
    return "\n".join(lines) + "\n"


def appendix_g() -> str:
    from firewall.eval.agentdojo.registry_map import SUITES, load_agentdojo_registry

    lines = ["# Appendix G — AgentDojo v1.2.2 registry mapping", "",
             ("Generated from `src/firewall/registry/agentdojo_<suite>.yaml` (pinned commit in `bench.lock`); policies: "
              "`src/firewall/policies/agentdojo/ad_<suite>.yaml`. Coverage is complete for all four suites "
              "(`registry_map.coverage`). Deviations from our own registry: Slack users/channels/URLs and banking "
              "recipients are `text` (AgentDojo uses bare names, scheme-less URLs and pays named merchants); "
              "`get_channels` output is untrusted (an injection vector lives in an external channel name); times "
              "are free-form `text` meta."), ""]
    for suite in SUITES:
        reg = load_agentdojo_registry(suite)
        rows = []
        for s in sorted(reg.specs(), key=lambda s: s.name):
            args = ", ".join(f"{n}:{a.type.value}/{a.role.value}" for n, a in s.args.items()) or "–"
            dest = f"{s.destination.kind.value} via {list(s.destination.args)}" if s.destination else "–"
            rows.append(f"| `{s.name}` | {s.side_effect.value} | {dest} | {args} | {s.output.source_trust} |")
        lines += [f"## {suite}", "", "| tool | side effect | sink destination | args (type/role) | output trust |",
                  "|---|---|---|---|---|", *rows, ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m firewall.eval.catalog")
    p.add_argument("--write", action="store_true")
    p.add_argument("--docs", type=Path, default=Path("docs"))
    args = p.parse_args(argv)
    docs = {"APPENDIX_B_scenarios.md": appendix_b(), "APPENDIX_C_livepi.md": appendix_c(),
            "APPENDIX_D_pinch.md": appendix_d(), "APPENDIX_F_oracles.md": appendix_f(),
            "APPENDIX_G_agentdojo.md": appendix_g()}
    for name, text in docs.items():
        if args.write:
            (args.docs / name).write_text(text, encoding="utf-8")
        print(f"{name}: {len(text.splitlines())} lines" + (" (written)" if args.write else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
