"""LivePI-style and Pinch-like generators: sizes, determinism, feasibility, B0 utility."""

from __future__ import annotations

from firewall.eval.livepi import INFEASIBLE, feasible_matrix, generate_livepi_scenarios
from firewall.eval.pinch_gen import generate_pinch, load_templates


def test_livepi_counts_and_matrix() -> None:
    mvp = generate_livepi_scenarios()
    assert len(mvp) >= 24 and len({s.id for s in mvp}) == len(mvp)
    fams = {s.livepi.family for s in mvp if s.livepi}
    assert len(fams) == 12
    for s in mvp:
        assert s.livepi is not None and (s.livepi.family, s.livepi.goal) not in INFEASIBLE
        assert s.kind == "attack" and any(st.induced for st in s.script)
    stretch = generate_livepi_scenarios(per_family=5)
    assert len(stretch) == len(feasible_matrix()) == 56
    assert {s.livepi.surface for s in stretch if s.livepi} == {"email", "group_chat", "local_docs", "repo_link",
                                                                 "gist"}


def test_livepi_deterministic_by_seed() -> None:
    assert [s.id for s in generate_livepi_scenarios(seed=1)] == [s.id for s in generate_livepi_scenarios(seed=1)]
    assert [s.id for s in generate_livepi_scenarios(seed=0)] != [s.id for s in generate_livepi_scenarios(seed=1)]


def test_pinch_size_and_determinism() -> None:
    assert len(load_templates()) >= 25
    tasks = generate_pinch()
    assert len(tasks) >= 120
    assert sum(1 for t in tasks for s in t.script if s.kind == "call") >= 600
    assert [t.model_dump() for t in tasks] == [t.model_dump() for t in generate_pinch()]
    assert [t.user_prompt for t in tasks] != [t.user_prompt for t in generate_pinch(seed=3)]
    assert all(t.kind == "benign" and "{" not in t.user_prompt for t in tasks)


def test_generated_utilities_under_b0(suite_run) -> None:  # type: ignore[no-untyped-def]
    assert all(e.utility for e in suite_run.of("B0", "PB"))
    assert all(e.attack_success for e in suite_run.of("B0", "LP"))
