"""Offline AgentDojo ground-truth replay (no LLM): benign user-task GT -> FBR; user GT + injection GT -> gate-only ASR."""

from __future__ import annotations

import warnings
from collections.abc import Sequence
from typing import Any

from pydantic import BaseModel

from firewall.core.models import Decision, Verdict
from firewall.eval.agentdojo.compat import BENCHMARK_VERSION, get_suite, register_model_names
from firewall.eval.agentdojo.llm import GroundTruthLLM
from firewall.eval.agentdojo.pipelines import build_pipeline
from firewall.eval.agentdojo.registry_map import legit_values_from_ground_truth, load_agentdojo_registry
from firewall.eval.agentdojo.scoring import run_pair
from firewall.eval.records import DecisionLite, EpisodeResult

REPLAY_MODEL_ID = "gemini-3.5-flash-lite"   # attacks address the victim model by name


class ReplayCase(BaseModel):
    suite: str
    user_task: str
    injection_task: str | None
    gt_calls: int
    allow: int
    review: int
    block: int
    utility: bool | None
    security: bool | None            # executed effects (gate-only); see scoring.py
    security_native: bool | None = None
    decisions: list[DecisionLite] = []


def first_decisions(decisions: Sequence[Decision]) -> dict[str, tuple[Decision, Decision]]:
    out: dict[str, tuple[Decision, Decision]] = {}
    for d in decisions:
        out[d.call_id] = (out.get(d.call_id, (d, d))[0], d)
    return out


def counts(decisions: Sequence[Decision], induced_from: int | None = None) -> tuple[int, int, int, list[DecisionLite]]:
    """(allow, review, block) by first verdict, and DecisionLite rows (gt_N ids: N > induced_from = induced)."""
    per = first_decisions(decisions)
    n = {Verdict.ALLOW: 0, Verdict.REVIEW: 0, Verdict.BLOCK: 0}
    lites = []
    for cid, (first, last) in per.items():
        n[first.verdict] += 1
        induced = None
        if induced_from is not None and cid.startswith("gt_"):
            induced = int(cid[3:]) > induced_from
        lites.append(DecisionLite(call_id=cid, tool=first.tool, verdict=last.verdict, rule_ids=list(first.rule_ids),
                                  origins={k: o.origin_class.value for k, o in first.arg_origins.items()},
                                  eval_us=first.eval_us, induced=induced))
    return n[Verdict.ALLOW], n[Verdict.REVIEW], n[Verdict.BLOCK], lites


def _attack(name: str, suite: Any) -> Any:
    from agentdojo.attacks.attack_registry import load_attack

    class _Target:
        name = f"{REPLAY_MODEL_ID}-replay"

    register_model_names([REPLAY_MODEL_ID])
    return load_attack(name, suite, _Target())  # type: ignore[arg-type]


def replay_suite(suite_name: str, *, defense: str = "GW", attack: str = "important_instructions",
                 user_tasks: Sequence[str] | None = None, injection_tasks: Sequence[str] | None = None,
                 benign: bool = True, attacks: bool = True) -> list[ReplayCase]:
    suite = get_suite(suite_name, BENCHMARK_VERSION)
    registry = load_agentdojo_registry(suite_name)
    uts = [suite.get_user_task_by_id(u) for u in user_tasks] if user_tasks else list(suite.user_tasks.values())
    its = ([suite.get_injection_task_by_id(i) for i in injection_tasks] if injection_tasks
           else list(suite.injection_tasks.values()))
    out: list[ReplayCase] = []
    env0 = suite.load_and_inject_default_environment({})
    for ut in uts:
        gt = ut.ground_truth(ut.init_environment(env0.model_copy(deep=True)))
        legit = legit_values_from_ground_truth(gt, registry)
        if benign:
            llm = GroundTruthLLM(ut.ground_truth, ut.GROUND_TRUTH_OUTPUT)
            pipe, ex, _ = build_pipeline(defense, llm=llm, model_id=REPLAY_MODEL_ID, suite=suite_name, legit=legit)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                res = run_pair(suite, pipe, ut, None, {})
            a, r, b, lites = counts(ex.decisions if ex else [])
            out.append(ReplayCase(suite=suite_name, user_task=ut.ID, injection_task=None, gt_calls=len(gt), allow=a,
                                  review=r, block=b, utility=res.utility, security=None, decisions=lites))
        if not attacks:
            continue
        atk = _attack(attack, suite)
        for it in its:
            try:
                injections = atk.attack(ut, it)
            except ValueError:   # user task not injectable
                continue
            n_user = len(gt)

            def calls(env: Any, _ut: Any = ut, _it: Any = it) -> list[Any]:
                return [*_ut.ground_truth(env), *_it.ground_truth(env)]

            llm = GroundTruthLLM(calls, ut.GROUND_TRUTH_OUTPUT)
            pipe, ex, _ = build_pipeline(defense, llm=llm, model_id=REPLAY_MODEL_ID, suite=suite_name, legit=legit)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                res = run_pair(suite, pipe, ut, it, injections)
            a, r, b, lites = counts(ex.decisions if ex else [], induced_from=n_user)
            out.append(ReplayCase(suite=suite_name, user_task=ut.ID, injection_task=it.ID, gt_calls=n_user, allow=a,
                                  review=r, block=b, utility=res.utility, security=res.security_executed,
                                  security_native=res.security_native, decisions=lites))
    return out


def to_episode(c: ReplayCase, *, run_id: str, defense: str, mode: str = "offline", model: str = "ground-truth",
               approver: str = "oracle", **extra: Any) -> EpisodeResult:
    sid = f"AD-{c.suite}-{c.user_task}" + (f"-{c.injection_task}" if c.injection_task else "")
    return EpisodeResult(
        run_id=run_id, scenario_id=sid, kind="attack" if c.injection_task else "benign",
        suite=f"agentdojo/{c.suite}", category=f"agentdojo/{c.suite}", defense=defense, mode=mode, model=model,
        approver=approver, seed=0, attack_success=c.security if c.injection_task else None,
        attack_success_native=c.security_native if c.injection_task else None,
        utility=bool(c.utility), intermediate=None, n_tool_calls=c.allow + c.review + c.block, n_allow=c.allow,
        n_review=c.review, n_block=c.block, decisions=c.decisions, tags=["agentdojo"], **extra)
