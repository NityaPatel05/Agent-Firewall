"""Parametrized offline corpus: every fixture whose `since` <= CURRENT_MILESTONE is asserted."""

from __future__ import annotations

import pytest
from harness import (
    Fixture,
    build_gateway_session,
    build_policy_context,
    build_session,
    compute_origins,
    fixture_policy,
    load_fixtures,
    milestone_reached,
    resolve_spec,
)

from firewall.core.decoders import decode_candidates, split_payload_join, trigger_signals
from firewall.core.exec_guard import exec_findings
from firewall.core.markdown import sanitize_final_answer
from firewall.core.models import Verdict, max_verdict
from firewall.core.policy.engine import evaluate_policy
from firewall.core.provenance import resolve_origin
from firewall.core.registry import ToolRegistry
from firewall.core.rule_of_two import rule_of_two_finding
from firewall.core.schema_validation import SchemaValidator
from firewall.core.sinks import classify_destinations, compute_facts, sink_findings

CURRENT_MILESTONE = "M6"
KINDS = ("provenance", "policy", "schema", "decoders", "sinks", "pipeline")

_REGISTRY = ToolRegistry.from_yaml()
_VALIDATOR = SchemaValidator(_REGISTRY)


def _active(kind: str) -> list[Fixture]:
    return [f for f in load_fixtures(kind) if milestone_reached(f.since, CURRENT_MILESTONE)]


def test_corpus_size() -> None:
    assert len(load_fixtures("provenance")) >= 60
    assert len(load_fixtures("policy")) >= 70
    assert len(load_fixtures("schema")) >= 40
    assert len(load_fixtures("decoders")) + len(load_fixtures("sinks")) >= 40
    assert len(load_fixtures("pipeline")) >= 40
    total = sum(len(load_fixtures(k)) for k in KINDS)
    assert total >= 200, total


def _gateway_origins(fx: Fixture) -> dict:
    """Origins of the call args computed on the Gateway-built session (events applied via the public API)."""
    assert fx.call is not None
    gw, sid = build_gateway_session(fx, _REGISTRY)
    spec = resolve_spec(_REGISTRY, fx.call.tool, fx.call.server)
    view = gw.session_state(sid).view()
    return {name: resolve_origin(view.ledger, arg=name, spec=spec.args[name], value=value, task_spec=view.task_spec,
                                 approvals=view.approvals, side_effect=spec.side_effect, constants=view.constants())
            for name, value in fx.call.args.items() if name in spec.args}


@pytest.mark.parametrize("fx", _active("provenance"), ids=lambda f: f.id)
def test_provenance_fixture_via_gateway(fx: Fixture) -> None:
    """M6: the same provenance expectations hold when events go through Gateway.label_output & co."""
    assert fx.expect.origins is not None
    origins = _gateway_origins(fx)
    got = {arg: origins[arg].origin_class for arg in fx.expect.origins}
    assert got == fx.expect.origins, fx.description


@pytest.mark.parametrize("fx", _active("pipeline"), ids=lambda f: f.id)
def test_pipeline_fixture(fx: Fixture) -> None:
    assert fx.call is not None and fx.expect.verdict is not None
    gw, sid = build_gateway_session(fx, _REGISTRY)
    d = gw.evaluate(sid, fx.call)
    all_ids = {f.rule_id for f in d.findings}
    hard_ids = {f.rule_id for f in d.findings if f.verdict != Verdict.ALLOW}
    detail = f"{fx.description}: {d.verdict} {[(f.rule_id, f.verdict.value) for f in d.findings]}"
    assert d.verdict == fx.expect.verdict, detail
    assert set(fx.expect.rule_ids_include) <= all_ids, detail
    assert not set(fx.expect.rule_ids_exclude) & hard_ids, detail
    if fx.expect.origins:
        got = {a: d.arg_origins[a].origin_class for a in fx.expect.origins}
        assert got == fx.expect.origins, detail


@pytest.mark.parametrize("fx", _active("schema"), ids=lambda f: f.id)
def test_schema_fixture_via_gateway(fx: Fixture) -> None:
    """M6: schema findings surface through the full pipeline; a schema failure is always a BLOCK."""
    assert fx.call is not None
    gw, sid = build_gateway_session(fx, _REGISTRY)
    d = gw.evaluate(sid, fx.call)
    ids = {f.rule_id for f in d.findings}
    assert set(fx.expect.rule_ids_include) <= ids, (fx.description, sorted(ids))
    if fx.expect.schema_ok is False:
        assert d.verdict == Verdict.BLOCK, (fx.description, sorted(ids))


@pytest.mark.parametrize("fx", _active("decoders"), ids=lambda f: f.id)
def test_decoder_fixture(fx: Fixture) -> None:
    exp = fx.expect
    if exp.sanitized is not None:
        assert fx.text is not None
        session = build_session(fx, _REGISTRY)
        out = sanitize_final_answer(fx.text, session=session.view(), policy=fixture_policy(fx, _REGISTRY))
        assert out.text == exp.sanitized, fx.description
        ids = {f.rule_id for f in out.findings}
        assert set(exp.rule_ids_include) <= ids and not set(exp.rule_ids_exclude) & ids, (fx.description, ids)
        return
    if fx.text is None:  # split payload across the last two tool-output entries
        session = build_session(fx, _REGISTRY)
        entries = [e for e in session.ledger.entries() if e.kind.value == "tool_output"]
        joined = split_payload_join(entries[-2], entries[-1])
        assert joined is not None, fx.description
        text = joined
    else:
        text = fx.text
    kinds = {s.kind for s in trigger_signals(text)}
    for d in decode_candidates(text):
        kinds |= {f"decoded:{d.scheme}"} | {s.kind for s in trigger_signals(d.text)}
    if exp.signals is not None:
        assert set(exp.signals) <= kinds, (fx.description, kinds)
    for k in exp.rule_ids_exclude:  # used as "signals that must NOT appear"
        assert k not in kinds, (fx.description, kinds)
    if exp.decoded is not None:
        texts = " | ".join(d.text for d in decode_candidates(text))
        for piece in exp.decoded:
            assert piece in texts, (fx.description, texts)


@pytest.mark.parametrize("fx", _active("sinks"), ids=lambda f: f.id)
def test_sink_fixture(fx: Fixture) -> None:
    assert fx.call is not None
    spec = resolve_spec(_REGISTRY, fx.call.tool, fx.call.server)
    session = build_session(fx, _REGISTRY)
    origins = compute_origins(fx, session, spec)
    view = session.view()
    pol = fixture_policy(fx, _REGISTRY)
    dests = classify_destinations(spec, fx.call.args, origins, view, pol)
    facts = compute_facts(spec, fx.call.args, view, pol)
    findings = sink_findings(spec, fx.call.args, origins, dests, facts, view, pol)
    findings += exec_findings(spec, fx.call.args, origins, pol)
    r2 = rule_of_two_finding(spec, view.flags, origins, dests)
    ids = {f.rule_id for f in findings} | ({r2.rule_id} if r2 else set())
    exp = fx.expect
    if exp.sink_rule_ids is not None:
        assert ids == set(exp.sink_rule_ids), (fx.description, sorted(ids))
    assert set(exp.rule_ids_include) <= ids and not set(exp.rule_ids_exclude) & ids, (fx.description, ids)
    if exp.destinations is not None:
        by_value = {d.value: d for d in dests}
        for value, fields in exp.destinations.items():
            assert value in by_value, (fx.description, list(by_value))
            for k, v in fields.items():
                assert str(getattr(by_value[value], k)) == str(v), (fx.description, value, k)
    if exp.facts is not None:
        for k, v in exp.facts.items():
            got = getattr(facts, k)
            got = got.name.lower() if hasattr(got, "name") else got
            assert got == v, (fx.description, k, got)


@pytest.mark.parametrize("fx", _active("schema"), ids=lambda f: f.id)
def test_schema_fixture(fx: Fixture) -> None:
    assert fx.call is not None
    spec = resolve_spec(_REGISTRY, fx.call.tool, fx.call.server)
    result = _VALIDATOR.validate_args(spec, fx.call.args)
    ids = {f.rule_id for f in result.findings}
    exp = fx.expect
    if exp.schema_ok is not None:
        assert result.ok is exp.schema_ok, f"{fx.description}: {sorted(ids)}"
    assert set(exp.rule_ids_include) <= ids, f"{fx.description}: got {sorted(ids)}"
    assert not set(exp.rule_ids_exclude) & ids, f"{fx.description}: got {sorted(ids)}"
    if exp.normalized_args is not None:
        for k, v in exp.normalized_args.items():
            assert result.normalized_args[k] == v, fx.description


@pytest.mark.parametrize("fx", _active("policy"), ids=lambda f: f.id)
def test_policy_fixture(fx: Fixture) -> None:
    ctx = build_policy_context(fx, _REGISTRY)
    outcome = evaluate_policy(ctx)
    ids = {f.rule_id for f in outcome.findings}
    exp = fx.expect
    if exp.policy_verdict is not None:
        got = max_verdict(*(f.verdict for f in outcome.findings))
        assert got == exp.policy_verdict, f"{fx.description}: findings={[(f.rule_id, f.verdict) for f in outcome.findings]}"
    missing = set(exp.rule_ids_include) - ids
    assert not missing, f"{fx.description}: missing {missing}; got {sorted(ids)}"
    unexpected = set(exp.rule_ids_exclude) & ids
    assert not unexpected, f"{fx.description}: unexpected {unexpected}"
    assert set(exp.relaxed) <= outcome.relaxed, fx.description
    if fx.expect.origins:
        got_o = {a: ctx.origins[a].origin_class for a in fx.expect.origins}
        assert got_o == fx.expect.origins, fx.description


@pytest.mark.parametrize("fx", [f for f in _active("provenance") if f.since != "M6"], ids=lambda f: f.id)
def test_provenance_fixture(fx: Fixture) -> None:
    assert fx.call is not None and fx.expect.origins is not None
    spec = resolve_spec(_REGISTRY, fx.call.tool, fx.call.server)
    session = build_session(fx, _REGISTRY)
    origins = compute_origins(fx, session, spec)
    got = {arg: origins[arg].origin_class for arg in fx.expect.origins}
    assert got == fx.expect.origins, fx.description
