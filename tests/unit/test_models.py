from __future__ import annotations

from firewall.core.models import (
    ORIGIN_RANK,
    TRUSTED_ORIGINS,
    Decision,
    Finding,
    OriginClass,
    Stage,
    Verdict,
    max_verdict,
)


def test_max_verdict_ordering() -> None:
    assert max_verdict() == Verdict.ALLOW
    assert max_verdict(Verdict.ALLOW, Verdict.REVIEW) == Verdict.REVIEW
    assert max_verdict(Verdict.REVIEW, Verdict.BLOCK, Verdict.ALLOW) == Verdict.BLOCK
    assert max_verdict(Verdict.ALLOW, Verdict.ALLOW) == Verdict.ALLOW


def _f(rule: str, v: Verdict, **ev: object) -> Finding:
    return Finding(rule_id=rule, stage=Stage.POLICY, verdict=v, reason="r", evidence=dict(ev))


def test_decision_rule_ids_unique_ordered() -> None:
    d = Decision(
        call_id="c",
        tool="t",
        verdict=Verdict.BLOCK,
        findings=(
            _f("POL-B", Verdict.REVIEW),
            _f("DEFAULT-READ", Verdict.ALLOW),
            _f("POL-A", Verdict.BLOCK),
            _f("POL-B", Verdict.BLOCK),
            _f("SYS-PROV-NAMED", Verdict.ALLOW, relaxed_by="FILES-NAMED-001"),
        ),
    )
    assert d.rule_ids == ("POL-B", "POL-A", "FILES-NAMED-001")


def test_origin_rank_total_order() -> None:
    ranks = list(ORIGIN_RANK.values())
    assert len(set(ranks)) == len(OriginClass) == len(ranks)
    assert ORIGIN_RANK[OriginClass.USER_TYPED] == max(ranks)
    assert ORIGIN_RANK[OriginClass.UNKNOWN] == min(ranks)
    ordered = sorted(OriginClass, key=ORIGIN_RANK.__getitem__, reverse=True)
    assert ordered == [
        OriginClass.USER_TYPED,
        OriginClass.APPROVED,
        OriginClass.OWN_RECORD,
        OriginClass.POLICY_CONST,
        OriginClass.USER_NAMED_SOURCE,
        OriginClass.UNTRUSTED_ONLY,
        OriginClass.UNKNOWN,
    ]


def test_trusted_origins() -> None:
    assert OriginClass.USER_NAMED_SOURCE not in TRUSTED_ORIGINS
    assert OriginClass.OWN_RECORD in TRUSTED_ORIGINS
