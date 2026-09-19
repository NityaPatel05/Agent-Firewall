from __future__ import annotations

from pathlib import Path

import yaml
from policy_helpers import REG, ctx, dest

from firewall.core.models import ArgType, OriginClass, Stage, Verdict, max_verdict
from firewall.core.policy.conditions import ArgFacts
from firewall.core.policy.engine import evaluate_policy
from firewall.core.policy.loader import load_policy
from firewall.core.task_spec import RuleBasedTaskSpecExtractor

O = OriginClass
X = RuleBasedTaskSpecExtractor()


def _verdict(outcome) -> Verdict:  # type: ignore[no-untyped-def]
    return max_verdict(*(f.verdict for f in outcome.findings))


def test_default_finding_when_nothing_matches() -> None:
    out = evaluate_policy(ctx("read_email", {"email_id": "e1"}))
    (f,) = out.findings
    assert f.rule_id == "DEFAULT-READ" and f.verdict == Verdict.ALLOW and f.stage == Stage.POLICY
    assert out.matched_rule_ids == ()


def test_default_by_side_effect() -> None:
    cp = load_policy("default", registry=REG)
    out = evaluate_policy(ctx("install_mcp_server", {"name": "x", "source": "https://x.example"}, pol=cp))
    assert [f.rule_id for f in out.findings] == ["DEFAULT-INSTALL"]
    assert out.findings[0].verdict == Verdict.REVIEW
    out2 = evaluate_policy(ctx("send_email", {"to": ["a@b.com"]}, pol=cp))
    assert out2.findings[0].rule_id == "DEFAULT-EXTERNAL-COMM" and out2.findings[0].verdict == Verdict.ALLOW


def test_config_side_effect_blocked() -> None:
    out = evaluate_policy(ctx("update_agent_config", {"key": "k", "value": "v"}))
    assert "POL-POLICY-001" in out.matched_rule_ids and _verdict(out) == Verdict.BLOCK


def test_multiple_matching_rules_combine() -> None:
    c = ctx("send_money", {"amount": 50000}, origins={"amount": O.UNKNOWN},
            task_spec=X.extract("Check my balance"))
    out = evaluate_policy(c)
    assert {"BANK-AMT-001", "POL-RO-001", "POL-SCOPE-001"} <= set(out.matched_rule_ids)
    assert _verdict(out) == Verdict.BLOCK
    assert not any(f.rule_id.startswith("DEFAULT-") for f in out.findings)


def test_strict_upgrades_ro_and_scope(tmp_path: Path) -> None:
    (tmp_path / "strict.yaml").write_text(yaml.safe_dump(
        {"version": 1, "policy_id": "strict", "extends": "default", "strictness": "strict"}), encoding="utf-8")
    cp = load_policy(tmp_path / "strict.yaml", registry=REG)
    c = ctx("send_email", {"to": ["a@b.com"]}, task_spec=X.extract("Summarize my unread emails"), pol=cp)
    out = evaluate_policy(c)
    by_id = {f.rule_id: f.verdict for f in out.findings}
    assert by_id["POL-RO-001"] == Verdict.BLOCK and by_id["POL-SCOPE-001"] == Verdict.BLOCK
    std = evaluate_policy(ctx("send_email", {"to": ["a@b.com"]}, task_spec=X.extract("Summarize my unread emails")))
    assert {f.rule_id: f.verdict for f in std.findings}["POL-RO-001"] == Verdict.REVIEW


def test_relaxations_collected() -> None:
    c = ctx("upload_file", {"path": "/repo.zip", "url": "https://s3.bluesparrowtech.com/backups/repo.zip"},
            destinations=[dest("https://s3.bluesparrowtech.com/backups/repo.zip", O.UNKNOWN, internal=True,
                               allowlisted=True, kind=ArgType.URL, arg="url")],
            task_spec=X.extract("Zip the project and upload to our S3 bucket"))
    out = evaluate_policy(c)
    assert "FILES-UPLOAD-ALLOW-001" in out.matched_rule_ids
    assert out.relaxed == frozenset({"SYS-PROV-UNKNOWN"})
    allow = next(f for f in out.findings if f.rule_id == "FILES-UPLOAD-ALLOW-001")
    assert allow.verdict == Verdict.ALLOW and allow.evidence["relax"] == ["SYS-PROV-UNKNOWN"]
    assert _verdict(out) == Verdict.ALLOW


def test_allow_rule_suppresses_default() -> None:
    c = ctx("run_command", {"argv": ["pytest", "-q"]}, task_spec=X.extract("Run the test suite"))
    out = evaluate_policy(c)
    assert out.matched_rule_ids == ("EXEC-TEST-001",) and _verdict(out) == Verdict.ALLOW
    other = evaluate_policy(ctx("run_command", {"argv": ["ls"]}, task_spec=X.extract("Run the test suite")))
    assert [f.rule_id for f in other.findings] == ["DEFAULT-EXEC"] and _verdict(other) == Verdict.REVIEW


def test_message_and_fallback_in_finding() -> None:
    out = evaluate_policy(ctx("update_password", {"password": "x"}, origins={"password": O.UNTRUSTED_ONLY}))
    f = next(f for f in out.findings if f.rule_id == "BANK-PWD-001")
    assert f.reason.startswith("Password changes") and f.evidence["fallback"] == "feedback_to_agent"


def test_secret_to_internal_user_typed_allowed_but_external_blocked() -> None:
    facts = ArgFacts(secret_in_args=True)
    ok = ctx("send_dm", {"user": "@oncall", "text": "ghp_x"}, facts=facts,
             destinations=[dest("@oncall", O.USER_TYPED, internal=True, kind=ArgType.HANDLE, arg="user")])
    assert "POL-SEC-001" not in evaluate_policy(ok).matched_rule_ids
    bad = ctx("send_dm", {"user": "@attacker", "text": "ghp_x"}, facts=facts,
              destinations=[dest("@attacker", O.UNTRUSTED_ONLY, kind=ArgType.HANDLE, arg="user")])
    assert "POL-SEC-001" in evaluate_policy(bad).matched_rule_ids
