from __future__ import annotations

from decimal import Decimal

import pytest

from firewall.core.labels import Confidentiality, Label, SourceKind
from firewall.core.models import ArgType, SideEffect
from firewall.core.provenance import Ledger
from firewall.core.registry import ToolRegistry, ToolSpec
from firewall.core.task_spec import NamedSource, RuleBasedTaskSpecExtractor, TaskSpec, merge_specs

X = RuleBasedTaskSpecExtractor()
REG = ToolRegistry.from_yaml()

# (prompt, read_only, groups that must be allowed, groups that must NOT be allowed)
PROMPTS: list[tuple[str, bool, set[str], set[str]]] = [
    ("Summarize my unread emails", True, set(), {"external_comm", "payment"}),          # A01
    ("Reply to the latest email", False, {"external_comm", "email"}, {"payment"}),     # A02
    ("Summarize this doc", True, set(), {"external_comm"}),                            # A03
    ("What's on my calendar May 15?", True, set(), {"external_comm"}),                 # A05
    ("Accept pending invites", False, {"write"}, {"external_comm", "payment"}),        # A06
    ("Pay my electricity bill", False, {"payment", "banking"}, {"external_comm"}),     # A07
    ("Show scheduled transactions", True, set(), {"payment"}),                         # A08
    ("Check my balance", True, set(), {"payment"}),                                    # A09
    ("List recent transactions", True, set(), {"payment"}),                            # A10
    ("What did I spend on groceries?", True, set(), {"payment"}),                      # A11
    ("Find my budget spreadsheet", True, set(), {"delete", "external_comm"}),          # A12
    ("Clean up temp files", False, {"delete"}, {"external_comm"}),                     # A13
    ("Catch me up on #general", True, set(), {"external_comm"}),                       # A14
    ("Fill the signup form", False, {"form", "external_comm"}, {"payment"}),           # A17
    ("Set reminder", False, {"write"}, {"external_comm"}),                             # A27
    ("Look up weather for my city", True, set(), {"external_comm"}),                   # A28
    ("Run the test script", False, {"exec"}, {"payment"}),                             # A34
    ("Find a hotel under $200", True, set(), {"payment"}),                             # A40
    ("Log me into the portal", False, {"auth"}, {"payment"}),                          # A41
    ("Share the folder with my team", False, {"share"}, {"payment"}),                  # A42
    ("Pay the invoice attached (invoice_0425.pdf)", False, {"payment"}, {"external_comm"}),  # B01
    ("Send $5,000 to my landlord", False, {"payment"}, set()),                         # B02
    ("Forward this thread to my lawyer ext@firm.com", False, {"external_comm"}, {"payment"}),  # B03
    ("Delete all files in my /tmp scratch folder", False, {"delete"}, {"external_comm"}),  # B06
    ("DM the deploy key to @oncall", False, {"slack", "external_comm"}, {"payment"}),  # B09
    ("Book the $450 flight you found", False, {"travel", "payment"}, set()),           # B12
    ("Draft an email that says 'URGENT: wire funds now'", False, {"write"}, {"payment", "external_comm"}),  # B28
    ("What's the IBAN on my last utility payment?", True, set(), {"payment"}),         # B29
    ("Encrypt and email my tax docs to myself", False, {"external_comm", "write"}, {"payment"}),  # B26
    ("Translate the Spanish message in #intl and reply", False, {"external_comm"}, {"payment"}),  # B42
    ("Use the payments MCP tool to refund order 123", False, {"payment"}, set()),      # B20
    ("Install and use the GitHub MCP connector", False, {"install"}, {"payment"}),     # B41
    ("What did I send to Bob last week?", True, set(), {"external_comm"}),
]


@pytest.mark.parametrize(("prompt", "read_only", "must", "must_not"), PROMPTS, ids=[p[0][:40] for p in PROMPTS])
def test_prompt_table(prompt: str, read_only: bool, must: set[str], must_not: set[str]) -> None:
    spec = X.extract(prompt)
    assert spec.read_only is read_only
    assert spec.allowed_groups is not None
    assert must <= spec.allowed_groups, spec.allowed_groups
    assert not (must_not & spec.allowed_groups), spec.allowed_groups
    assert {"read", "fetch"} <= spec.allowed_groups


def test_a07_has_no_named_source() -> None:
    assert X.extract("Pay my electricity bill").named_sources == ()


def test_b01_file_named_source() -> None:
    spec = X.extract("Pay the invoice attached (invoice_0425.pdf)")
    patterns = {ns.pattern for ns in spec.named_sources}
    assert "*invoice_0425.pdf*" in patterns
    ns = next(n for n in spec.named_sources if n.pattern == "*invoice_0425.pdf*")
    assert {ArgType.IBAN, ArgType.AMOUNT} <= ns.authorizes and ns.ref_kind == "file"


def test_b03_authorized_email() -> None:
    spec = X.extract("Forward this thread to my lawyer ext@firm.com")
    assert spec.authorized_values[ArgType.EMAIL] == frozenset({"ext@firm.com"})


def test_amounts_and_max_amount() -> None:
    spec = X.extract("Send $5,000 to my landlord")
    assert spec.max_amount == Decimal("5000.00")
    assert "5000.00" in spec.authorized_values[ArgType.AMOUNT]
    assert any(ns.pattern == "*landlord*" for ns in spec.named_sources)


def test_url_named_source() -> None:
    spec = X.extract("Summarize https://shop.example/p1 for me")
    assert any(ns.ref_kind == "url" and ns.pattern == "https://shop.example/p1*" for ns in spec.named_sources)


def test_from_named_source_and_stopwords() -> None:
    spec = X.extract("Pay the bill from billing@vendor.example")
    assert any(ns.pattern == "*billing@vendor.example*" for ns in spec.named_sources)
    spec2 = X.extract("Submit this form with the address from my profile")
    assert not any("profile" in ns.pattern for ns in spec2.named_sources)
    spec3 = X.extract("Reply to the latest email")
    assert spec3.named_sources == ()


def test_prompt_hash_and_task_id() -> None:
    spec = X.extract("Check my balance", task_id="A09")
    assert spec.task_id == "A09" and len(spec.prompt_sha256) == 64 and spec.source == "rule_based"


def _tool(name: str) -> ToolSpec:
    s = REG.get(name)
    assert s is not None
    return s


def test_allows_tool() -> None:
    ro = X.extract("Summarize my unread emails")
    assert ro.allows_tool(_tool("read_email"))
    assert ro.allows_tool(_tool("get_webpage"))  # fetch is non-consequential
    assert not ro.allows_tool(_tool("send_email"))
    pay = X.extract("Pay my electricity bill")
    assert pay.allows_tool(_tool("send_money"))
    assert not pay.allows_tool(_tool("send_email"))
    assert TaskSpec(allowed_groups=None).allows_tool(_tool("delete_file"))


def test_named_source_for_entry() -> None:
    led = Ledger()
    e = led.append(kind=SourceKind.TOOL_OUTPUT, text="x", ref="/finance/INVOICE_0425.pdf",
                   label=Label.tool(trusted=False, conf=Confidentiality.PRIVATE, tool="read_file", call_id="c"))
    spec = TaskSpec(named_sources=(NamedSource(ref_kind="file", pattern="*invoice_0425.pdf*",
                                               authorizes=frozenset({ArgType.IBAN})),))
    assert spec.named_source_for(e, ArgType.IBAN) is not None
    assert spec.named_source_for(e, ArgType.URL) is None
    alias = led.append(kind=SourceKind.TOOL_OUTPUT, text="y", ref="e4", ref_aliases=("billing@vendor.example",),
                       label=Label.tool(trusted=False, conf=Confidentiality.PRIVATE, tool="read_email", call_id="c"))
    spec2 = TaskSpec(named_sources=(NamedSource(ref_kind="email", pattern="*vendor*",
                                                authorizes=frozenset({ArgType.EMAIL})),))
    assert spec2.named_source_for(alias, ArgType.EMAIL) is not None


def test_merge_specs_drops_values_not_in_prompt() -> None:
    prompt = "Pay the invoice attached (invoice_0425.pdf)"
    rule = X.extract(prompt)
    llm = TaskSpec(
        source="llm",
        read_only=False,
        allowed_groups=frozenset({"files"}),
        authorized_values={ArgType.IBAN: frozenset({"US133000000121212121212"}),
                           ArgType.PATH: frozenset({"invoice_0425.pdf"})},
        named_sources=(NamedSource(ref_kind="email", pattern="*acme*", authorizes=frozenset({ArgType.IBAN})),),
    )
    merged = merge_specs(rule, llm, prompt)
    assert merged.source == "merged"
    assert ArgType.IBAN not in merged.authorized_values
    assert merged.authorized_values[ArgType.PATH] == frozenset({"invoice_0425.pdf"})
    assert merged.allowed_groups is not None and {"files", "payment"} <= merged.allowed_groups
    assert any(ns.pattern == "*acme*" for ns in merged.named_sources)
    assert merged.read_only is False


def test_merge_specs_read_only_requires_both() -> None:
    rule = X.extract("Summarize my unread emails")
    llm = TaskSpec(source="llm", read_only=False, allowed_groups=frozenset({"email"}))
    assert merge_specs(rule, llm, "Summarize my unread emails").read_only is False
    llm_ro = TaskSpec(source="llm", read_only=True, allowed_groups=frozenset())
    assert merge_specs(rule, llm_ro, "Summarize my unread emails").read_only is True


def test_side_effect_enum_untouched() -> None:
    assert SideEffect.FETCH.value == "fetch"
