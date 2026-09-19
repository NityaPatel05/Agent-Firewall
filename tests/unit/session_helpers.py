"""Build sessions with labeled tool outputs for unit tests (no Gateway)."""

from __future__ import annotations

from typing import Any

from firewall.core.labels import Confidentiality, Label, SourceKind
from firewall.core.models import ToolCall
from firewall.core.provenance import compute_output_labels
from firewall.core.registry import ToolRegistry
from firewall.core.session import SessionState
from firewall.core.task_spec import RuleBasedTaskSpecExtractor

REG = ToolRegistry.from_yaml()


def make_session(user: str | None = None, *outputs: tuple[str, dict[str, Any], Any]) -> SessionState:
    s = SessionState("t", own_emails=["emma.johnson@bluesparrowtech.com", "emma.j.personal@gmail.com"],
                     own_ibans=["DE89370400440532013000"])
    if user is not None:
        s.ledger.append(kind=SourceKind.USER, text=user, label=Label.user())
        s.task_spec = RuleBasedTaskSpecExtractor().extract(user)
    for i, (tool, args, output) in enumerate(outputs):
        add_output(s, tool, args, output, call_id=f"c{i + 1}")
    return s


def add_output(s: SessionState, tool: str, args: dict[str, Any], output: Any, call_id: str = "cx") -> None:
    spec = REG.resolve(tool).spec
    assert spec is not None
    call = ToolCall(call_id=call_id, tool=spec.qualified_name, args=args)
    frags = compute_output_labels(spec, call, output, user_handle=s.user_handle)
    for e in s.ledger.extend_fragments(frags, kind=SourceKind.TOOL_OUTPUT, call_id=call_id, tool=spec.qualified_name):
        if not e.label.trusted:
            s.flags.ingested_untrusted = True
        if e.label.confidentiality >= Confidentiality.PRIVATE:
            s.flags.read_private = True
