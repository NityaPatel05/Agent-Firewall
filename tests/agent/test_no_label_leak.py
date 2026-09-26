"""Labels live only in ToolMessage.artifact; nothing label-shaped is ever sent to the model."""

from __future__ import annotations

from agent_helpers import call, final, run


def test_no_label_json_reaches_the_model() -> None:
    steps = [
        call("list_emails", unread_only=True),
        call("read_email", email_id="e4"),
        call("read_file", path="/finance/invoice_0425.pdf"),
        call("read_channel", channel="#general"),
        call("get_webpage", url="https://shop.example/p1"),
        call("search_contacts", query="Carl"),
        final(),
    ]
    _, _, _, decisions, _, model = run("Summarize my unread emails, the invoice and #general", steps)
    assert len(decisions) == 6 and len(model.recorded_inputs) == 7
    for messages in model.recorded_inputs:
        for m in messages:
            text = str(m.content)
            for marker in ("integrity", "fw_label", "entry_ids", "confidentiality"):
                assert marker not in text, (marker, text[:200])
