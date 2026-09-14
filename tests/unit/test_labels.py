from __future__ import annotations

import itertools

import pytest
from pydantic import ValidationError

from firewall.core.labels import (
    Confidentiality,
    Integrity,
    Label,
    SourceKind,
    SourceRef,
    join_all,
)


def _lab(i: Integrity, c: Confidentiality, src: str, readers: object = "*") -> Label:
    return Label(
        integrity=i,
        confidentiality=c,
        sources=frozenset({SourceRef(kind=SourceKind.TOOL_OUTPUT, tool=src)}),
        readers=readers,  # type: ignore[arg-type]
    )


LABELS = [
    _lab(Integrity.TRUSTED, Confidentiality.PUBLIC, "a"),
    _lab(Integrity.UNTRUSTED, Confidentiality.PRIVATE, "b", frozenset({"x", "y"})),
    _lab(Integrity.TRUSTED, Confidentiality.SECRET, "c", frozenset({"y"})),
    Label.user(),
    Label.system(),
]


@pytest.mark.parametrize(("a", "b"), list(itertools.product(LABELS, LABELS)))
def test_join_commutative(a: Label, b: Label) -> None:
    assert a.join(b) == b.join(a)


@pytest.mark.parametrize(("a", "b", "c"), list(itertools.product(LABELS[:3], LABELS[1:4], LABELS[2:])))
def test_join_associative(a: Label, b: Label, c: Label) -> None:
    assert a.join(b).join(c) == a.join(b.join(c))


@pytest.mark.parametrize("a", LABELS)
def test_join_idempotent(a: Label) -> None:
    assert a.join(a) == a


def test_untrusted_absorbs_and_conf_max() -> None:
    j = LABELS[0].join(LABELS[1])
    assert j.integrity == Integrity.UNTRUSTED
    assert j.confidentiality == Confidentiality.PRIVATE
    assert not j.trusted
    j2 = LABELS[0].join(LABELS[2])
    assert j2.trusted
    assert j2.confidentiality == Confidentiality.SECRET


def test_readers_intersection_and_star_identity() -> None:
    assert LABELS[1].join(LABELS[2]).readers == frozenset({"y"})
    assert LABELS[0].join(LABELS[1]).readers == frozenset({"x", "y"})
    assert LABELS[0].join(LABELS[0]).readers == "*"


def test_sources_union() -> None:
    j = LABELS[0].join(LABELS[1])
    assert {s.tool for s in j.sources} == {"a", "b"}


def test_join_all_empty_and_many() -> None:
    empty = join_all([])
    assert empty.integrity == Integrity.TRUSTED
    assert empty.confidentiality == Confidentiality.PUBLIC
    assert empty.sources == frozenset()
    many = join_all(LABELS)
    assert many.integrity == Integrity.UNTRUSTED
    assert many.confidentiality == Confidentiality.SECRET


def test_constructors() -> None:
    assert Label.user().trusted and Label.user().confidentiality == Confidentiality.PRIVATE
    assert Label.system().confidentiality == Confidentiality.PUBLIC
    t = Label.tool(trusted=False, conf=Confidentiality.PRIVATE, tool="read_email", call_id="c1", ref="e1")
    (src,) = t.sources
    assert src.kind == SourceKind.TOOL_OUTPUT and src.ref == "e1" and not t.trusted


def test_frozen() -> None:
    lab = Label.user()
    with pytest.raises(ValidationError):
        lab.integrity = Integrity.UNTRUSTED  # type: ignore[misc]
    with pytest.raises(ValidationError):
        SourceRef(kind=SourceKind.USER).tool = "x"  # type: ignore[misc]


def test_hashable() -> None:
    assert len({Label.user(), Label.user(), Label.system()}) == 2
