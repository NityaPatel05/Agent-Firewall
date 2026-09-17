"""Rule-of-Two fallback: untrusted input [A] x private data [B] x consequential action [C]."""

from __future__ import annotations

from collections.abc import Mapping

from firewall.core.models import (
    TRUSTED_ORIGINS,
    ArgOrigin,
    ArgRole,
    DestinationInfo,
    Finding,
    OriginClass,
    Stage,
    Verdict,
)
from firewall.core.registry import ToolSpec
from firewall.core.session import SessionFlags

_OK = TRUSTED_ORIGINS | {OriginClass.USER_NAMED_SOURCE}


def rule_of_two_finding(spec: ToolSpec, flags: SessionFlags, origins: Mapping[str, ArgOrigin],
                        destinations: tuple[DestinationInfo, ...]) -> Finding | None:
    """SYS-R2-001 (REVIEW) when A and B hold, the call is consequential, and lineage is not trusted.

    Annotated tools whose destinations (and authority args) are all trusted never trigger it.
    """
    if not (flags.ingested_untrusted and flags.read_private and spec.consequential):
        return None
    weak_dest = any(d.origin_class not in _OK for d in destinations)
    weak_auth = any(o.role == ArgRole.AUTHORITY and o.origin_class not in _OK and o.value_canonical not in (None, [])
                    and spec.args.get(o.arg) is not None and spec.args[o.arg].origin_required
                    for o in origins.values())
    if spec.annotated and not (weak_dest or weak_auth):
        return None
    return Finding.model_construct(
        rule_id="SYS-R2-001", stage=Stage.RULE_OF_TWO, verdict=Verdict.REVIEW,
        reason="session ingested untrusted content and read private data; consequential call lacks trusted "
               "provenance", arg=None, evidence={"unannotated": not spec.annotated})
