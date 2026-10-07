"""Developer helper: dump the Gateway session built for one offline fixture.

Usage: python scripts/debug_fixture.py <kind> <fixture-id>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests" / "offline"))

from harness import build_gateway_session, load_fixtures


def main() -> None:
    kind, fid = sys.argv[1], sys.argv[2]
    fx = next(f for f in load_fixtures(kind) if f.id == fid)
    gw, sid = build_gateway_session(fx)
    st = gw.session_state(sid)
    print("resource_labels:", {k: v.integrity.name for k, v in st.resource_labels.items()})
    for e in st.ledger.entries():
        print(e.entry_id, e.kind.value, e.label.integrity.name, e.tool, e.ref, repr(e.text[:70]))
    print("task_spec:", st.task_spec.model_dump(mode="json") if st.task_spec else None)
    if fx.call is not None:
        d = gw.evaluate(sid, fx.call)
        print("decision:", d.verdict, [(f.rule_id, f.verdict.value, f.arg) for f in d.findings])
        print("origins:", {k: o.origin_class.value for k, o in d.arg_origins.items()})


if __name__ == "__main__":
    main()
