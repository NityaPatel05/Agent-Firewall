"""Public core API (framework-agnostic; depends only on pydantic, pyyaml, fastjsonschema and the stdlib).

Import from the submodules, e.g. `from firewall.core.gateway import Gateway`,
`from firewall.core.pipeline import evaluate, EvalInputs, GatewayOptions`,
`from firewall.core.approvals import OracleApprover`.
"""

from __future__ import annotations
