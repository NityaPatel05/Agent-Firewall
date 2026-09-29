"""RemoteGateway: GatewayProtocol over HTTP (drop-in replacement for the in-process Gateway)."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any, TypeVar

import httpx
from pydantic import BaseModel, TypeAdapter

from firewall.core.models import (
    ApprovalResult,
    Decision,
    Finding,
    LabeledOutput,
    SanitizedText,
    ToolCall,
)
from firewall.core.provenance import LedgerEntry
from firewall.core.registry import ToolSpec
from firewall.core.task_spec import TaskSpec
from firewall.service.schemas import CreateSessionResponse

M = TypeVar("M", bound=BaseModel)
_FINDINGS = TypeAdapter(list[Finding])


class GatewayHTTPError(RuntimeError):
    def __init__(self, status: int, detail: Any) -> None:
        super().__init__(f"HTTP {status}: {detail}")
        self.status = status
        self.detail = detail


class RemoteUnknownSessionError(GatewayHTTPError, KeyError):
    """404 from the service (mirrors the in-process KeyError)."""


class RemoteConflictError(GatewayHTTPError, ValueError):
    """409 from the service, e.g. the session already exists (mirrors the in-process ValueError)."""


class RemoteGateway:
    """Every GatewayProtocol method maps 1:1 to a service route and parses into the same pydantic models."""

    def __init__(self, base_url: str = "http://127.0.0.1:8787", *, timeout: float = 5.0,
                 client: httpx.Client | None = None) -> None:
        self._client = client or httpx.Client(base_url=base_url, timeout=timeout)
        self.last_session: CreateSessionResponse | None = None

    def close(self) -> None:
        self._client.close()

    # ------------------------------------------------------------------ transport
    def _request(self, method: str, path: str, body: Any = None) -> httpx.Response:
        if isinstance(body, BaseModel):
            resp = self._client.request(method, path, content=body.model_dump_json(by_alias=True),
                                        headers={"content-type": "application/json"})
        elif body is not None:
            resp = self._client.request(method, path, json=body)
        else:
            resp = self._client.request(method, path)
        if resp.status_code >= 400:
            try:
                detail = resp.json()
            except ValueError:
                detail = resp.text
            if resp.status_code == 404:
                raise RemoteUnknownSessionError(resp.status_code, detail)
            if resp.status_code == 409:
                raise RemoteConflictError(resp.status_code, detail)
            raise GatewayHTTPError(resp.status_code, detail)
        return resp

    def _post(self, path: str, body: Any, model: type[M]) -> M:
        return model.model_validate_json(self._request("POST", path, body).content)

    @staticmethod
    def _dump(m: BaseModel) -> dict[str, Any]:
        return m.model_dump(mode="json", by_alias=True)

    # ------------------------------------------------------------------ GatewayProtocol
    def new_session(self, session_id: str | None = None, *, user_handle: str = "@emma",
                    own_emails: Iterable[str] = (), own_ibans: Iterable[str] = (),
                    task_id: str | None = None) -> str:
        body = {"session_id": session_id, "user_handle": user_handle, "own_emails": list(own_emails),
                "own_ibans": list(own_ibans), "task_id": task_id}
        self.last_session = self._post("/v1/sessions", body, CreateSessionResponse)
        return self.last_session.session_id

    def record_system_message(self, session_id: str, text: str) -> LedgerEntry:
        return self._post(f"/v1/sessions/{session_id}/messages:system", {"text": text}, LedgerEntry)

    def record_user_message(self, session_id: str, text: str, *, message_id: str | None = None) -> LedgerEntry:
        return self._post(f"/v1/sessions/{session_id}/messages:user", {"text": text, "message_id": message_id},
                          LedgerEntry)

    def set_task_spec(self, session_id: str, spec: TaskSpec) -> None:
        self._request("PUT", f"/v1/sessions/{session_id}/task-spec", spec)

    def evaluate(self, session_id: str, call: ToolCall) -> Decision:
        return self._post("/v1/tool-calls:evaluate", {"session_id": session_id, "call": self._dump(call)}, Decision)

    def record_approval(self, session_id: str, decision: Decision, result: ApprovalResult) -> Decision:
        body = {"session_id": session_id, "decision": self._dump(decision), "result": self._dump(result)}
        return self._post("/v1/approvals", body, Decision)

    def commit(self, session_id: str, call: ToolCall, decision: Decision, *, executed: bool) -> None:
        body = {"session_id": session_id, "call": self._dump(call), "decision": self._dump(decision),
                "executed": executed}
        self._request("POST", "/v1/tool-calls:commit", body)

    def label_output(self, session_id: str, call: ToolCall, output: Any) -> LabeledOutput:
        body = {"session_id": session_id, "call": self._dump(call), "output": output}
        return self._post("/v1/tool-outputs:label", body, LabeledOutput)

    def record_summary(self, session_id: str, text: str, covered_entry_ids: Sequence[str]) -> LedgerEntry:
        return self._post(f"/v1/sessions/{session_id}/summaries",
                          {"text": text, "covered_entry_ids": list(covered_entry_ids)}, LedgerEntry)

    def observe_tool_definitions(self, session_id: str, specs: Sequence[ToolSpec]) -> list[Finding]:
        resp = self._request("POST", f"/v1/sessions/{session_id}/tool-definitions",
                             {"specs": [self._dump(s) for s in specs]})
        return _FINDINGS.validate_json(resp.content)

    def sanitize_final_answer(self, session_id: str, text: str) -> SanitizedText:
        return self._post("/v1/final-answers:sanitize", {"session_id": session_id, "text": text}, SanitizedText)

    def provenance(self, session_id: str) -> dict[str, Any]:
        return self._request("GET", f"/v1/sessions/{session_id}/provenance").json()  # type: ignore[no-any-return]

    def close_session(self, session_id: str) -> None:
        self._request("DELETE", f"/v1/sessions/{session_id}")

    # ------------------------------------------------------------------ extras
    def healthz(self) -> dict[str, Any]:
        return self._request("GET", "/healthz").json()  # type: ignore[no-any-return]

    def audit(self, session_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        params = f"?limit={limit}" + (f"&session_id={session_id}" if session_id else "")
        return self._request("GET", f"/v1/audit{params}").json()  # type: ignore[no-any-return]
