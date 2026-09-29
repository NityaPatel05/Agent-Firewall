"""FastAPI service exposing the in-process Gateway over HTTP (same semantics, sessions held server-side)."""

from __future__ import annotations

import re
import tempfile
import time
from collections import deque
from collections.abc import AsyncIterator, Awaitable, Callable, MutableMapping
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import yaml
from fastapi import FastAPI, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from pydantic import BaseModel, ValidationError

from firewall.core.audit import JsonlAuditSink
from firewall.core.gateway import Gateway, UnknownSessionError
from firewall.core.metrics import GatewayMetrics
from firewall.core.models import AuditRecord, ToolCall, Verdict
from firewall.core.pipeline import GatewayOptions
from firewall.core.policy.loader import PolicyError, load_policy
from firewall.core.registry import ToolRegistry
from firewall.core.task_spec import TaskSpec
from firewall.service.schemas import (
    ApprovalRequestBody,
    CommitRequest,
    CreateSessionRequest,
    CreateSessionResponse,
    DryRunRequest,
    DryRunResponse,
    ErrorResponse,
    EvaluateRequest,
    LabelRequest,
    MessageRequest,
    PolicyValidateRequest,
    PolicyValidateResponse,
    SanitizeRequest,
    SummaryRequest,
    ToolDefinitionsRequest,
)
from firewall.service.store import SessionStore
from firewall.settings import get_settings

AUDIT_RING = 10_000
_SESSION_PATH = re.compile(r"^/v1/sessions/[^/]+")


class TeeAuditSink:
    """Writes to a JSONL sink and keeps the last records in memory for `GET /v1/audit`."""

    def __init__(self, inner: JsonlAuditSink | None, maxlen: int = AUDIT_RING) -> None:
        self.inner = inner
        self.ring: deque[AuditRecord] = deque(maxlen=maxlen)

    def write(self, record: AuditRecord) -> None:
        self.ring.append(record)
        if self.inner is not None:
            self.inner.write(record)

    def flush(self) -> None:
        if self.inner is not None:
            self.inner.flush()

    def close(self) -> None:
        if self.inner is not None:
            self.inner.close()


class TimingMiddleware:
    """Pure-ASGI middleware recording per-route latency into the gateway's GatewayMetrics."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: MutableMapping[str, Any], receive: Callable[..., Awaitable[Any]],
                       send: Callable[..., Awaitable[None]]) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        t0 = time.perf_counter()
        try:
            await self.app(scope, receive, send)
        finally:
            gw = getattr(getattr(scope.get("app"), "state", None), "gateway", None)
            if gw is not None:
                route = _SESSION_PATH.sub("/v1/sessions/{sid}", scope.get("path", ""))
                gw.metrics.observe_http(f"{scope.get('method', '')} {route}", (time.perf_counter() - t0) * 1000.0)


def _json(obj: BaseModel | list[Any] | dict[str, Any], status: int = 200) -> Response:
    if isinstance(obj, BaseModel):
        return Response(content=obj.model_dump_json(by_alias=True), media_type="application/json",
                        status_code=status)
    if isinstance(obj, list) and obj and isinstance(obj[0], BaseModel):
        body = "[" + ",".join(o.model_dump_json(by_alias=True) for o in obj) + "]"
        return Response(content=body, media_type="application/json", status_code=status)
    return JSONResponse(obj, status_code=status)


def _error(status: int, error: str, detail: Any = None) -> Response:
    return _json(ErrorResponse(error=error, detail=detail), status)


def _policy_from_yaml(text: str, registry: ToolRegistry) -> Any:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "candidate.yaml"
        path.write_text(text, encoding="utf-8")
        return load_policy(path, registry=registry)


def create_app(*, policy: str = "all", gateway: Gateway | None = None, audit_path: Path | None = None,
               session_ttl_s: float = 3600.0) -> FastAPI:
    """Build the service. The Gateway (and its compiled, frozen policy) is created once in the lifespan."""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if gateway is not None:
            gw = gateway
            if gw.audit is None:
                gw.audit = TeeAuditSink(None)
        else:
            path = audit_path or (get_settings().runs_dir / "service" / "audit.jsonl")
            registry = ToolRegistry.from_yaml()
            gw = Gateway(policy=load_policy(policy, registry=registry), registry=registry,
                         metrics=GatewayMetrics(), audit=TeeAuditSink(JsonlAuditSink(path)))
        app.state.gateway = gw
        app.state.store = SessionStore(gw.close_session, ttl_s=session_ttl_s)
        try:
            yield
        finally:
            if gw.audit is not None:
                gw.audit.close()

    app = FastAPI(title="Agent Firewall", version="0.1.0", lifespan=lifespan)
    app.add_middleware(TimingMiddleware)

    def gw_of(request: Request) -> Gateway:
        return request.app.state.gateway  # type: ignore[no-any-return]

    def touch(request: Request, sid: str) -> None:
        store: SessionStore = request.app.state.store
        store.sweep()
        store.touch(sid)

    @app.exception_handler(UnknownSessionError)
    async def _unknown(_: Request, exc: UnknownSessionError) -> Response:
        return _error(404, "unknown session", str(exc.args[0]) if exc.args else None)

    @app.exception_handler(KeyError)
    async def _missing(_: Request, exc: KeyError) -> Response:
        return _error(404, "not found", str(exc.args[0]) if exc.args else None)

    @app.exception_handler(ValueError)
    async def _conflict(_: Request, exc: ValueError) -> Response:
        return _error(409, "conflict", str(exc))

    # ------------------------------------------------------------------ sessions
    @app.post("/v1/sessions")
    async def create_session(body: CreateSessionRequest, request: Request) -> Response:
        gw = gw_of(request)
        sid = gw.new_session(body.session_id, user_handle=body.user_handle, own_emails=body.own_emails,
                             own_ibans=body.own_ibans, task_id=body.task_id)
        touch(request, sid)
        return _json(CreateSessionResponse(session_id=sid, policy_id=gw.policy.policy.policy_id,
                                           policy_hash=gw.policy.hash, registry_hash=gw.registry.registry_hash()))

    @app.post("/v1/sessions/{sid}/messages:user")
    async def user_message(sid: str, body: MessageRequest, request: Request) -> Response:
        touch(request, sid)
        return _json(gw_of(request).record_user_message(sid, body.text, message_id=body.message_id))

    @app.post("/v1/sessions/{sid}/messages:system")
    async def system_message(sid: str, body: MessageRequest, request: Request) -> Response:
        touch(request, sid)
        return _json(gw_of(request).record_system_message(sid, body.text))

    @app.put("/v1/sessions/{sid}/task-spec")
    async def put_task_spec(sid: str, body: TaskSpec, request: Request) -> Response:
        touch(request, sid)
        gw_of(request).set_task_spec(sid, body)
        return _json(body)

    @app.post("/v1/sessions/{sid}/summaries")
    async def summary(sid: str, body: SummaryRequest, request: Request) -> Response:
        touch(request, sid)
        return _json(gw_of(request).record_summary(sid, body.text, body.covered_entry_ids))

    @app.post("/v1/sessions/{sid}/tool-definitions")
    async def tool_definitions(sid: str, body: ToolDefinitionsRequest, request: Request) -> Response:
        touch(request, sid)
        return _json(gw_of(request).observe_tool_definitions(sid, body.specs))

    @app.get("/v1/sessions/{sid}/provenance")
    async def provenance(sid: str, request: Request) -> Response:
        touch(request, sid)
        return JSONResponse(gw_of(request).provenance(sid))

    @app.delete("/v1/sessions/{sid}", status_code=204)
    async def delete_session(sid: str, request: Request) -> Response:
        gw = gw_of(request)
        if not gw.has_session(sid):
            return _error(404, "unknown session", sid)
        gw.close_session(sid)
        request.app.state.store.forget(sid)
        return Response(status_code=204)

    # ------------------------------------------------------------------ hot path
    @app.post("/v1/tool-calls:evaluate")
    async def evaluate(body: EvaluateRequest, request: Request) -> Response:
        touch(request, body.session_id)
        return _json(gw_of(request).evaluate(body.session_id, body.call))

    @app.post("/v1/tool-calls:commit")
    async def commit(body: CommitRequest, request: Request) -> Response:
        touch(request, body.session_id)
        gw_of(request).commit(body.session_id, body.call, body.decision, executed=body.executed)
        return JSONResponse({"ok": True})

    @app.post("/v1/approvals")
    async def approvals(body: ApprovalRequestBody, request: Request) -> Response:
        touch(request, body.session_id)
        return _json(gw_of(request).record_approval(body.session_id, body.decision, body.result))

    @app.post("/v1/tool-outputs:label")
    async def label(body: LabelRequest, request: Request) -> Response:
        touch(request, body.session_id)
        return _json(gw_of(request).label_output(body.session_id, body.call, body.output))

    @app.post("/v1/final-answers:sanitize")
    async def sanitize(body: SanitizeRequest, request: Request) -> Response:
        touch(request, body.session_id)
        return _json(gw_of(request).sanitize_final_answer(body.session_id, body.text))

    # ------------------------------------------------------------------ policies (read-only)
    @app.post("/v1/policies:validate")
    async def validate_policy(body: PolicyValidateRequest, request: Request) -> Response:
        try:
            cp = _policy_from_yaml(body.yaml, gw_of(request).registry)
        except (PolicyError, ValidationError, yaml.YAMLError, OSError) as exc:
            return _json(PolicyValidateResponse(ok=False, errors=[str(exc)]))
        return _json(PolicyValidateResponse(ok=True, policy_hash=cp.hash))

    @app.post("/v1/policies:dry-run")
    async def dry_run(body: DryRunRequest, request: Request) -> Response:
        live = gw_of(request)
        try:
            cp = _policy_from_yaml(body.policy_yaml, live.registry) if body.policy_yaml else live.policy
        except (PolicyError, ValidationError, yaml.YAMLError) as exc:
            return _error(422, "invalid policy", str(exc))
        return _json(_dry_run(cp, live.registry, body))

    @app.get("/v1/policies/active")
    async def active_policy(request: Request) -> Response:
        cp = gw_of(request).policy
        text = yaml.safe_dump(cp.policy.model_dump(mode="json", by_alias=True), sort_keys=False)
        return JSONResponse({"policy_id": cp.policy.policy_id, "hash": cp.hash, "yaml": text})

    # ------------------------------------------------------------------ observability
    @app.get("/v1/audit")
    async def audit(request: Request, session_id: str | None = None, limit: int = Query(100, ge=1, le=AUDIT_RING)
                    ) -> Response:
        sink = gw_of(request).audit
        ring = list(sink.ring) if isinstance(sink, TeeAuditSink) else []
        records = [r for r in ring if session_id is None or r.session_id == session_id][-limit:]
        return _json(records) if records else JSONResponse([])

    @app.get("/metrics")
    async def metrics(request: Request) -> Response:
        return PlainTextResponse(gw_of(request).metrics.prometheus_text(), media_type="text/plain; version=0.0.4")

    @app.get("/healthz")
    async def healthz(request: Request) -> Response:
        return JSONResponse({"status": "ok", "policy_hash": gw_of(request).policy.hash})

    return app


def _dry_run(cp: Any, registry: ToolRegistry, body: DryRunRequest) -> DryRunResponse:
    """Replay traces in shadow mode on a temporary gateway; counts the would-be verdicts."""
    gw = Gateway(policy=cp, registry=registry, options=GatewayOptions(mode="shadow"))
    counts = {Verdict.ALLOW: 0, Verdict.REVIEW: 0, Verdict.BLOCK: 0}
    by_rule: dict[str, int] = {}
    for i, trace in enumerate(body.traces):
        sid = gw.new_session(f"dry-{i}")
        last_call: ToolCall | None = None
        for ev in trace:
            if ev.kind == "user" and ev.text is not None:
                gw.record_user_message(sid, ev.text)
            elif ev.kind == "system" and ev.text is not None:
                gw.record_system_message(sid, ev.text)
            elif ev.kind == "call" and ev.call is not None:
                d = gw.evaluate(sid, ev.call)
                verdict = d.shadow_verdict or d.verdict
                counts[verdict] += 1
                for f in d.findings:
                    if f.verdict != Verdict.ALLOW:
                        by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1
                gw.commit(sid, ev.call, d, executed=True)
                last_call = ev.call
            elif ev.kind == "output" and last_call is not None:
                gw.label_output(sid, last_call, ev.output)
        gw.close_session(sid)
    n = sum(counts.values())
    return DryRunResponse(n_calls=n, allow=counts[Verdict.ALLOW], review=counts[Verdict.REVIEW],
                          block=counts[Verdict.BLOCK], review_rate=counts[Verdict.REVIEW] / n if n else 0.0,
                          block_rate=counts[Verdict.BLOCK] / n if n else 0.0, by_rule=dict(sorted(by_rule.items())))
