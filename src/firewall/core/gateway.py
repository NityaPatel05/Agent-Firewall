"""Gateway facade: sessions, evaluation, approvals, commit, output labeling, audit and metrics."""

from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any, Protocol

from firewall.core.approvals import Approver
from firewall.core.audit import AuditSink
from firewall.core.canonical import canon_amount, canonicalize
from firewall.core.decoders import decode_candidates, split_payload_join, trigger_phrases, trigger_signals
from firewall.core.labels import BOTTOM, Confidentiality, Integrity, Label, SourceKind, SourceRef, join_all
from firewall.core.markdown import sanitize_final_answer as _sanitize
from firewall.core.metrics import GatewayMetrics
from firewall.core.models import (
    ApprovalResult,
    ArgRole,
    ArgType,
    AuditRecord,
    Decision,
    Finding,
    LabeledOutput,
    OriginClass,
    SanitizedText,
    SideEffect,
    Stage,
    ToolCall,
    Verdict,
)
from firewall.core.pipeline import EvalDetail, EvalInputs, GatewayOptions, evaluate_detailed
from firewall.core.policy.conditions import ArgFacts
from firewall.core.policy.loader import CompiledPolicy, load_policy
from firewall.core.provenance import (
    LabeledFragment,
    LedgerEntry,
    Signal,
    compute_output_labels,
    resolve_origin,
)
from firewall.core.registry import ResolveStatus, ToolRegistry, ToolSpec, canonical_json
from firewall.core.schema_validation import SchemaValidator
from firewall.core.secrets import find_canaries, find_secrets, mask_secrets
from firewall.core.session import SessionState, resource_key
from firewall.core.task_spec import RuleBasedTaskSpecExtractor, TaskSpec, TaskSpecExtractor

_APPROVAL_LABEL = Label(integrity=Integrity.TRUSTED, confidentiality=Confidentiality.PRIVATE,
                        sources=frozenset({SourceRef(kind=SourceKind.APPROVAL)}))
MIN_DECODE_LEN = 16
MIN_DETECTOR_LEN = 24


class UnknownSessionError(KeyError):
    """No such gateway session (HTTP 404 in the service)."""


class GatewayProtocol(Protocol):
    def new_session(self, session_id: str | None = None, *, user_handle: str = "@emma",
                    own_emails: Iterable[str] = (), own_ibans: Iterable[str] = (),
                    task_id: str | None = None) -> str: ...
    def record_system_message(self, session_id: str, text: str) -> LedgerEntry: ...
    def record_user_message(self, session_id: str, text: str, *, message_id: str | None = None) -> LedgerEntry: ...
    def set_task_spec(self, session_id: str, spec: TaskSpec) -> None: ...
    def evaluate(self, session_id: str, call: ToolCall) -> Decision: ...
    def record_approval(self, session_id: str, decision: Decision, result: ApprovalResult) -> Decision: ...
    def commit(self, session_id: str, call: ToolCall, decision: Decision, *, executed: bool) -> None: ...
    def label_output(self, session_id: str, call: ToolCall, output: Any) -> LabeledOutput: ...
    def record_summary(self, session_id: str, text: str, covered_entry_ids: Sequence[str]) -> LedgerEntry: ...
    def observe_tool_definitions(self, session_id: str, specs: Sequence[ToolSpec]) -> list[Finding]: ...
    def sanitize_final_answer(self, session_id: str, text: str) -> SanitizedText: ...
    def provenance(self, session_id: str) -> dict[str, Any]: ...
    def close_session(self, session_id: str) -> None: ...


def _mask_tree(value: Any) -> Any:
    if isinstance(value, str):
        return mask_secrets(value)[0]
    if isinstance(value, list):
        return [_mask_tree(v) for v in value]
    if isinstance(value, dict):
        return {k: _mask_tree(v) for k, v in value.items()}
    return value


def _args_sha(args: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(dict(args)).encode("utf-8")).hexdigest()


def _render(output: Any) -> str:
    if isinstance(output, str):
        return output
    return json.dumps(output, sort_keys=True, ensure_ascii=False, default=str)


class Gateway:
    """In-process gateway. Every public method takes the session lock; `evaluate` reads a snapshot."""

    def __init__(
        self,
        *,
        policy: CompiledPolicy,
        registry: ToolRegistry,
        options: GatewayOptions | None = None,
        audit: AuditSink | None = None,
        metrics: GatewayMetrics | None = None,
        task_spec_extractor: TaskSpecExtractor | None = None,
        detectors: Any | None = None,
        run_context: Mapping[str, str] | None = None,
    ) -> None:
        self.policy = policy
        self.registry = registry
        self.options = options or GatewayOptions()
        self.audit = audit
        self.metrics = metrics or GatewayMetrics()
        self.extractor: TaskSpecExtractor = task_spec_extractor or RuleBasedTaskSpecExtractor()
        self.detectors = detectors
        self.run_context = dict(run_context or {})
        self.validator = SchemaValidator(registry)
        self._sessions: dict[str, SessionState] = {}
        self._lock = threading.Lock()
        self._auto_spec: dict[str, bool] = {}
        self._user_texts: dict[str, list[str]] = {}
        self._details: dict[tuple[str, str], EvalDetail] = {}
        self._calls: dict[tuple[str, str], ToolCall] = {}
        self._desc_seen: dict[str, set[str]] = {}
        self._audit_seq: dict[str, int] = {}

    @classmethod
    def from_config(cls, *, policy: str | Path = "all", registry_files: Sequence[Path] | None = None,
                    **kwargs: Any) -> Gateway:
        registry = ToolRegistry.from_yaml(registry_files)
        return cls(policy=load_policy(policy, registry=registry), registry=registry, **kwargs)

    # ------------------------------------------------------------------ sessions
    def _session(self, session_id: str) -> SessionState:
        try:
            return self._sessions[session_id]
        except KeyError as exc:
            raise UnknownSessionError(f"unknown session: {session_id}") from exc

    def has_session(self, session_id: str) -> bool:
        return session_id in self._sessions

    def new_session(self, session_id: str | None = None, *, user_handle: str = "@emma",
                    own_emails: Iterable[str] = (), own_ibans: Iterable[str] = (),
                    task_id: str | None = None) -> str:
        al = self.policy.policy.allowlists
        sid = session_id or uuid.uuid4().hex
        state = SessionState(sid, user_handle=user_handle, own_emails=[*al.own_emails, *own_emails],
                             own_ibans=[*al.own_ibans, *own_ibans])
        with self._lock:
            if sid in self._sessions:
                raise ValueError(f"session already exists: {sid}")
            self._sessions[sid] = state
            self._auto_spec[sid] = True
            self._user_texts[sid] = []
            self._desc_seen[sid] = set()
            self._audit_seq[sid] = 0
        self._audit(sid, "session", extra={"task_id": task_id})
        return sid

    def close_session(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)
            for d in (self._auto_spec, self._user_texts, self._desc_seen, self._audit_seq):
                d.pop(session_id, None)
            for key in [k for k in self._details if k[0] == session_id]:
                self._details.pop(key, None)
                self._calls.pop(key, None)

    def record_system_message(self, session_id: str, text: str) -> LedgerEntry:
        s = self._session(session_id)
        with s.lock:
            return s.ledger.append(kind=SourceKind.SYSTEM, text=text, label=Label.system())

    def record_user_message(self, session_id: str, text: str, *, message_id: str | None = None) -> LedgerEntry:
        s = self._session(session_id)
        with s.lock:
            if message_id is not None and message_id in s.seen_message_ids:
                return next(e for e in reversed(s.ledger.entries()) if e.kind == SourceKind.USER)
            if message_id is not None:
                s.seen_message_ids.add(message_id)
            entry = s.ledger.append(kind=SourceKind.USER, text=text, label=Label.user())
            self._user_texts[session_id].append(text)
            if self._auto_spec.get(session_id, True):
                # Each turn ends a clause, so a verb at the start of a later turn counts as an action.
                s.task_spec = self.extractor.extract(".\n".join(self._user_texts[session_id]), task_id=session_id)
            return entry

    def set_task_spec(self, session_id: str, spec: TaskSpec) -> None:
        s = self._session(session_id)
        with s.lock:
            s.task_spec = spec
            self._auto_spec[session_id] = False

    # ------------------------------------------------------------------ evaluation
    def _evaluate(self, session_id: str, call: ToolCall, approved_by: str | None = None) -> Decision:
        s = self._session(session_id)
        with s.lock:
            inputs = EvalInputs(policy=self.policy, registry=self.registry, validator=self.validator,
                                session=s.view(), call=call, options=self.options, approved_by=approved_by)
            detail = evaluate_detailed(inputs)
            self._details[(session_id, call.call_id)] = detail
            self._calls[(session_id, call.call_id)] = call
            decision = detail.decision
        self.metrics.observe_decision(decision)
        self._audit_decision(session_id, call, decision)
        return decision

    def evaluate(self, session_id: str, call: ToolCall) -> Decision:
        return self._evaluate(session_id, call)

    def pin_approval(self, session_id: str, side_effect: SideEffect, arg_type: ArgType, value: Any) -> None:
        """Pin one approved value (approver channel only)."""
        s = self._session(session_id)
        canonical = canonicalize(value, arg_type) or str(value)
        with s.lock:
            s.approvals.add(side_effect, arg_type, canonical)
            s.ledger.append(kind=SourceKind.APPROVAL, text=canonical, label=_APPROVAL_LABEL)

    def record_approval(self, session_id: str, decision: Decision, result: ApprovalResult) -> Decision:
        self._audit(session_id, "approval", tool=decision.tool, call_id=decision.call_id,
                    extra={"approved": result.approved, "approver": result.approver})
        if not result.approved:
            ids = ", ".join(decision.rule_ids)
            return decision.model_copy(update={"message_to_agent": f"Not executed: the user declined this action "
                                                                   f"[{ids}]."})
        call = self._calls.get((session_id, decision.call_id))
        if call is None:
            raise KeyError(f"no pending call {decision.call_id} in session {session_id}")
        spec = self.registry.resolve(call.tool, call.server).spec
        if result.edited_args:
            call = call.model_copy(update={"args": {**call.args, **result.edited_args}})
        if spec is not None:
            items = decision.review.items if decision.review is not None else ()
            for item in items:
                a = spec.args.get(item.arg)
                if a is not None and item.value_canonical:
                    self.pin_approval(session_id, spec.side_effect, a.value_type, item.value_canonical)
            for name, value in (result.edited_args or {}).items():
                a = spec.args.get(name)
                if a is not None and a.role in (ArgRole.AUTHORITY, ArgRole.BOUNDED):
                    for v in value if isinstance(value, list) else [value]:
                        self.pin_approval(session_id, spec.side_effect, a.value_type, v)
        return self._evaluate(session_id, call, approved_by=result.approver)

    def approve_with(self, session_id: str, decision: Decision, approver: Approver) -> Decision:
        """Convenience: route a REVIEW decision through an approver and record the result."""
        if decision.verdict != Verdict.REVIEW or decision.review is None:
            return decision
        return self.record_approval(session_id, decision, approver.decide(decision.review))

    # ------------------------------------------------------------------ commit
    def commit(self, session_id: str, call: ToolCall, decision: Decision, *, executed: bool) -> None:
        s = self._session(session_id)
        detail = self._details.get((session_id, call.call_id))
        with s.lock:
            s.step += 1
            if not executed:
                if decision.verdict == Verdict.BLOCK:
                    s.counters.blocks += 1
                    if s.counters.blocks >= self.policy.policy.circuit_breaker.max_blocks:
                        s.circuit_open = True
                elif decision.verdict == Verdict.REVIEW:
                    s.counters.reviews += 1
                return
            spec = detail.spec if detail is not None else self.registry.resolve(call.tool, call.server).spec
            if spec is None:
                return
            args = detail.args if detail is not None else call.args
            facts = detail.facts if detail is not None else ArgFacts()
            c = s.counters
            c.calls_by_tool[spec.qualified_name] = c.calls_by_tool.get(spec.qualified_name, 0) + 1
            for d in decision.destinations:
                key = f"{spec.qualified_name}|{d.value}"
                c.calls_by_dest[key] = c.calls_by_dest.get(key, 0) + 1
                if d.kind == ArgType.URL and d.host:
                    c.external_fetches_by_host[d.host] = c.external_fetches_by_host.get(d.host, 0) + 1
            if spec.side_effect == SideEffect.PAYMENT:
                for name, a in spec.args.items():
                    if a.role == ArgRole.BOUNDED and a.type == ArgType.AMOUNT:
                        amt = canon_amount(args.get(name))
                        if amt is not None:
                            c.transfer_total += amt
            c.private_bytes_out += facts.private_bytes
            if spec.writes_ref_arg is not None:
                self._store_resource_label(s, spec, args)

    def _store_resource_label(self, s: SessionState, spec: ToolSpec, args: Mapping[str, Any]) -> None:
        ref_spec = spec.args[spec.writes_ref_arg]  # type: ignore[index]
        key = resource_key(ref_spec.value_type, args.get(spec.writes_ref_arg))  # type: ignore[arg-type]
        if key is None:
            return
        view = s.view()
        labels: list[Label] = []
        for name, a in spec.args.items():
            if a.role != ArgRole.CONTENT or args.get(name) in (None, ""):
                continue
            o = resolve_origin(view.ledger, arg=name, spec=a, value=args[name], task_spec=view.task_spec,
                               approvals=view.approvals, side_effect=spec.side_effect, constants=view.constants())
            labels.append(o.label)
            if o.origin_class == OriginClass.UNKNOWN:
                labels.append(view.ledger.ctx_label())
        if labels:
            s.resource_labels[key] = join_all(labels)

    # ------------------------------------------------------------------ outputs
    def label_output(self, session_id: str, call: ToolCall, output: Any) -> LabeledOutput:
        t0 = time.perf_counter_ns()
        s = self._session(session_id)
        res = self.registry.resolve(call.tool, call.server)
        spec = res.spec
        findings: tuple[Finding, ...] = ()
        with s.lock:
            if spec is None:
                lab = Label.tool(trusted=False, conf=Confidentiality.PRIVATE, tool=call.tool, call_id=call.call_id)
                frags = [LabeledFragment(text=_render(output), label=lab)]
            else:
                findings = self.validator.validate_output(spec, output)
                frags = compute_output_labels(spec, call, output, user_handle=s.user_handle)
                if spec.ref_arg is not None:
                    key = resource_key(spec.args[spec.ref_arg].value_type, call.args.get(spec.ref_arg))
                    stored = s.resource_labels.get(key) if key else None
                    if stored is not None:
                        frags = [f.model_copy(update={"label": f.label.join(stored)}) for f in frags]
            entries = self._append_fragments(s, frags, call, spec)
            label = join_all(e.label for e in entries) if entries else BOTTOM
            agent_output = _mask_tree(output) if spec is not None and spec.output.mask_secrets else output
        label_us = (time.perf_counter_ns() - t0) / 1000.0
        self.metrics.observe_label(label_us)
        self._audit(session_id, "output", tool=call.tool, call_id=call.call_id,
                    extra={"label": label.model_dump(mode="json"), "entries": [e.entry_id for e in entries]})
        return LabeledOutput(call_id=call.call_id, content=_render(agent_output), label=label,
                             entry_ids=tuple(e.entry_id for e in entries), findings=findings, label_us=label_us)

    def _append_fragments(self, s: SessionState, frags: list[LabeledFragment], call: ToolCall,
                          spec: ToolSpec | None) -> list[LedgerEntry]:
        canaries = self.policy.policy.canaries
        tool = spec.qualified_name if spec is not None else call.tool
        prev_untrusted = next((e for e in reversed(s.ledger.entries())
                               if e.kind == SourceKind.TOOL_OUTPUT and not e.label.trusted), None)
        entries: list[LedgerEntry] = []
        first_untrusted: LedgerEntry | None = None
        for f in frags:
            label = f.label
            if find_secrets(f.text) or (canaries and find_canaries(f.text, canaries)):
                label = label.model_copy(update={"confidentiality": Confidentiality.SECRET})
            signals: list[Signal] = trigger_signals(f.text) if not label.trusted else []
            if self.detectors is not None and not label.trusted and len(f.text) >= MIN_DETECTOR_LEN:
                res = self.detectors.score(f.text)
                signals.append(Signal(source=f"detector:{res.detector}", kind="detector", score=res.score,
                                      detail="flagged" if res.flagged else ""))
            e = s.ledger.append(kind=SourceKind.TOOL_OUTPUT, text=f.text, label=label, call_id=call.call_id,
                                tool=tool, ref=f.ref, ref_aliases=f.ref_aliases, author=f.author, field=f.field,
                                signals=signals)
            entries.append(e)
            if not label.trusted:
                s.flags.ingested_untrusted = True
                first_untrusted = first_untrusted or e
            if label.confidentiality >= Confidentiality.PRIVATE:
                s.flags.read_private = True
            if label.confidentiality >= Confidentiality.SECRET:
                s.flags.read_secret = True
            if len(f.text) >= MIN_DECODE_LEN:
                for d in decode_candidates(f.text):
                    sig = [Signal(source="decoders", kind=f"decoded:{d.scheme}"), *trigger_signals(d.text)]
                    entries.append(s.ledger.append(kind=SourceKind.DERIVED, text=d.text, label=label,
                                                   call_id=call.call_id, tool=tool, ref=f.ref,
                                                   ref_aliases=f.ref_aliases, field=f.field, signals=sig))
        if prev_untrusted is not None and first_untrusted is not None:
            joined = split_payload_join(prev_untrusted, first_untrusted)
            if joined is not None:
                known = set(trigger_phrases(prev_untrusted.text)) | set(trigger_phrases(first_untrusted.text))
                phrases = [p for p in trigger_phrases(joined) if p not in known]
                new = [Signal(source="decoders", kind=f"trigger:{lang}", detail=p) for lang, p in phrases]
                if new:
                    entries.append(s.ledger.append(
                        kind=SourceKind.DERIVED, text=joined, label=prev_untrusted.label.join(first_untrusted.label),
                        call_id=call.call_id, tool=tool, field="split_payload",
                        signals=[Signal(source="decoders", kind="split_payload"), *new]))
        return entries

    def record_summary(self, session_id: str, text: str, covered_entry_ids: Sequence[str]) -> LedgerEntry:
        s = self._session(session_id)
        with s.lock:
            covered = [s.ledger.get(e).label for e in covered_entry_ids]
            label = join_all(covered) if covered else s.ledger.ctx_label()
            return s.ledger.append(kind=SourceKind.SUMMARY, text=text, label=label)

    def record_tool_description(self, session_id: str, tool: str, server: str | None, text: str) -> LedgerEntry:
        s = self._session(session_id)
        label = Label.tool(trusted=False, conf=Confidentiality.PUBLIC, tool=tool, call_id=None, server=server,
                           kind=SourceKind.TOOL_DESCRIPTION)
        with s.lock:
            s.flags.ingested_untrusted = True
            return s.ledger.append(kind=SourceKind.TOOL_DESCRIPTION, text=text, label=label, tool=tool)

    def observe_tool_definitions(self, session_id: str, specs: Sequence[ToolSpec]) -> list[Finding]:
        findings: list[Finding] = []
        seen = self._desc_seen.setdefault(session_id, set())
        for spec in specs:
            status = self.registry.observe_definition(spec)
            if status == ResolveStatus.PIN_MISMATCH:
                findings.append(Finding(rule_id="SYS-REG-PIN", stage=Stage.REGISTRY, verdict=Verdict.BLOCK,
                                        reason=f"definition of {spec.qualified_name} changed (rug pull)"))
            elif status == ResolveStatus.UNAPPROVED:
                findings.append(Finding(rule_id="SYS-REG-UNAPPROVED", stage=Stage.REGISTRY, verdict=Verdict.BLOCK,
                                        reason=f"{spec.qualified_name} is not approved"))
            h = spec.definition_hash()
            # Pinned, approved definitions were vetted at pin time; only changed/unapproved ones are untrusted text.
            if status != ResolveStatus.OK and h not in seen and spec.description:
                seen.add(h)
                self.record_tool_description(session_id, spec.qualified_name,
                                             None if spec.server == "local" else spec.server, spec.description)
        return findings

    def sanitize_final_answer(self, session_id: str, text: str) -> SanitizedText:
        s = self._session(session_id)
        with s.lock:
            out = _sanitize(text, session=s.view(), policy=self.policy)
        self._audit(session_id, "final_answer", extra={"changed": out.changed,
                                                       "rule_ids": [f.rule_id for f in out.findings]})
        return out

    def provenance(self, session_id: str) -> dict[str, Any]:
        s = self._session(session_id)
        with s.lock:
            v = s.view()
            return {
                "session_id": session_id,
                "entries": [{"entry_id": e.entry_id, "kind": e.kind.value, "text": mask_secrets(e.text)[0][:500],
                             "integrity": e.label.integrity.name, "confidentiality": e.label.confidentiality.name,
                             "tool": e.tool, "ref": e.ref, "author": e.author, "field": e.field,
                             "signals": [x.kind for x in e.signals]} for e in v.ledger.entries()],
                "ctx_label": v.ledger.ctx_label().model_dump(mode="json"),
                "flags": v.flags.model_dump(),
                "counters": json.loads(v.counters.model_dump_json()),
                "task_spec": v.task_spec.model_dump(mode="json") if v.task_spec else None,
                "circuit_open": v.circuit_open,
            }

    def session_state(self, session_id: str) -> SessionState:
        """Direct access for tests and benchmarks (not part of GatewayProtocol)."""
        return self._session(session_id)

    # ------------------------------------------------------------------ audit
    def _next_seq(self, session_id: str) -> int:
        with self._lock:
            self._audit_seq[session_id] = self._audit_seq.get(session_id, 0) + 1
            return self._audit_seq[session_id]

    def _audit(self, session_id: str, event: str, *, tool: str | None = None, call_id: str | None = None,
               extra: Mapping[str, Any] | None = None) -> None:
        if self.audit is None:
            return
        rec = AuditRecord(ts=time.time(), session_id=session_id, seq=self._next_seq(session_id), event=event,  # type: ignore[arg-type]
                          tool=tool, call_id=call_id, label=dict(extra) if extra else None,
                          policy_hash=self.policy.hash, registry_hash=self.registry.registry_hash(),
                          mode=self.options.mode or self.policy.policy.mode,
                          scenario_id=self.run_context.get("scenario_id"), run_id=self.run_context.get("run_id"))
        self.audit.write(rec)

    def _audit_decision(self, session_id: str, call: ToolCall, d: Decision) -> None:
        if self.audit is None:
            return
        rec = AuditRecord(
            ts=time.time(), session_id=session_id, seq=self._next_seq(session_id), event="decision", tool=d.tool,
            call_id=d.call_id, args_sha256=_args_sha(call.args), normalized_args=_mask_tree(d.normalized_args),
            verdict=d.verdict, rule_ids=list(d.rule_ids),
            origins={k: o.origin_class.value for k, o in d.arg_origins.items()}, eval_us=d.eval_us,
            policy_hash=d.policy_hash, registry_hash=d.registry_hash, mode=self.options.mode or self.policy.policy.mode,
            scenario_id=self.run_context.get("scenario_id"), run_id=self.run_context.get("run_id"))
        self.audit.write(rec)


__all__ = ["Gateway", "GatewayOptions", "GatewayProtocol"]
