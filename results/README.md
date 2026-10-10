# M10 results

Exported by `python -m firewall.eval.run_scenarios ... --results-dir results` (per run: `<run>_summary.{csv,json}`
= metric rows per subset × defense × approver; `<run>_episodes.csv` = one row per episode). Raw episodes, manifests
and audit logs are in `runs/<run>/`. No API keys or prompts with secrets are stored here (scenario data only).

| run | mode | what |
|---|---|---|
| `m10-offline` | offline (scripted, gate-only) | full suite (42 A + 42 B + 14 T + 24 LP + 120 PB) under GW, GW-STRICT, B0, B2, B6 (oracle + autodeny) and B3 ProtectAI (oracle). Prompt Guard 2 (B4/B4s) skipped: gated, no HF token. |
| `m10-ablations` | offline | ABL-PROV/ROLES/TASKSPEC/SINKS/SCHEMA/R2/PIN and GW+D (oracle). |
| `m10-live-final` | live, gemini-3.5-flash-lite | **authoritative live outcomes**: 10 attacks (9 twin pairs + A14) + 10 benign twins under B0, B3, GW; served from the response cache of `m10-live` (sequential tool execution), 1 new call. |
| `m10-live` | live | the run that made the real API calls: use it for LLM calls / tokens / cost / wall-clock. Its `intermediate` column uses the earlier (too loose) definition — superseded by `m10-live-final`. |
| `m10-live-replay` | replay | cache-only re-derivation; B0/B34 and B0/B35 missed the cache because parallel tool calls ran concurrently (fixed by sequential execution). Kept for transparency. |
