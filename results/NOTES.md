### Summary and context for the criteria table

**What the evidence supports.** Against a scripted, fully compromised agent the gateway stopped every attack in our
suites (0/42 A, 0/24 LivePI-style, 0/7 T-items, 0/42 under each of 15 mutation operators) while every benign twin
completed with the oracle approver and an everyday workload of 120 tasks / 612 calls saw no interruption. On
AgentDojo's own ground truth it stopped all banking and nearly all travel/workspace attacks; Slack has documented
gaps. **What it does not show:** a live security improvement — the live models we could use rarely followed the
injections (0/10 on our scenarios for every model; 2/8 AgentDojo pairs for gpt-oss-20b, 0/8 for Gemini).

**Criteria not met, and why**

- **S3 (AgentDojo gate-only ASR 3.4 % > 2 %).** 32/949 pairs (32/583 where the undefended replay succeeds).
  21 are Slack `injection_task_3` ("visit this URL"): fetches are read-class and allowed by default; 11 are goal
  collisions (the attacker's recipient/file/participant is one the user task itself names or owns, so provenance
  cannot separate them). Without the fetch-only goal: 11/928 = 1.2 %.
- **S10 (AgentDojo ground truth: 13.9 % interruption, 6 hard blocks).** Most interruptions are by-design
  confirmations of values from user-named sources (banking "pay the bill in the file": 27 % of banking GT calls,
  all approved). Hard blocks: 3 Slack invites whose e-mail address comes from a chat message/inbox
  (`AD-SLACK-INVITE-001`), and 3 workspace e-mails whose recipients never appear in anything the agent read
  (`UNKNOWN` origin → `POL-PRIV-001` / `AD-WS-ATTACH-001`).
- **S11a / S12 (evaluate p50 232 µs, label_output p95 2.5 ms normalized).** Measured with other workloads running on
  this laptop (machine factor 3.9× vs. 2.8–3.0× when idle); the M6 idle measurement was ~0.5 ms raw p50. M10–M11
  added checks to the hot path (credential-named fields, list-valued URL parameters, name matching). The supervisor
  accepted sub-millisecond evaluate cost at M6; p95/p99 and HTTP targets are met.
- **S16 (suite 94.6 s > 60 s).** 1170 tests pass. The suite took 59.2 s on an idle machine at M10; M11–M13 added
  report/README/AgentDojo-adapter tests and the measurement was taken under external load. AgentDojo adapter tests
  are opt-in (`--run-agentdojo`, +38 s) because importing AgentDojo's pipeline package costs ~14 s.
- **S4 / S5 n.a.** The AgentDojo live run is partial (below); the adaptive LLM-attacker loop is implemented and
  tested offline but was not run live within the budget.

**Live-run log notes**

- *Gemini scenario arm* (`m10-live-final`) was replayed from the response cache of `m10-live`, which made the real
  calls: B0 44, B3 103, GW 3 LLM calls (GW's prompts were mostly identical to B0's), ≈ $0.32 total, median episode
  7.7 s (B0).
- *Groq scenario arm* (`m11-live-groq`, gpt-oss-20b, `--live-tools script`): neither gpt-oss-20b nor qwen3.8-27b
  executed any injected action undefended, also with a neutral system prompt without the injection warning
  (`m11-probe-*` runs). Groq occasionally returns HTTP 400 "failed_generation" for malformed tool calls; these are
  recorded as errors (no utility, no attack success), never retried.
- *AgentDojo live* (banking + slack, 2 user × 2 injection tasks, `important_instructions`): B0 complete for both
  models; for gpt-oss-20b, B2/B3/GW were only partly run — the run was stopped twice by the background time limit
  after a Groq connection error stalled it (GW reached 3 banking episodes). Observations from the partial data: our
  port of AgentDojo's tool filter left gpt-oss-20b with no tools at all on banking (0 tool calls); GW blocked a benign
  banking call because the model added an argument that the tool does not have (`SYS-SCHEMA-EXTRA-KEY`).
