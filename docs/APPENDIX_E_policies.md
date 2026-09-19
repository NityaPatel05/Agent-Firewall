# Appendix E — Policy-pack rule catalog

Source of truth: `src/firewall/policies/*.yaml` (the table below is generated from the merged `all` policy).
Validate with `python -m firewall.core.policy.loader --validate src/firewall/policies/*.yaml`.
Inputs: PLAN §5.5, synthesis §4.3 (Progent / LivePI starter rules) and §4.6 (sinks), scenario catalog
(research/04 Part C(b)).

## Semantics recap
- All matching rules contribute; combined effect is BLOCK > REVIEW > ALLOW. If no rule matched, the side-effect
  default applies (`DEFAULT-<SIDE-EFFECT>`). Any matching rule — including an `allow` rule — suppresses the default.
- Built-in stages (`SYS-*`, M4–M6) cannot be overridden by `allow`; an `allow` rule may only `relax` the names in
  `RELAXABLE` (`SYS-PROV-NAMED`, `SYS-PROV-UNKNOWN`, `SYS-SINK-HOST`, `SYS-R2-001`, `SYS-SCHEMA-URL-IN-TEXT`).
- `strict` strictness upgrades `POL-RO-001` and `POL-SCOPE-001` from REVIEW to BLOCK.
- Condition extensions (documented deviations): `arg` accepts paths (`argv[0]`, `fields.name`); `value` may be
  `"@allowlists.<name>"`; for list-valued arguments a condition holds if **any** element satisfies it.
- `DEFAULT-*` finding IDs use dashes (`DEFAULT-EXTERNAL-COMM`) to stay within the rule-ID grammar.

## Packs (what each adds beyond PLAN §5.5)
- **workspace**: mass mail, attachments to untrusted external recipients, hidden BCC, contact-adding after taint,
  drafts are always allowed.
- **slack**: outside users, outside invites, secrets broadcast to channels.
- **travel**: booking rate limits; booking after untrusted listings when the task did not ask to book.
- **web**: SSRF (loopback / metadata hosts), webhooks to non-allow-listed hosts, saved-credential logins only on
  user-chosen sites, no secrets in forms/webhooks.
- **files**: protected paths (block unless user-typed; confirm even if typed), external share grants, bulk deletes,
  uploads to allow-listed storage (relaxes `SYS-PROV-UNKNOWN`).
- **mcp**: installs only from allow-listed registries (and relax `SYS-PROV-UNKNOWN` when the user asked), large
  refunds, publishing private content.
- **exec**: pytest allow-rules (B15), block exec when the task did not ask to run anything (A33).
- **livepi** (LivePI's 7 starter rules, condensed): wallet transfers only to trusted addresses, key-file reads in
  tainted sessions, firewall disable, secret-labelled content never leaves externally.

## Rules (merged `all` policy)

| id | effect | match | description |
|---|---|---|---|
| `POL-SEC-001` | block | groups=egress | Secrets or canaries never reach an egress sink unless the destination is internal AND user-typed |
| `POL-PRIV-001` | block | groups=egress | Private/secret content to an external destination of untrusted or unknown origin |
| `POL-PRIV-002` | review | groups=egress | Private content to an external destination that came from a user-named source is confirmed once |
| `POL-EGRESS-BULK-001` | review | groups=egress | Bulk private egress (e.g. whole-inbox forward) is confirmed once even to user-typed addresses |
| `POL-RO-001` | review | groups=consequential | A read-only task cannot perform consequential actions |
| `POL-SCOPE-001` | review | groups=consequential | Consequential tool outside the task's allowed groups |
| `POL-POLICY-001` | block | side_effects=config | Agent may never modify policy, firewall or agent config |
| `POL-CB-001` | block | groups=consequential | Circuit breaker |
| `BANK-AMT-001` | block | tools=schedule_transaction,send_money,update_scheduled_transaction | Transfers above 10k need a user-typed amount |
| `BANK-RATE-001` | block | tools=send_money | More than 3 transfers to the same non-user-typed recipient in a session (chunking, A09) |
| `BANK-PWD-001` | block | tools=update_password | Password changes need the new password typed by the user |
| `BANK-RECUR-001` | review | tools=update_scheduled_transaction | Changing a recurring payee is always confirmed |
| `BANK-PROFILE-001` | review | tools=update_user_info | Profile changes (address, name) after reading untrusted content are confirmed |
| `WS-MASS-001` | review | tools=create_event,forward_email,send_email | Sending to more than 25 recipients at once is confirmed (mass mail, A05 shape) |
| `WS-ATTACH-001` | block | tools=reply_email,send_email | Attachments to an external recipient of untrusted or unknown origin are blocked (A12) |
| `WS-BCC-001` | review | tools=reply_email,send_email | A hidden (BCC) external recipient that the user did not type is confirmed (A02) |
| `WS-CONTACT-001` | review | tools=add_contact | Adding contacts after reading untrusted content is confirmed (contacts become own records) |
| `WS-DRAFT-001` | allow | tools=draft_email | Drafts never leave the mailbox (B28) |
| `SLACK-EXT-001` | review | tools=add_user_to_channel,send_dm | Messages or invites to users outside the workspace need a user-typed recipient |
| `SLACK-INVITE-001` | block | tools=add_user_to_channel | Inviting an outside user of untrusted origin into a channel is blocked |
| `SLACK-SECRET-CHANNEL-001` | review | tools=post_message | Posting a secret to a channel (broadcast) is confirmed even when the user asked |
| `TRAVEL-RATE-001` | review | tools=book_hotel | More than two hotel bookings in one session are confirmed |
| `TRAVEL-RATE-002` | review | tools=book_flight | More than two flight bookings in one session are confirmed |
| `TRAVEL-TAINT-001` | review | groups=booking | Booking after reading untrusted listings when the task did not ask to book (A35, A40) |
| `WEB-SSRF-001` | block | tools=call_webhook,download_file,get_weather,get_webpage,login_portal,post_form,upload_file | Requests to loopback, link-local or cloud-metadata hosts are blocked unless the user typed the URL |
| `WEB-WEBHOOK-001` | review | tools=call_webhook | Webhooks to hosts outside the allow-list are confirmed (A39) |
| `WEB-LOGIN-001` | review | tools=login_portal | Saved credentials are only used on a site the user chose (A41) |
| `WEB-FORM-SECRET-001` | block | tools=call_webhook,post_form | Secrets are never submitted to web forms or webhooks (A17, A41) |
| `FILES-PROTECT-001` | block | tools=delete_file,download_file,write_file,zip_files | Writing or deleting a protected path needs a user-typed path (A13, T10) |
| `FILES-PROTECT-002` | review | tools=delete_file,write_file | Even a user-typed protected path is confirmed once before it is modified |
| `FILES-SHARE-EXT-001` | review | tools=share_file | Sharing with an external grantee the user did not type is confirmed (A42) |
| `FILES-BULK-DELETE-001` | review | tools=delete_file | More than 20 deletions in one session are confirmed |
| `FILES-UPLOAD-ALLOW-001` | allow (relax SYS-PROV-UNKNOWN) | tools=upload_file | Uploads to allow-listed internal storage do not need a user-typed URL (B36) |
| `MCP-INSTALL-001` | block | tools=install_mcp_server | Installing an MCP server from outside the registry allow-list is blocked |
| `MCP-INSTALL-002` | allow (relax SYS-PROV-UNKNOWN) | tools=install_mcp_server | Installing from an allow-listed registry when the user asked for an install (B41) |
| `MCP-REFUND-001` | review | tools=finance__refund | Refunds above 500 need a trusted amount |
| `MCP-PUBLISH-001` | review | tools=github__create_pr | Publishing private content (e.g. a public PR with private repo data, T3) is confirmed |
| `EXEC-TEST-001` | allow | tools=run_command | Running the test suite with pytest is allowed when the user asked to run things (B15) |
| `EXEC-TEST-002` | allow | tools=run_command | `python -m pytest` is equivalent to EXEC-TEST-001 |
| `EXEC-SCOPE-001` | block | side_effects=exec | Executing commands when the user did not ask to run anything is blocked (A33) |
| `LIVEPI-WALLET-001` | block | tools=transfer_crypto | Crypto transfers only to user-typed, approved or own addresses |
| `LIVEPI-KEYFILE-001` | review | tools=read_file | Reading wallet keys or SSH keys after ingesting untrusted content is confirmed |
| `LIVEPI-FIREWALL-001` | block | tools=update_firewall_settings | Disabling the host firewall is always blocked |
| `LIVEPI-SECRETS-OUT-001` | block | groups=egress | Secret-labelled content never leaves through any external sink, whatever the destination origin |
