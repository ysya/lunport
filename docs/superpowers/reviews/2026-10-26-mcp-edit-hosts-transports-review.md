# AI edits of hosts and transports with consent: review record

The plan `docs/superpowers/plans/2026-10-26-mcp-edit-hosts-transports.md` (design `docs/superpowers/specs/2026-10-26-mcp-edit-hosts-transports-design.md`) was executed in five tasks on the branch `claude/project-thread-whbjuy`, each with its tests written first, and the range `0cc29491..360c5e8` (the three MCP tools, the proposal kinds in the window, the transport in the host view, plus the terminal default, the tab strip's drag region and the authentication window's size) was read by a fresh reviewer against the spec, the plan and the executor's rulings. The reviewer ran the MCP and window tests (80 Rust, 9 frontend) and read the complete safe suite's result (3534 passed). Verdict: ready with fixes; no Critical findings.

## Fixed

| Finding | Fix | Test |
|---|---|---|
| The `Route` row restated every address, user and alias change, since the chain's label includes the destination hop; the window's contract is the changed fields only. | The row appears only when the host's jump hosts change. | `an_update_asks_shows_old_and_new_and_saves_only_on_consent` (no `Route` row) |
| `set_transport` and `remove_transport` did not refuse a host whose Group inheritance needs review before the window; the save went through and the answer then failed, so the audit said "not completed" for a save that happened. | Both refuse up front with `metadata`'s sentence, as `update_host` does. | `tools_refuse_a_host_whose_group_needs_review_before_the_window` |
| The transport tools had no denied / timed-out / cancelled case. | A test pins the sentences, the unchanged state and the audit outcome. | `a_denied_timed_out_or_cancelled_transport_change_changes_nothing_and_is_audited` |

## Calls made

- Only hosts the client may use can be edited or given a transport; `create_host` stays as it was.
- `group_id` is not accepted by `update_host`: moving a host between Groups or libraries can change AI access and upload a host, so it stays in the app.
- A field the host inherits from its Group becomes the host's own when the client changes it, and the window marks the old value as the Group's; the client cannot put a field back to inheriting.
- Changing the hostname or port clears the pinned server key, as every edit of the address does; the window says so in its own row and the answer tells the client to run `verify_host_key`.
- `set_transport` merges: a field given replaces that field only; `pam` as `null` removes the check, as an object sets it, keeping the person's own justification and, when omitted, the stored duration; `location` omitted resets to `global`.
- The success scenario ("point the host at an address and reach it through IAP") is two proposals, each reviewed on its own.
- `get_host` and `list_hosts` show the AI a host's transport, without the person's justification.
- Refusals before the window are not audited, as for `create_host`; proposals are matched to the window by the request id, as before.

## Left for later

- `(Group default)` is shown when the host inherits a field no Group sets (Lunport's own default applies); a clearer note would be `(inherited default)`.
- The `Keepalive interval / missed` row's inherited note looks at `keepalive_secs` only.
- The self-jump refusal test asserts only that the repository refuses, not its sentence.
- An unknown proposal `kind` falls back to the create-host words in the window; the backend sends four kinds today.
- `alias` is not trimmed by the three tools, while `get_host` trims its parameter.
- A deserialization failure answers the "settings only" sentence whatever the mistake (a missing `entitlements`, a mistyped `os_login`), as `create_host` does.
- The window's "Resolved:" line shows the TCP address for a transport proposal; the rows make the tunnel clear.
- `docs/usage.md` does not name `new_alias`, the one field whose name is not obvious.
- The live check of the three tools from an MCP client against the Development build is still to be done by hand.
