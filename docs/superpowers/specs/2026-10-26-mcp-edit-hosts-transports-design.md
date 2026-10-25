# AI edits hosts and transports, with your consent: design

2026-10-26. Follows the AI access design (`create_host`, `verify_host_key`) and the Google Cloud IAP transports design (`2026-10-25-gcp-iap-oslogin-design.md`); an addition to the branch `claude/project-thread-whbjuy`.

## Intent

Frank drives Lunport partly through an AI client over MCP. Today the client can propose a new host (`create_host`), which Lunport shows in its approval window before saving, but it cannot change a host it already knows, and it cannot set up the Google Cloud IAP transport a production host needs; Frank types those in the panel by hand. He wants the client to be able to edit a host's connection settings and to add, change or remove a host's transport, with Lunport asking him first every time, exactly as it asks before adding a host.

Success: from the AI client, "point jumpbox-prod at 10.20.0.8 and reach it through IAP in knowknow-prod with the prod-operate grant" ends in Lunport's approval window, once for the host's address and once for the transport, each showing what would change and saving on one click. Nothing is saved without that click; a proposal the person denies leaves the other one's save as it was, and the client is told which one failed.

## Goals

1. `update_host`: the client proposes changes to the public connection settings of a host it is permitted to use; Lunport shows the host and every field that would change, old and new, and saves on **Save changes**.
2. `set_transport` and `remove_transport`: the client proposes a host's Google Cloud IAP transport (all of its fields, including OS Login and the PAM check) or its removal; Lunport shows the transport as it is and as it would be, and saves on **Save transport** / **Remove transport**.
3. The approval window is the one that `create_host` and `ssh_exec` use, so the person reviews every AI proposal in one place, with the same attribution, the same 120-second expiry, and the same rule that the client cannot approve.

## Non-goals

- Changing a host's server identity (pinned key), its saved password, or private keys: `update_host` never touches them, as `create_host` never accepts them.
- Granting AI access: editing a host does not change whether the client may use it; a transport does not either.
- Editing Groups, keys, tunnels or settings; deleting hosts.
- Editing hosts the client is not permitted to use: the tools answer exactly what `get_host` answers for such a host (no more is revealed than today).
- Moving a host between Groups or libraries (`group_id`): that stays in the app, since it can change AI access and upload a host to the synced library.

## Anti-goals

- A proposal that saves anything without the window: every one of these tools asks, in Ask and in Auto-log mode alike, as `create_host` does.
- A window that shows a diff the person cannot judge: every changed field is shown by its name with the old and the new value; a field the client did not send is not changed and not shown.
- A save over someone else's change: the proposal records the host's revision (and the transport as it was); if either changed while the window was open, nothing is saved and the client is told to look again.

## Constraints

- The tools take the same field names and limits as `create_host` (`alias`, `hostname`, `port`, `user`, `auth`, `key_id`, `jump`, `keepalive_secs`, `keepalive_max_missed`, `connect_timeout_secs`, `tags`; not `group_id`) and the transport editor (`project`, `zone`, `instance`, `interface`, `account`, `os_login`, `pam` with `entitlements`, `location`, `duration_minutes`), validated by the same code and refused with the same sentences.
- Secrets never enter a proposal, the window, the audit log or an error: a `key_id` is shown as the key's name and fingerprint, as `create_host` shows it.
- The approval request, the decision and the outcome are audited as `create_host`'s are.

## How it works (decided)

**Tools.** Three MCP tools beside `create_host`:

- `update_host { alias_or_id, ...fields }`: `alias_or_id` names a permitted host (a stable id or an exact, unambiguous alias, as `verify_host_key` takes it); every other field is optional and replaces that field only. At least one field must be given. The proposal is built on a snapshot: the host's current payload with the given fields replaced, validated as the editor validates it (`update_host` in the repository, with the host's revision as `expected`). A field the host inherits from its Group (`inherit`) becomes the host's own value when the client sends it, as the editor does when the person unticks "Use group default": the window shows the effective value as the old one, marked as the Group's, and the save removes the field from `inherit`; the client cannot put a field back to inheriting (the app can). Changing the hostname or port clears the host's pinned server key, as every edit of the address does (the next connection verifies the server again, and saved passwords wait for that): the window says so in its own row, and the tool's answer reminds the client to run `verify_host_key`.
- `set_transport { alias_or_id, project?, zone?, instance?, interface?, account?, os_login?, pam? }`: a transport's fields; a field given replaces that field only, as `update_host` does, so a client that changes the PAM check does not have to repeat the instance. A host without a transport needs `project`, `zone` and `instance`; `interface` then defaults to `nic0`, `os_login` to `true`, `account` to gcloud's active account (`null`) and `pam` to none. `pam` given as an object sets the check (`entitlements` required, `location` defaulting to `global`, `duration_minutes` to the stored one, else 30; the stored justification is kept); `pam` given as `null` removes the check. The result is validated as the panel validates it.
- `remove_transport { alias_or_id }`: removes the host's transport; the host is then reached at its saved address.

**Permission.** The host must be permitted to the client (allowed individually or through a Group), checked as `get_host` checks it; otherwise the tool answers the sentence `get_host` answers (an unknown or ambiguous name, or a host that is not allowed). `create_host` stays as it is (a new host is not permitted until the person allows it). `jump` takes host ids as `create_host` takes them; the window shows the resulting route, as it does for a new host.

**Reading a transport.** `get_host` (and `list_hosts`) gain a `transport` object (`project`, `zone`, `instance`, `interface`, `account`, `os_login`, `pam`), `null` for a host reached at its address, so the client can see what it would change and can look again after a conflict. The three new tools answer the same host view.

**The window.** `McpPendingRequest` carries a `proposal` with a kind (`create_host`, `update_host`, `set_transport`, `remove_transport`) and the rows to show. For `create_host` the rows are today's settings. For `update_host` the rows are the changed fields only, each `old → new` (a field the client sent with its current value is not a change; a proposal with no change is refused before the window: "Nothing would change."). For `set_transport` the rows are the transport's fields, `old → new` where there was a transport, plain where there was none; for `remove_transport` the rows are the transport being removed. Titles: **Change this SSH host?**, **Change this host's transport?**, **Remove this host's transport?**; buttons **Save changes**, **Save transport**, **Remove transport**; the description says what the save does and does not do (no connection, no trust decision, AI access unchanged). Deny stays the default focus; the Allow button arms after the delay the window already uses.

**Saving.** On Allow the tool checks the policy is still enabled and the mode unchanged (`live`), then saves through `edit_records` with the revision (hosts, through the repository's `update_host`, never the library move) or the transport as it was when proposed (`transports::set` with `expected`); a mismatch answers "The host changed while the request was open; read it again and retry." (or "…the transport…"). The answer to the client is the host's sanitized public view (`get_host`'s shape, transport included).

**Audit.** Each tool writes the audit entries `create_host` writes: the request with its outcome (allowed, denied, timed out, canceled) and the client attribution.

**Documentation.** `docs/usage.md`'s tool table gains the three rows; the example after the table shows `update_host` and `set_transport`.

## Left to the builder

- The exact shape of the `proposal` field (one struct with `kind` and `rows`, replacing `host_proposal`, is the expectation) and the `ts-rs` binding.
- How `alias_or_id` is resolved (the helper `verify_host_key` uses).
- The order of the rows and the wording of unchanged-field omissions.
- Whether `set_transport` with a `pam` block whose `entitlements` are unchanged keeps the stored `justification` (yes) and `duration_minutes` when the client omits it (keep the stored one, else 30).

## Calls I made (for Frank to check)

1. Only hosts the AI is already allowed to use can be edited or given a transport. Creating a host stays as it is (not allowed until you allow it).
2. The host's server key, passwords and private keys cannot be changed this way, as with `create_host`; changing the address clears the pinned key as every edit does, and the window says so.
3. Removing a transport is included (`remove_transport`). Deleting hosts and moving a host between Groups are not: those stay in the app.
4. Every one of these asks, even in Auto-log mode, exactly like adding a host; the success scenario is two proposals (the host, then its transport), each reviewed on its own.
5. `get_host` and `list_hosts` show the AI a host's transport (project, zone, instance, account, OS Login, the PAM check): without it the client cannot edit what it cannot see.
6. A field the host takes from its Group becomes the host's own when the AI changes it (as unticking "Use group default" does); the window shows that.
