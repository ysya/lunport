# Plan 1c scout: host records, schema 3, local store, import, and what goes

Read-only scout of branch `next/own-ssh` at 9476f10 (2026-10-14; "merge main into next/own-ssh", the same tree as 8055064,
`git diff 8055064 9476f10` is empty). Nothing tracked was changed. The only command that built anything:
`CARGO_TARGET_DIR=<scratchpad>/target-scout /opt/homebrew/bin/cargo test --offline --locked --lib -- --list` (Homebrew cargo/rustc
1.99.0; a cold build of 506 crates took 39 s; no test was run; the one warning is the old dead `config::edit::set_host_enabled`,
`config/edit.rs:175`). It lists **2004 lib tests on macOS** (cfg(windows) tests not counted). No pnpm/npm/npx, no app, no ssh,
no ~/.ssh / Keychain / app-data access. Frontend test counts below are static counts of `it(`/`test(` (not run).
Spec = `docs/superpowers/specs/2026-10-10-own-ssh-client-design.md`. All paths below are under `src-tauri/src/` unless they start
with `src/` (frontend), `relay/`, `.github/` or `docs/`.

**Handoff note (2026-10-14):** The original scout observed `.superpowers/` as untracked. At handoff, `git check-ignore -v`
reports `.git/info/exclude:8:.superpowers/`. This copy preserves the report in tracked documentation; the session workspace stays excluded.

## 0. Answers first (what will shape the plan most)

1. **0.17 does not just "go read-only" on 1.0 data; it also drops and deletes.** In read-only mode 0.17 still pulls and applies
   (`sync/round.rs:622-665`; only uploads stop, `:717-719`). It skips a space-chain host record whose payload is not
   `HostPayload{schema,text}` but still advances the cursor (`sync/merge.rs:156-162`, `:235`), skips a `keyslot` that fails
   `valid_slot_payload` (schema must be 1, `sync/slot_rules.rs:294`) and advances that cursor too (`sync/merge.rs:617-623`, `:677`),
   and it **applies tombstones** of host records as file deletions (`sync/merge.rs:145-152`). So (a) if 1.0 tombstones the old
   alias-keyed host records, every 0.17 computer deletes those hosts from its space files while it waits to be updated; (b) a 0.17
   computer that later updates to 1.0 has already moved its cursors past every schema-2 record it skipped and will never see them
   unless 1.0 re-pulls from seq 0. The SP3 "upgrade sealed unknown kinds" trick (`sync/merge.rs:571-600`) only rescues unknown
   *kinds*, not known kinds with unreadable payloads.
2. **The record layer is welded to the file layer.** `round.rs` steps 1–3 and 6, `account.rs` (create/join require a loaded ssh
   config, `sync/account.rs:83-89,208,278`), `spaces.rs`, `rotation.rs`, `dto.rs`, `engine.rs` and even `runtime::mutate` (takes
   the config `doc` lock first, `sync/runtime.rs:128-129`) import `files`/`hosts_file`/`space_files`/`slots`/`config`. "Delete the
   file layers" means rewriting most of `sync/` (~5,800 production lines of round/account/spaces/rotation/merge/dto/engine), not
   deleting a leaf. The Keychain's key operations (paste, file, generate, export, delete, sync key) all live in the to-be-deleted
   `slots.rs`/`local_keys.rs`/`slot_setup.rs` and must be re-implemented on keyslot schema 2 + vault before those files go.
3. **A 1c dev build would work on the user's real data.** App data is `dirs::data_local_dir()/org.homelab.sshelter` hard-coded
   (`fsutil.rs:12-16`), the keychain service is the constant `"SSHelter"` (`secrets.rs:9`), there is no env/feature override, and
   debug builds skip the single-instance plugin so they run next to the installed app (`lib.rs:137-144`). If the installed app is
   not running, a dev build takes the sync lock (`sync/engine.rs:371-378`), uses the stored real relay URL (`sync/state_v2.rs:35`;
   the debug relay default only applies to a fresh state, `sync/state.rs:21-34`), and would write schema 3 to the real account and
   move real `host:<alias>` keychain entries. The CLI finds the socket through the same `app_data_root()` (`cli/mod.rs:132`) and is
   launched by Terminal/iTerm without the app's environment, so an env-var override alone would not reach it.
4. **There is no `local` section today.** `SyncStateV2` (`sync/state_v2.rs:29-63`) has `account`, `spaces`, `key_slots`, notices,
   etc. "Only on this computer" keys are `key_slots` entries with `local_only: true` (`:254-257`) plus a vault entry under the same
   32-hex slot id. Hosts without an account exist only in `~/.ssh/config`. The local store of spec §5.4 is new, and so is the
   question of what a state file with it does under 0.17: serde ignores unknown fields (no `deny_unknown_fields` anywhere), so a
   `version: 2` file with extra sections is read by 0.17 and the extras are silently dropped on its next save; only a version bump
   makes 0.17 set the file aside (`sync/state_v2.rs:533-535`, `sync/engine.rs:241-268`) and start fresh, as spec §9 describes.
5. **Deleting `config/` breaks the whole host UI and several kept backends.** The frontend calls 98 of the 100 registered commands
   (`config_list_files` and `keys_agent_status` are unused); 25 of the 100 are `config_*`/`discover_hosts`. MCP (`list_hosts`,
   `get_effective_config`, `run`), the tray, `connect::validate_alias`, deploy, keys and the broker's adapter all read the config
   doc. The one-time import (§9) needs a read-only ssh_config reader, which `config/{lexer,parser,model,include}` already are
   (1,008 lines incl. tests); the import must skip SSHelter's own Includes (space files, agent config), or synced hosts come back
   as duplicates.

Other plan-shaping facts: stable is still **0.16.0 with sync state v1** (`git ls-remote --tags`: v0.16.0, then only
v0.17.0-1…-11 betas), so 1.0 can meet v1, v2 or no state; CI runs **no** `config::` tests, no `sync::` tests except `sync::slot_rules`/
`sync::slot_files` on Windows, and **no** frontend tests (§12);
`cargo test` rewrites the 68 committed ts-rs bindings in `src/bindings/` (§13).

## 1. The record store today

### 1.1 Record model (`sync/record.rs`)
- `SCHEMA_VERSION = 1` (payload `schema` of host/device/space/spacekey, `:10-11`); `ACCOUNT_SCHEMA_VERSION = 2` (`:12-13`);
  account meta id `"account"` (`:15`); rotation markers `meta` `rotation:<device>` (`:16-17`, `:256-272`).
- `RecordKind` = host, key, password, device, meta, space, spacekey, keyslot (`:22-65`); secret kinds = key, password, spacekey
  (`:67-71`), never stored in plaintext (`sync/state_v2.rs:550-565`).
- `Record{kind,id,version,updated_at_ms,device_id,deleted,payload: Value}` (`:75-84`); `record_key(kind,id) = "kind:id"` (`:115-117`).
- LWW `merge()` (`:127-149`): later `updated_at_ms` wins; tie → tombstone wins, then lexically smaller `device_id`; a newer remote
  over a dirty local is `RemoteWinsOverDirtyLocal` (reported as a conflict).
- Payloads: `HostPayload{schema,text}` = the whole Host block text (`:164-169`); `DevicePayload{schema,name,platform,joined_at_ms,
  last_seen_ms,keys,spaces,slots}` (`:171-188`; `slots: Vec<DeviceSlot{slot_id,fingerprint,synced_copy,in_vault}>`,
  `sync/slot_rules.rs:69-77`: **no file names**, contrary to spec §5.3's "不再列插槽檔名"); `MetaPayload{schema_version,
  created_by_app_version}` (`:190-201`); `SpacePayload` (`:203-215`, space0 deterministic `:217-228`); `SpaceKeyPayload` (`:230-254`).
- `keyslot` = `KeySlotPayload{schema:1,name,mode: synced|own,origin_device_id,created_at_ms,public_key?,fingerprint?,key_type?,
  has_passphrase?}` (`sync/slot_rules.rs:26-49`; `Own` ⇒ the four key fields are None, `Synced` ⇒ all set, `:293-308`). `key` =
  sealed `KeyPayload{schema:1,private_key}` (`:51-56`), ≤ 16 KiB (`:17`, `:311-313`). Slot ids are 32 lowercase hex (`:79-87`).
- Encoding: whole record JSON sealed; relay row keyed by `id_hash = HMAC(enc_key, kind+"\n"+id)` (`sync/reconcile.rs:24-50`,
  `sync/crypto.rs:136-144`). Same id ⇒ same relay row.

### 1.2 Account chain vs space chains
- Account chain: device, meta, space, spacekey, keyslot (plaintext in `AccountState.records`), key and spacekey sealed in
  `AccountState.sealed`, unknown kinds kept sealed and never decrypted (`sync/state_v2.rs:105-130`, `sync/merge.rs:603-616`).
  Validation per kind in `valid_account_record` (`sync/merge.rs:520-561`).
- Space chain: **only `host` records**, id = **alias** (`sync/planner.rs:45-54`: `id: block.alias`, payload `HostPayload{schema:1,
  text}`), cached in `SpaceState.records` keyed `host:<alias>` (`sync/state_v2.rs:285-287`); `pending_approvals` and `declined`
  keyed by alias (`:288-297`). A rename is tombstone + new record. Pipeline: space file blocks → `planner::detect_local_changes`
  → `merge::plan_hosts`; remote → `merge::merge_space` (kind/alias filter `:126-131`, text validation and risky-directive approval
  `:156-205`) → `reconcile::HostEffect{Upsert,Delete}` → `files::apply_and_commit_space` writes `~/.ssh/sshelter/<slug>-<id8>.config`.
- Default space on create is "Personal" (`sync/account.rs:26`, `:235`); v1 upgrades get space0 "Synced" (`sync/record.rs:18-20`).

### 1.3 Local state (`sync/state_v2.rs`, `<app data>/sync-state.json`, 0600, atomic)
- `STATE_VERSION_V2 = 2` (`:23`); fields `:29-63`: `device_id`, `device_name`, `relay_url`, `account`, `spaces` (only selected
  spaces), `rotation`, `legacy_v1_backup`, `relay_features`, `phrase_cleanup_pending`, `last_sync_ms`, `last_error`, `key_slots`,
  `notices` (unknown notice kinds are skipped on read, `:369-374`).
- `LocalSlot` (`:202-258`): `file_name` (`<name>-<id8>`), `source: Option<SlotSource>`, `payload` (last seen keyslot), consent/
  provenance flags (`uploaded_fingerprint`, `learned_in`, `copy_from_another_account`), `parked`, `local_only`.
  `SlotSource` (`:261-271`) = `Linked{path,link,fingerprint,origin}` | `SyncedCopy{fingerprint}` | `Vault{fingerprint,public_key,
  has_passphrase}`. `key_slots` survives leaving an account (`:56`).
- `load()` (`:524-538`): version 1 → `Legacy` (v1 upgrade path), 2 → current, >2 → "written by a newer SSHelter" error, which
  `engine::unreadable_state_outcome` turns into a rename to `sync-state.unreadable-<ms>.json` + fresh state (`sync/engine.rs:241-268`,
  `:288-328`). A fresh state has no account (the keychain still holds `sync:mnemonic`).
- Writes go through `SyncCore` (`sync/runtime.rs:36-63`): `commit` (generation check, `:113-125`), `mutate` (takes `env.doc` then
  core, bumps generation, `:128-143`), `save_core` refuses while `save_blocked` (second process) or a v1 upgrade is pending (`:91-104`).

### 1.4 The `schema_version` gate
- `merge_account` records `remote_schema_version` from meta `"account"` (`sync/merge.rs:653-658`); `read_only()` = remote >
  `ACCOUNT_SCHEMA_VERSION` (`sync/state_v2.rs:91-97`). Read-only: no uploads (`sync/round.rs:540`, `:717-719`), status
  `READ_ONLY_MESSAGE` "this sync account uses a newer format; update SSHelter to keep syncing" (`sync/account.rs:34`,
  `sync/round.rs:994-1006`), structure-changing actions refused (`sync/account.rs:93-110`). Pull/merge/apply continue (see §0.1).
- The meta record is written only at create (`sync/account.rs:226-233`), v1 upgrade (`sync/upgrade.rs:446`) and rotation copy
  (`sync/rotation.rs:545`), always with the compile-time constant. Nothing today bumps an existing account's meta: 1c adds that.

### 1.5 Key rotation `copy()` (`sync/rotation.rs:448-590`)
- Space chains: every decodable `Host` record is re-encrypted for the new chain with id/version/timestamps/tombstone kept
  (`:512-527`, filter `:520`); the payload is opaque, so schema-2 hosts pass as they are.
- Account: new meta with the current `ACCOUNT_SCHEMA_VERSION` (`:539-547`), `space` with `previous_id`, this device's `device`,
  `keyslot` records copied as-is from `old.records` (`:571-576`), `key` re-sealed (`:577-581`). `old` comes from
  `merge_account` (`old_account_snapshot`, `:439-441`), which drops keyslots failing `valid_slot_payload`: **schema-2 keyslots are
  dropped by today's validator** until it accepts them.
- Rejoin after rotation keeps selection/file names/approvals by `previous_id` (module doc `:1-6`) — file-name parts go too.

### 1.6 What carrying §5.1 records touches (facts, not a design)
`HostPayload` (text) is parsed in `planner.rs:20,51,94`, `merge.rs:156,254`, `upgrade.rs:479,725`, `slots.rs:384,4671`.
Alias keys: `SpaceState.records/pending_approvals/declined`, `PendingApproval.text` + `ApprovalSignature` (text-based approval,
`sync/approval.rs:10-50`: 24 gated directives, none of which exist in schema 2), `HostEffect` (alias+text), `dto::SyncSpaceView`
(`file_name`, `file_path`, `sync/dto.rs:99-125`), `SyncOverview.stray_files` and `key_slots` (`sync/dto.rs:269-301`).
`valid_slot_payload` hard-codes schema 1 (`sync/slot_rules.rs:294`). `ACCOUNT_SCHEMA_VERSION` (`sync/record.rs:13`).

## 2. The relay (`relay/src/index.ts`, 522 lines, v0.2.0)
- Schema-agnostic: stores `kind`, `idHash`, `nonce`, `ciphertext`, `deleted`, `seq` (`:64-80`). Push validation: `idHash` 64 hex,
  **`kind` must match `/^[a-z]{1,16}$/`** (letters only: a new kind like `host2` would be rejected; `:345-355`), nonce ≤ 64,
  strict base64.
- Sizes: one record's ciphertext ≤ 65,536 base64 chars (`:3`, `:514`); a chain ≤ 1 MiB of ciphertext+nonce **including
  tombstones** and ≤ 4096 rows (`:4-5`, `:224-235`, 413); a push ≤ 200 items and ≤ 1 MiB body (`:6-7`, `:501-512`). Client batches at
  200 items / 512 KiB (`sync/merge.rs:24-26`). Rate limits: 120 requests/min per chain (`:18`), per IP per hour create 20,
  request 1200, pull 12000 (`:278`).
- 1c hits: tombstoning N old host records keeps N rows on the chain; `imported.unsupported` raw text must stay well under ~48 KiB
  plaintext per host; no relay change is needed for new payloads.

## 3. The old model's modules: size, dependents, commands

Lines incl. tests (`wc -l`); "prod" = lines before the `#[cfg(test)] mod tests`; tests = macOS `--list` count.

| Module | Lines (prod) | Tests | Tauri commands | Production dependents outside the module |
|---|---|---|---|---|
| `config/commands.rs` | 2467 (1272) | 51 | 21: `config_load`, `config_list_files` (unused), `config_plan_new_file`, `config_create_file`, `config_get_host`, `config_save_host`, `config_set_identity_file`, `config_add_host`, `config_remove_host`, `config_rename_host`, `config_move_host`, `config_duplicate_host`, `config_read_file`, `config_set_option_enabled`, `config_set_tags`, `config_reorder_hosts`, `config_set_backup_retention`, `config_check_drift`, `discover_hosts`, `config_list_backups`, `config_restore_backup` (`:688-1217`) | `persist_file`: agent::wiring, sync::{account, files, local_keys, migrate, slot_setup, spaces, testkit, upgrade}; `load_doc_migrated`: sync::{env, migrate}; `default_config_path`: deploy; `drift`/`move_host`/`validate_host_patterns`: sync::{local_keys, migrate} |
| `config/intel.rs` | 875 (452) | 24 | `config_effective`, `config_lint`, `config_jump_chain`, `config_key_hygiene` (`:400-450`) | `effective_config` (`ssh -G`, `:27`): deploy, mcp |
| `config/dto.rs` | 269 (153) | 7 | – | `host_summaries`: mcp; `parse_tags` (`#tags:` sentinel, `:135-150`): sync::migrate |
| `config/edit.rs` | 898 (327) | 20 | – | sync::migrate |
| `config/include.rs` | 365 (169) | 7 | – | `load_doc`: session::app; `with_test_home`: sync::env; `find_host_file_index`: sync::migrate. It calls `agent::wiring::is_agent_include_token` (`:87`) |
| `config/lexer.rs`, `parser.rs`, `model.rs`, `serialize.rs`, `newfile.rs`, `mod.rs` | 295, 256, 92, 66, 348, 10 | 10, 6, 0, 0, 14, 0 | – | `model` everywhere (31 files); `parser`: agent::wiring, sync::{approval, hosts_file, slots, testkit, upgrade}; `serialize`: sync::{files, hosts_file, upgrade} |
| **`config/` total** | **5941** | **139** | 25 | |
| `agent/` (8 files) | 4154 | 107 | `agent_pending`, `agent_resolve` (`agent/prompt.rs:216-221`), `agent_problem`, `agent_fix_include` (`agent/mod.rs:234-244`) | `lib.rs:26-27,182,190-195`; `state.rs:23` (`AgentRuntime`); `config/include.rs:87`; `sync/engine.rs:174` + `sync/round.rs:282` + `sync/slots.rs:1660` (`wiring::refresh_env`); `sync/hosts_file.rs:49` (`is_agent_include`); `sync/slots.rs:1912` (`passphrase_account`) |
| `sync/slots.rs` | 8226 (2078) | 217 | via engine: `sync_key_set_mode`, `_pick`, `_use_synced`, `_delete_copy` (also "Delete key…"), `_set_delivery`, `_move_all_into_vault`, `_export_private` (`sync/engine.rs:646-697`) | sync::{round (`:301-302,697-698`), dto (`:413-414` views), local_keys, slot_setup}, config::intel (`account_slot_files`), agent (`vault_slot_files`) |
| `sync/slot_setup.rs` | 3151 (1054) | 80 | `sync_key_candidates`, `sync_setup_keys` (`sync/engine.rs:634-642`) | engine |
| `sync/local_keys.rs` | 2169 (870) | 66 | `sync_key_import_text`, `_import_file`, `_preview_file`, `_generate` (`sync/engine.rs:703-750`) | engine |
| `sync/migrate.rs` | 1399 (628) | 31 | `sync_duplicate_aliases`, `sync_resolve_shadowed` (`:303-317`); via engine `sync_move_hosts_to_space`, `sync_move_files_to_new_spaces`, `sync_unmovable_hosts` (`sync/engine.rs:607-630`) | config::commands (`:708,1027,1032`) |
| `sync/upgrade.rs` (v1→v2) | 1827 (668) | 46 | – | engine (`shell_state`), round (`:217` `upgrade_v1`), account (`back_up_first`, `:401`) |
| `sync/hosts_file.rs` | 1762 (695) | 34 | – | files, merge, planner, account, dto, approval, upgrade, migrate, slots |
| `sync/space_files.rs` | 733 (408) | 12 | – | account, spaces, rotation, files, merge, dto |
| `sync/files.rs` | 1107 (482) | 25 | – | round, spaces, account, dto, engine (`note_written`) |
| `sync/merge.rs` | 1636 (858) | 27 | – | round, account, spaces, rotation, dto (account half stays; space half is text) |
| `sync/slot_rules.rs` | 933 (338) | 14 | – | pure; **keep most**: `inspect_private_key`/`KeyFacts` (vault, local_keys), payload types and validators, `resolve_identity_value` (import), `test_keys` (`:340`, used by ssh/vault/session tests) |
| `sync/slot_files.rs` (+`slot_files_windows.rs` 136, Windows-only) | 281 (146) | 4 | – | **`vault/store.rs:385` (`write_private`)**, **`ipc/server.rs:35` (`ensure_keys_dir`)**, agent::wiring, state_v2 (`LinkKind`), slots, slot_setup, local_keys |
| `sync/planner.rs`, `reconcile.rs` (HostEffect), `approval.rs` | 186, 82, 525 | 7, 1, 20 | – | merge, files, spaces, dto, state_v2 (`ApprovalSignature`) |
| `keys.rs` | 706 (401) | 19 | `keys_list` (`ssh-add -l`, `ssh-keygen -l`, hosts from doc), `keys_git_ssh_hint`, `keys_agent_status` (unused), `keys_read_public`, `keys_deploy` (`ssh-copy-id` in a terminal, `:391-396`) | `ssh_dir()` (`:56-60`): agent/mod.rs (3), config/commands.rs (2), deploy.rs, session/app.rs (2), sync/engine.rs (2), sync/migrate.rs; `validate_public_path`: deploy |
| `deploy.rs` | 1476 (830) | 49 | `deploy_preflight`, `deploy_precheck_host_key`, `deploy_trust_host_key`, `deploy_key`, **`secrets_has/get/set/delete`** (`:812-829`, the HostEditor's password UI) | none (lib.rs only) |
| `askpass.rs` | 313 (142) | 14 | – | `main.rs:7-9` (`SSHELTER_ASKPASS`); spawned by deploy (`deploy.rs:507-511`) |
| `connect.rs` | 924 (459) | 36 | `connect_list_terminals`, `connect_launch` (`:424-458`) | `validate_alias(doc,…)` (`:60-70`): config::intel, deploy, keys, mcp, session::ssh_config_directory, tray. Launch code (`connect_argv` `:364-372`, `launch_for` `:408-413`) is already the new model |
| `mcp.rs` | 1373 (1289) | 9 | `mcp_status`, `mcp_set_enabled`, `mcp_set_host_allowed`, `mcp_resolve_request` (`:902-990`) | lib.rs, main.rs (`run_stdio`), state.rs |
| `session/ssh_config_directory.rs` | 1118 (347) | 28 | – | session::app (`:17,92-112`); **session::testing (`MAX_JUMPS`, `:15`)** |
| `session/ssh_g.rs` | 481 (227) | 7 | – | session::app (`:102`) |
| `session/pins.rs` | 262 (143) | 6 | – | session::app (`:94`), ssh_config_directory |
| `known_hosts.rs`, `discover.rs` (not in the spec) | 507, 524 | 15, 15 | `known_hosts_list`, `known_hosts_remove`; `discover_hosts` | deploy (`append_known_hosts_line` writes `~/.ssh/known_hosts`, `:725`), discover |
| `tray.rs` | 195 | 3 | `tray_set_visible` | `tray_aliases(doc)` (`:15`) from config::commands and sync::engine |

`session/directory.rs` (146 lines, the `HostDirectory` trait `:45-78`, `PinDecision` `:84-112`) is the seam that stays;
`session/testing.rs:506` `check_the_pin_contract` checks any directory implementation.

## 4. Frontend

### 4.1 Commands invoked, by area (`src/lib/ipc.ts` `tauriInvoke`; call sites)
- Hosts/config (23): `config_load` (`src/lib/queries.ts:84`, path from settings `configPath`), `config_get_host` 147,
  `config_save_host` 161, `config_add_host` 179, `config_remove_host` 191, `config_rename_host` 213, `config_move_host` 234,
  `config_duplicate_host` 259, `config_plan_new_file` 283, `config_create_file` 291, `config_read_file` 303, `config_set_tags` 313,
  `config_set_option_enabled` 337, `config_reorder_hosts` 370, `config_check_drift` 447, `config_key_hygiene` 461,
  `config_effective` 478, `config_jump_chain` 492, `config_lint` 507, `config_list_backups` 538, `config_restore_backup` 813,
  `config_set_identity_file` 755, `config_set_backup_retention` (`src/lib/backend-settings.ts:24`, SettingsDialog 614).
- Discover/known_hosts: `discover_hosts` (queries 522), `known_hosts_list` 568, `known_hosts_remove` 587.
- Keys/keychain: `keys_list` 553, `keys_read_public` 729, `keys_git_ssh_hint` 742, `keys_deploy` 606; `sync_key_*` 13 commands
  (`src/lib/sync.ts:376-464`): candidates, setup_keys, set_mode, pick, use_synced, delete_copy, set_delivery, move_all_into_vault,
  export_private, import_text, import_file, preview_file, generate.
- Sync (28): `src/lib/sync.ts:77-497` (overview, now, create/join/leave/rejoin, words, relay url/check, device name/forget,
  spaces create/rename/delete/select/unselect/rebuild, approvals pending/approve/reject, dismiss notice, change/cancel code,
  move hosts/files to spaces, unmovable, duplicate aliases, resolve shadowed).
- Connect: `connect_list_terminals` (queries 405), `connect_launch` 422 (records `recentConnections` by alias, 431).
- Deploy/passwords: `deploy_preflight` 715, `deploy_precheck_host_key` 668, `deploy_trust_host_key` 682, `deploy_key` 696,
  `secrets_has/get/set/delete` 620/633/643/655 (keyed by alias).
- MCP: `mcp_status/set_enabled/set_host_allowed/resolve_request` (`src/lib/mcp.ts:16-46`).
- Agent: `agent_pending/resolve/problem/fix_include` (`src/lib/agent.ts:20-160`). Host key: `hostkey_pending/resolve`
  (`src/lib/hostkey.ts:17-21`). App/updater: `app_platform`, `app_set_close_to_tray`, `tray_set_visible`, `settings_export/import`,
  `updater_check_beta/install_beta`.
- Events: `sync://status|applied|conflict|approval|notice` (`sync/engine.rs:95-120`), `mcp://approval-requested`
  (`mcp.rs:690`), `agent://approvals` (`src/lib/agent.ts:17`), `hostkey://requests` (`src/lib/hostkey.ts:14`).
- Window labels: `approval` (agent) and `hostkey` share the page (`src/main.tsx:26-30`); capability files
  `src-tauri/capabilities/{default,approval,hostkey}.json`.

### 4.2 ssh_config semantics in components and stores
- Identity = alias + source file: `HostSummary{alias,patterns,source_file,tags,hostname,user}`, `HostDetail{…,options}`,
  `LoadResult{files,hosts}` (`src/bindings/*.ts`); query keys by alias/path (`src/lib/queries.ts:36-52`); ui store
  `selectedAlias`, `selectedFile`, `collapsedGroups` (file paths), `fileScope`, `groupMode: "file"|"tag"`, `addHostTargetFile`,
  `newFileIntent`, `deployKeyAlias` (`src/stores/ui.ts:34-104`).
- Include/space-file wording and shadowing: `HostList.tsx`, `DuplicateCopies.tsx`, `ShadowFixDialog.tsx`, `src/lib/sync-sidebar.ts`
  (`shadowedCopies`, `ambiguousNames`, `spaceFileLabels`), `src/lib/sync-labels.ts`, `SyncMigrationDialog.tsx`,
  `NewConfigFileDialog.tsx`, `KeychainBanners.tsx` (agent Include missing → Fix).
- Drift/reload: `DriftBanner.tsx`, toolbar reload in `App.tsx`, `CommandPalette.tsx`. Lint: `LintDialog.tsx`, `HostEditor.tsx`,
  `settings-logic.ts` `LINT_RULES`. Move to file: `HostList`/`HostEditor` (`useMoveHost`), `NewConfigFileDialog`.
  Backups: `BackupHistoryDialog.tsx`. ssh -G intelligence: `HostIntelligence.tsx`. IdentityFile: `src/lib/identity-file.ts`,
  `hostFields.ts` (the 18 editor fields `:20-68`), `key-slots.ts`, `keychain/AddHostForKeyDialog.tsx` (`useAddHost`),
  `SyncKeyDialog.tsx`. "Other key files in ~/.ssh": `src/lib/keychain.ts:91-99`.
- Sizes (lines): HostList 1712, HostEditor 1464, SettingsDialog 980, queries.ts 822, SyncPane 790, sync-approvals.ts 700,
  DeployKeyDialog 617, sync.ts 498, SyncSpacesSection 468, NewKey 441, SyncApprovalDialog 427, KeyDetail 424, keychain/dialogs 357,
  SyncMigrationDialog 342, sync-sidebar.ts 323, App.tsx 312, CommandPalette 310. By area (prod/test lines): hosts/config UI
  6969/2001, sync 4448/3112, keys/keychain 2839/2595, settings+updater+shell 2451/835, deploy 617/0, discover+known_hosts 398/0,
  agent 326/408, hostkey 205/159, MCP 170/0. Total `src/` (excluding bindings) 29,972 lines.

## 5. MCP (`mcp.rs`)
- Tools (`:1127-1160`): `list_hosts` = `config::dto::host_summaries(doc)` filtered by `allowed_hosts` (`:518-525`);
  `get_effective_config` = `ssh -G [-F main]` filtered to hostname/user/port/proxyjump/identitiesonly (`:526-544`); `run` =
  `run_approved` (`:600-796`): `validate_alias(doc)`, `ssh -G` to refuse ProxyCommand/KnownHostsCommand/PermitLocalCommand,
  approval window (120 s), then **system `ssh -F <main> -o BatchMode=yes … <alias> <cmd>`** (`execute_ssh`, `:815-850`).
- Every tool waits up to 5 s for the window's loaded doc (`wait_for_loaded_doc`, `:560-571`). `mcp_set_host_allowed` validates
  the alias against the doc (`:926-935`). Policy `mcp-policy.json` = `{enabled, allowed_hosts: aliases}` (`:38-43`, `:247-249`).
  Audit/pending entries carry `alias` (`:52-77`). The bridge is still loopback TCP + `mcp-runtime.json` (`:251-253`).
- Without `config/`: all three tools and `mcp_set_host_allowed` stop compiling; `run` cannot work from records at all with system
  ssh (it needs the user's ssh_config to know the host). The broker refuses `exec` until phase 2 (`session/protocol.rs:182-184`).

## 6. Deploy (in-app public-key deploy)
- Uses: `config::intel::effective_config` (`ssh -G`) for the endpoint (`deploy.rs:480-495`), `config::commands::default_config_path`
  (`:447-466`), `ssh-keyscan` + `ssh-keygen -F` against `~/.ssh/known_hosts` (`:673-704`), appends to `~/.ssh/known_hosts` on trust
  (`:706-734`, `:725`), the public key from a `~/.ssh/*.pub` path (`keys::validate_public_path`, `:765-766`), system `ssh` with
  `SSH_ASKPASS=<sshelter exe>` + `SSHELTER_ASKPASS=1` + keychain account `deploy-tmp:<alias>` (`:498-560`, `:778-782`), saves
  `host:<alias>` when remembered (`:806`); `ssh -V` for askpass support (`:469-471`, `:598-623`).
- A records world would need: endpoint from the record; host-key check against the record's pin (not known_hosts); transport
  over the own engine — `Session::exec(command, timeout, output_cap)` has **no stdin** (`ssh/traits.rs:46`) while
  `REMOTE_SCRIPT` reads the key from stdin (`deploy.rs:26-38`), and the broker has no exec yet; the public key from the vault
  keyslot; passwords from `host:<id>` or a prompt. `keys_deploy` (`ssh-copy-id`) and askpass become dead.

## 7. Vault and keys
- `vault.json` beside `sync-state.json` (`vault/store.rs:23`, `:41-44`), format v2 with its key in keychain `vault:key:<16 hex>`
  (legacy `vault:key`) (`:24-38`, `:184-189`, `:354-376`). Entries keyed by **slot id** (AAD includes it, `:176-178`, `:277-285`);
  replaced keys kept as `retired:<slot id>:<ms>` (`:31-33`, `:296-332`). `VaultEntry{private_key,public_key,fingerprint,origin,
  added_at_ms}` (`:63-70`); `EntryOrigin{Generated,Imported,Synced}` (`:55-59`). The header also holds `AgentSettings
  {remember_minutes, always_ask}` (`:93-98`, agent-only). Unreadable/keyless files are set aside (`:213-270`). Writes:
  `slot_files::write_private` (`:385`) under `SyncRuntime.vault` (`:399-409`).
- How keys enter today: paste → `local_keys::import_text` (`sync/local_keys.rs:329-337`); file → `import_file(keep_file)`
  (`:410-412`; without keep_file it rewrites `IdentityFile` lines and **removes the user's key file**, `:442-480`, `:473`);
  generate → `vault::generate` + `add_key(Generated)` (`:500-512`); all via `add_key_from` (`:191-281`): vault put (`:221`),
  `.pub` written into `~/.ssh/sshelter/keys/` (`:228`), `LocalSlot{local_only: true, source: Vault, payload: keyslot schema 1
  mode Own}` (`:232-264`). Refused keys: `slots::agent_refusal` (`sync/slots.rs:1919-1930`, uses `vault::material`). Synced keys
  land into the vault with origin Synced (`sync/slots.rs:1021`, `:1766`).
- Slot → vault mapping: `key_slots[id].source == SlotSource::Vault` + vault entry `id`. The broker's `KeyStore` uses exactly that
  (`session/app.rs:38-45`, `:68-90`); the 1b adapter maps a host's first `IdentityFile` to such a slot (`vault_slot_of`,
  `session/ssh_config_directory.rs:198-209`). The agent serves all `SlotSource::Vault` slots (`agent/broker.rs:44-64`) to system
  ssh via `~/.ssh/sshelter/agent/config` (per-host `IdentityAgent`, `agent/wiring.rs:1-4`, `:17`).
- Passphrases are remembered as keychain `vault:passphrase:<slot id>` (`agent/broker.rs:28-30`; the broker's twin
  `session/auth.rs:34`, pinned equal by the test at `:444`; a stale one is deleted, `:236-242`).

## 8. Passwords
- Keychain service `SSHelter`, account `host:<alias>` (`secrets.rs:9-14`); temporary `deploy-tmp:<alias>` (`:17-19`).
- Read: `secrets_has/get` (`deploy.rs:812-819`), the broker via `HostDirectory::password_account` → `host:<alias>`
  (`session/ssh_config_directory.rs:342-345`, used at `session/auth.rs:314`) and `password_saved` (`session/app.rs:109`).
  Written: `secrets_set` (`deploy.rs:822-824`), `deploy_key` remember (`:806`). Deleted: `secrets_delete` (`:827-829`).
- Rename: `config_rename_host` touches no keychain entry, and the frontend's `useRenameHost` neither (`src/lib/queries.ts:205-224`):
  a rename orphans the password; per-host terminal and recent connections (alias-keyed, §10) are orphaned too.

## 9. App data, dev builds, test isolation
- App data `dirs::data_local_dir()/org.homelab.sshelter` (`fsutil.rs:12-16`; dirs 5.0.1: macOS Application Support, Windows
  LocalAppData, Linux XDG data). Config backups use `dirs::data_dir()` (Roaming on Windows) with a temp root in tests
  (`fsutil.rs:75-96`). Files there: `sync-state.json` (+`.v1-backup`, `.unreadable-*`), `vault.json`, `sync.lock`, `host-pins.json`
  (`session/app.rs:94`), `mcp-policy.json`, `mcp-runtime.json`, `mcp-spawn.lock` (`host_start.rs:116`), `ipc/{lock,sock}`.
- Same dir, same keychain service and same `~/.ssh` for debug and release; the tauri identifier is only re-typed in `fsutil.rs:15`
  (`tauri.conf.json:5`). Second-process guards: sync lock → `save_blocked`, state shown read-only (`sync/engine.rs:340-392`);
  broker lock → `OtherInstance` (`session/app.rs:24-33`, `:162-166`); agent lock likewise. Nothing else (config writes, vault via
  key import is blocked by `save_blocked`, MCP runtime file) is guarded. The 1b design brief already called this out
  (`docs/superpowers/plans/2026-10-12-own-ssh-phase1b-design-brief.md:10`, R1).
- Frontend settings live in WebView localStorage `sshelter-settings` (`src/stores/settings.ts:15`); a dev build loads from
  `http://localhost:1420` (`tauri.conf.json` `devUrl`), a different origin from the bundled app.
- Tests: the sync engine takes `SyncEnv` (`sync/env.rs:87-105`) with temp home, `MemKeychain`, `FakeRelay`, `TestClock`
  (`sync/testkit.rs:1-4`); `SyncEnv.home` redirects Include `~` (`sync/env.rs:97-98`, `:120-127`). Two tests touch the real
  keychain and are skipped in whole-suite runs: `secrets::tests::round_trip_set_get_delete`, `askpass::tests::
  env_secret_takes_priority_over_keychain` (earlier plans pass `--skip` for both). No test calls `app_data_root()`.

## 10. Settings
- Per machine, frontend only (`src/stores/settings.ts:49-130`): theme, `terminalId`, `hostTerminals` (alias → terminal),
  `fontSize`, `showHostTags` ("file grouping only"), `recentConnections` (alias → ms), update checks/channel, tray, close-to-tray,
  global hotkey, `newTabConnect`, `configPath`, `backupRetention`, `discoverKnownHosts`, `discoverTailscale`, `driftAutoCheck`,
  `driftIntervalSec`, `lintRules`, `fileAliases`. Tray/close/retention are re-pushed to the backend each launch
  (`src/lib/backend-settings.ts:13-35`). Settings panes: General, Appearance, Connection, Files & Backups, AI Access, Sync (Beta),
  Advanced (`src/components/SettingsDialog.tsx:86-99`).
- Meaningless without ssh_config: `configPath`, `backupRetention` (+`config_set_backup_retention`), `drift*`, `lintRules`,
  `fileAliases`, file grouping (`groupMode: "file"`, `collapsedGroups`, `fileScope`), and the discovery sources if Discover goes.
  Need re-keying: `hostTerminals`, `recentConnections` (alias). Spec §5.4's "keepalive 預設" setting does not exist yet.
  Backend: `vault.json` `AgentSettings` (agent-only), `mcp-policy.json` (alias allow-list).

## 11. Tests

### 11.1 Counts (`cargo test --lib -- --list`, macOS, 2004 total)
sync 848 (slots 217, slot_setup 80, local_keys 66, round 54, rotation 47, upgrade 46, hosts_file 34, migrate 31, account 30,
merge 27, files 25, spaces 23, approval 20, dto 20, relay 19, record 17, state_v2 17, crypto 14, engine 14, slot_rules 14,
space_files 12, planner 7, slot_files 4, runtime 4, state 4, fake_relay 1, reconcile 1) · ssh 215 · session 213 (connect 43,
broker 42, ssh_config_directory 28, relay 25, auth 22, hostkey_window 13, protocol 11, testing 10, ssh_g 7, pins 6, app 4,
directory 2) · cli 174 · config 139 (commands 51, intel 24, edit 20, newfile 14, lexer 10, dto 7, include 7, parser 6) ·
agent 107 · vault 66 · deploy 49 · connect 36 · ipc 35 · keys 19 · fsutil 16 · known_hosts 15 · discover 15 · askpass 14 ·
host_start 10 · mcp 9 · updater_channel 6 · lib tests 4 · tray/settings_io/secrets/error 3 each · process 2.
68 of them are ts-rs `export_bindings_*` (19 in `sync::dto`).

### 11.2 Shared kits
- `sync::testkit` (cfg(test), `sync/mod.rs:62-63`): `TestDevice` is file-based (temp home with `.ssh/config`, `persist_file`,
  `parse_file`; `sync/testkit.rs:272-408`) and used by sync tests, `agent::wiring` and `config::intel` tests; `MemKeychain`
  (`:51-98`) is used by session (auth, broker, connect), cli (run, e2e, pipe), vault::store, agent tests. `sync::fake_relay::
  FakeRelay` (563 lines) is record-level already.
- `session::testing` (716 lines): `FakeDirectory` (`:142-276`), `FakeKeys`, `FakeOwner`, `FakeConfirmer`, gates,
  `check_the_pin_contract` (`:506`); imports `ssh_config_directory::MAX_JUMPS` (`:15`).
- `sync::slot_rules::test_keys` (`:340`) feeds ssh, vault and session tests. `ssh::testing` (harness, scratch sshd).
- Frontend: 50 test files, ≈795 static cases (plan 1b-2 recorded 845 run); kits `src/lib/test-ipc.ts` (`stubBackend`,
  `renderHook`), `src/lib/sync-fixtures.ts`, `src/lib/event-bus-fixture.ts`, `src/components/keychain/test-markup.ts`. By area:
  hosts/config ≈190 (HostList 13, sync-sidebar 41, identity-file 24, host-display 22, hostFields 14, …), keychain ≈213
  (NewKey 46, dialogs 23, keychain 23, key-slots 22, KeyDetail 20, deploy-key-select 16, …), sync ≈262 (sync-approvals 72,
  sync-overview 43, sync-migration 40, sync 28, sync-spaces 25, sync-events 20, SyncApprovalDialog 17, SyncPane 14, …),
  agent 46, hostkey 12, settings/updater ≈62.

## 12. CI (`.github/workflows/`)
- `test-engine.yml` (push to main/next/own-ssh and PRs, paths `src-tauri/**`): macOS and Linux run
  `cargo test --locked --lib -- ssh:: session:: cli:: host_start:: vault::` (`:57`, `:107`), Linux also the PAM container
  `ssh::engine_tests::login_methods::pam` (`:117`).
- `test-windows.yml` (same triggers): `sync::slot_rules sync::slot_files vault:: ipc:: agent:: ssh:: session:: cli:: connect::`
  (`:76`), `cargo build --locked` of the whole app, cli-helper tests, real-console and runner-sshd engine tests.
- `relay.yml` (relay paths, main): relay typecheck + tests. `beta.yml`/`release.yml`/`build-platform.yml`: build installers only
  (`tauri build` runs `pnpm build` = `tsc && vite build`). `windows-bundle-check.yml`: installers on next/own-ssh.
- Not covered anywhere: `sync::` (except slot_rules/slot_files on Windows), `config::`, `deploy`, `mcp`, `keys`, `known_hosts`,
  `discover`, `tray`, and **all frontend tests**. 1c's new code lands in `sync::` (or a new module): extend the filters or it is
  only tested locally. Deleting `agent::`/`sync::slot_files` silently shrinks the Windows job (a filter matching nothing passes);
  the owner-only DACL code (`slot_files_windows::restrict_to_owner`) is what vault/ipc use on Windows.

## 13. Other things a planner trips over
- **Cycles**: config ↔ connect (`config/intel.rs:408` → `connect::validate_alias`; connect → `config::model`); config ↔ agent
  (`config/include.rs:87`; `agent/wiring.rs` → config); config ↔ sync (`config/commands.rs:403,675,708,722,1027,1032` →
  `sync::engine`/`sync::migrate`); config → tray/discover/keys and back; sync ↔ agent; vault → sync (`vault/store.rs:18-21`:
  crypto, `env::Keychain`, `runtime::SyncRuntime`, `slot_files`); ipc → sync::slot_files; session → connect, config, keys, secrets,
  sync::{env, state_v2, slot_rules}.
- **Writers of `~/.ssh` today**: config edits/backups/restore/new files (`persist_file` `config/commands.rs:361-405`,
  `migrate_legacy_backups` on every load `:569`, `:661-667`), the sync Include line and space files
  (`sync/hosts_file.rs:47-94`, `sync/space_files.rs`, `~/.ssh/sshelter-local/` on leave), the agent Include (must stay first,
  token `~/.ssh/sshelter/agent/config`, `agent/wiring.rs:17`) and `agent/config`, the slot dir `~/.ssh/sshelter/keys/`
  (`sync/slot_rules.rs:15`; `.pub` files even for vault keys), key "Move" deleting the user's file (`sync/local_keys.rs:473`),
  `known_hosts` append/remove (`deploy.rs:725`, `known_hosts.rs`), the agent socket `~/.ssh/sshelter/agent/sock`.
  After 1c these stay on disk unmaintained (spec §9 accepts it); the agent config keeps `IdentityAgent` for vault-key hosts.
- **Import duplicates**: the loader follows top-level `Include`s (`config/include.rs:60-110`) and skips only the agent token
  (`:87`). SSHelter's own space files are Included from the top of `~/.ssh/config` (`sync/hosts_file.rs:24-26`,
  `is_our_include_token`), so a naive import re-imports every synced host. `hosts.config` (v1) and `~/.ssh/sshelter-local/` (left
  accounts) are other SSHelter-written sources. Relative Includes resolve against the including file's directory
  (`config/include.rs:93-99`) whereas OpenSSH resolves them against `~/.ssh` for user configs (`man ssh_config`, Include).
  Tags are a `#tags:` comment (`config/dto.rs:135-150`); disabled hosts are commented blocks.
- **Schema 2 has fields for 8 of the editor's 18 settings** (`src/lib/hostFields.ts:20-68`): hostname, user, port, IdentityFile→
  `key_id`, ProxyJump→`jump`, ServerAliveInterval/CountMax→keepalive, ConnectTimeout. No field for IdentitiesOnly,
  AddKeysToAgent, UseKeychain, ForwardAgent, Local/Remote/DynamicForward, Compression, RequestTTY, StrictHostKeyChecking.
  Reusable for the import: `parse_proxy_jump` and the jump-chain rules (`session/ssh_config_directory.rs:74-132`, `:261-316`,
  deleted with the adapter), `resolve_identity_value` (`sync/slot_rules.rs:172-195`).
- **Engine/broker inputs**: `Hop::new` defaults 15 s / 30 s / 3 (`ssh/types.rs:10-12`, `:156`); `HostId(String)` (`:19`). The
  engine has no local-user lookup: the adapter always got a user from `ssh -G`; a record with an empty `user` needs one.
  `HostDirectory::pin` has no device id (needed for `pinned_by_device_id`). `host-pins.json` = `{version:1, pins:{<alias>:
  {algorithm, public_key b64, fingerprint, pinned_at_ms}}}` (`session/pins.rs:18-35`), real data on machines that ran 0.17.0-10/-11.
  Alias rule for launches: `[A-Za-z0-9._@%-]`, no leading `-` (`connect.rs:33-43`); the CLI already takes `--id` (`cli/mod.rs:47-60`)
  but `connect_argv` passes the alias (`connect.rs:364-372`); tray quick-connect is capped at 25 aliases (`tray.rs:11-15`).
- **Generated files**: `cargo test` runs 68 ts-rs exports into the committed `src/bindings/` (68 tracked files); deleting a Rust
  type leaves its `.ts` file behind (and its frontend imports compile against it). `tauri_build` regenerates the ignored `gen/`.
- **Guards that new code must respect**: only `ssh/russh_engine.rs` may name russh (`ssh/mod.rs:52-72`); `ipc/` may not name the
  agent module (`ipc/mod.rs:38-59`); `clippy.toml` bans `Command::spawn/output/status` (use `crate::process`).
- **Startup paths**: `sync::engine::initialize` loads/sets aside state and runs a round at once (`sync/engine.rs:371-427`); each
  attempt may run the v1 upgrade (`sync/round.rs:217`), local slot maintenance (`:290-321`) and agent wiring (`:282`);
  `agent::start`, `session::app::start`, `mcp::initialize` (`lib.rs:179-185`); `config_load` from the window does the backup
  migration and wakes sync (`config/commands.rs:688-722`). The broker waits up to 5 s for the window's doc (`session/app.rs:35-60`).
- **Updater/versions**: branch version is still 0.16.0 (`Cargo.toml`, `tauri.conf.json`, release-please manifest); one beta
  channel (`updater_channel.rs:14`), updates only to newer versions.
- **Deferred to 1c by earlier reviews**: delete the agent's dead `Grant` path and `session/app.rs`'s duplicate `private_text`/naming
  (`docs/superpowers/plans/2026-10-13-own-ssh-phase1b-final-review-fixlist.md:364-366`); sanitize vault key names in prompts
  (`:196-199`); host-record validation of absurd timeouts, `keepalive_max_missed = 0`, empty `key_id`, show key names not ids
  (design brief `:43`).

## 14. Dependency map (an order that keeps the build green)

1. **Add without deleting**: schema-2 host payload + keyslot schema 2 in `valid_account_record`/`valid_slot_payload`,
   `ACCOUNT_SCHEMA_VERSION = 3`, the local store in `SyncStateV2` (and the state-version decision), a record-backed
   `HostDirectory` (run `check_the_pin_contract`), the import reader (reuse `config::{lexer,parser,model,include}`), the migration.
2. **Swap the broker**: `session/app.rs::directory()` → record directory; move `MAX_JUMPS` (and `parse_proxy_jump` if the import
   uses it) out; then delete `session/{ssh_config_directory,ssh_g,pins}.rs` (1,861 lines, 41 tests). Nothing else depends on them.
3. **Move shared helpers off doomed files first**: `slot_files::{write_private, ensure_keys_dir}` + `slot_files_windows` (vault,
   ipc); `keys::ssh_dir` (import, engine); `secrets_*` commands out of `deploy.rs`; `slots::agent_refusal`; `passphrase_account`
   (already twinned in `session/auth.rs:34`); keep `sync::testkit::MemKeychain`, `slot_rules::{inspect_private_key, payloads,
   test_keys}`.
4. **Delete `agent/`** (4,154 lines, 107 tests) with: `lib.rs` start/commands/window handler, `state.rs:23`, `config/include.rs:87`
   (keep the skip as a local constant for the import), `sync/{engine,round,slots,hosts_file}` call sites, frontend
   `AgentApprovalWindow`/`lib/agent.ts`/Keychain banner/`main.tsx` label, `capabilities/approval.json`, the Windows CI filter.
5. **Rewrite the sync engine to records**, then delete `files`, `hosts_file`, `space_files`, `planner`, text `approval` +
   `HostEffect`, `migrate`, `upgrade` (after the v1 decision), `slots`, `slot_setup`, `local_keys` (after re-implementing key
   import/generate/export/delete/sync on schema 2), `slot_files`; rewrite `TestDevice`; drop the doc lock from `runtime::mutate`.
6. **Re-point the last config readers**: `connect::validate_alias`, tray, MCP (records for list/get; decide `run`), then delete
   `keys.rs`, `deploy.rs` + `askpass.rs` (+ `main.rs:7-9`), `known_hosts.rs`, `discover.rs` (or rebuild deploy on the broker),
   `config/{commands,edit,newfile,serialize,intel,dto}`, `AppState.{doc,backed_up,backup_retention}`, config backups in `fsutil`.
7. **Frontend** follows each removal (commands vanish at runtime; TS only breaks when a binding file is deleted).
Steps 2, 3 and 4 can land in any order (4 is smaller after 3, since `agent/wiring.rs` also uses `slot_files`); 5 needs 3 and 4
(vault/ipc/agent call sites); 6 needs 5 for `migrate`'s config hooks (`config/commands.rs:708,1027,1032`).

## 15. Open questions for the planner (the spec does not settle them)

1. Space-chain transition of the alias-keyed text records: tombstone them (0.17 computers delete those hosts from their space
   files while read-only), leave them (1.0 ignores schema-1 hosts forever, and must not migrate them twice), or reuse the alias
   as the id of migrated hosts (not a random 16-hex id). With random ids, two 1.0 computers migrating the same space at once
   create duplicates unless the ids are derived deterministically (precedent: space0, `sync/record.rs:217-228`).
2. Cursor reset: does 1.0 re-pull the account and every space from seq 0 at migration (needed for records 0.17 skipped)?
3. State file: bump `version` to 3 (0.17 sets it aside, matches spec §9) or keep 2 (0.17 reads it and drops the new sections)?
4. v1 state (stable 0.16.0 users): migrate v1 → 1.0 directly, require 0.17 first, or treat as leave + rejoin? `upgrade.rs` is
   file-based.
5. Import source and mapping: textual blocks vs `ssh -G` effective values (Host * defaults, Match); one record per Host line or
   per pattern; wildcard/`Host *`; commented hosts; the 10 editor settings with no schema-2 field (unsupported or dropped?);
   which host gets a `Match` block; `ProxyJump user@host:port` that differs from the saved host ("缺的主機順便建立"?).
6. Where imported hosts go when an account exists (local store vs Personal), and what leaving an account does with the hosts of
   selected spaces (today they become local files).
7. `SlotMode::Own` keyslots (no public key in the account) under schema 2's required `public_key`; Linked/SyncedCopy slots'
   "ask to copy into the vault" (§9 step 2) needs UI — 1c or 1d? Same for the key-file question of §9 step 1.
8. Pins: move `host-pins.json` into `host_key` with `pinned_by_device_id` = this device? Then delete the file?
9. Remote edits from other account members: approval today gates risky text; with synced pins a remote change of hostname +
   `host_key` (or `jump`) redirects a host without any host-key prompt. Keep a review gate for those fields?
10. MCP until phase 2: records for `list_hosts`/`get_host`; `run` disabled, kept on system ssh (needs ssh_config), or pull
    `ssh_exec` forward? Migrate `mcp-policy.json` aliases to ids now or in phase 2?
11. Deploy (and its password UI, `secrets_*`): rebuild over the broker (exec without stdin today) or drop until later? Discover
    and the known_hosts dialog: drop?
12. Frontend scope of 1c: deleting `config/` breaks HostList/HostEditor/AddHost/CommandPalette/tray/MCP pane. Minimal record
    list in 1c, or keep `config/` until 1d?
13. Dev isolation before the first 1c dev build: separate data dir + keychain service (and the CLI's socket path) for debug
    builds, decided at compile time or otherwise?
14. Alias rules for records (charset, uniqueness per space vs global) and whether Connect/tray pass `--id`.
15. Empty `user` → which local user name (env vs OS call), per platform.
16. `DevicePayload.slots`: keep, empty, or drop (it has no file names today)?
17. Re-key alias-keyed per-machine data: `host:<alias>` passwords (spec), `hostTerminals`, `recentConnections`, stored
    `SyncNotice`s that mention files, `deploy-tmp:*` leftovers.
18. Version bump to 1.0.0 on the branch: in 1c or at the first 1.0 beta?
