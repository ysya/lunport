# Records account lifecycle UI ledger

Authorization: root assigned frontend ownership after actual leave/rotation backend GREEN. No real account migration, relay, private key, or Keychain operation was performed by this worker. All IPC in frontend tests uses fixtures.

Source verification: record_commands.rs now exposes LeaveReply {receipt, overview}, records_account_rotate(device_name)->AccountSetupReply and records_migration_resume(migration_id, words:Option<String>) with Zeroizing conversion. Client arguments use Tauri camelCase. Pending kinds include leave_account and rotate_account.

Startup visibility: lib.rs setup shows the main window for !start_hidden before engine initialization. This does not depend on LegacyApp hooks or RecordsApp. No speculative frontend show hook was added.

RED evidence: compile-safe lifecycle skeletons failed eight meaningful consent/outcome/action tests; migration optional recovery failed three exact argument cases. Fixed a test-only SSR readOnly attribute casing assumption after inspecting emitted markup.

GREEN behavior: unchecked explicit consent dialogs explain Local ID/jump remapping and retained local credentials, remote sources, and rotation's historical-data limitation. Only explicit complete receipts report completion. Partial operations expose existing pending retry, operation IDs, copy counts/mappings and publication errors. Local code state is never placed in query/mutation cache or browser storage; acknowledgment clears it. Native retry retires previous attempt hints while preserving an unsaved new code.

Concurrency: lifecycle busy state disables other account actions; pending/shared gate blocks new operations. Original code must be dismissed before starting leave/rotation. Pending leave does not ask for a recovery code; rotation can provide its staged new code via the existing generic resume.

Migration recovery: optional words are passed directly for the selected durable migration ID. Failed resume retains input with a generic non-secret error; successful resume or cancel clears component code. Pending query cache contains public metadata only. Existing native status generation/Legacy activation race guards remain in force.

Final verification: focused records 89/89; all frontend 63 files /942 tests; TypeScript and Vite production build GREEN. Existing >500kB chunk advisory remains. Logs: /private/tmp/sshelter-lifecycle-ui-focused.log, /private/tmp/sshelter-lifecycle-ui-full.log, /private/tmp/sshelter-lifecycle-ui-build.log. Root owns native compilation, isolated GUI smoke and whole Rust gates.

Exact ownership: records client, account lifecycle component/actions/tests, AccountPanel and migration recovery components/actions/tests, dedicated plan/ledger. No unrelated native or other-worker paths staged.
