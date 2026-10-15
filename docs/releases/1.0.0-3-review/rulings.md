# Delegated decisions and costs

All ledger Ruling entries in chronological order, retaining their reasons and costs.

1. Ruling: use the existing clean checkout on a dedicated feature branch, without changing the user-retained phase-1c worktree — avoids new out-of-root writes and concurrent checkout changes — costs branch isolation rather than a separate directory.

2. Ruling: self-review the written design and plan and continue under delegated design/workflow decisions — user explicitly requested autonomous completion — costs visible rework if the user steers the design.

3. Ruling: retain the previous exact-code native CI as baseline instead of rerunning unchanged Rust — 0e9c727 differs from tested 07e669a only in documentation — new behavior receives focused RED/GREEN and full integration/native CI.

4. Ruling: sequential implementation agents, task-scoped review and a final broad review — interfaces span groups, resolution and authorization — costs extra review contexts but avoids conflicting writes.

5. Ruling: a materialized ungrouped host moving from Local Groups into an account still at schema 3 must serialize compatible host schema 2, or first perform a safe advertised schema upgrade — otherwise old clients receive unsupported host payloads without the account gate — costs one focused cross-scope regression.

6. Ruling: Auto-log means no new interaction; already available local authentication may be used noninteractively, but missing/locked credentials or unpinned identity cannot trigger any prompt — matches noninteractive broker behavior — costs explicit noninteractive credential tests.

7. Ruling: add backward-compatible optional upgrade_confirmed to host create/update using the existing Group promotion path — Ungrouped app-default inheritance must not require creating a throwaway Group — costs two focused promotion tests; missing flag remains false and schema2 unchanged. Agent will finish the ongoing full suite before this repair, and report the full baseline plus amended focused coverage; final integration reruns the whole suite.

8. Ruling: put inheritance controls/provenance beside each existing field, display effective values in disabled inherited controls and retain raw overrides internally; advanced inheritance stays in Advanced — actual 1100x720 visual showed the separate seven-row card hides Alias/Hostname below fold and presents contradictory used/raw settings — costs presentation rework while preserving backend/raw semantics. Task2 implementer received this before final commit; behavioral tests and reinspection required.

9. Ruling: allow Task2's minimal operations.ts group_error guard and focused regression — the shared Connect helper also serves the palette, so Group diagnostics must block stale-ready UI entrypoints consistently — costs one presentation-layer guard while the backend directory remains authoritative.

10. Ruling: include minimal root light/.dark dark color-scheme declarations in Task2 fix round1, no native-control replacement or new dependency — app theme needs to govern UA native form colors as well as custom colors — costs cross-platform visual regression checks; actual Windows popup validation remains explicitly unclaimed.

11. Ruling: MCP uses protocol2 hello/tool/result frames while existing protocol1 Connect framing remains supported — shell protocol is unchanged and CLI can be older than running app during updates — costs explicit dual-version regression coverage; MCP protocol1/unsupported versions still refuse. Broker tracks MCP cancellation/drain through injected service; native auth hub is shared with future human deployment.

12. Ruling: extend per-call noninteractive credential/material/directory reads for Auto-log, including required sync/env/vault call sites; reject unsupported paths with needs interaction — existing Keychain.get/OsKeychain keyring read can invoke OS unlock/consent, so suppressing only SSHelter windows does not satisfy no-new-interaction — costs platform API/compatibility coverage and explicit support limits. No process-global interaction toggle, new dependency, globally-unlocked material bypass or real credential testing. Trace headless startup before requests for the same boundary.

13. Ruling: native auth questions must reliably attribute the trusted hop/request, adding minimal context DTO/default Owner method if current shown text cannot provide it — Task4 must distinguish destination/jump prompts rather than infer identity from server text — costs small backend/CLI-compatible interface expansion.

14. Ruling: support verified per-call noninteractive Windows CredReadW credentials; macOS/Linux credential paths fail closed with explicit capability/notice in MCP status — the existing macOS file-keychain provider ignores per-call authentication UI options and Linux has no verified no-prompt guarantee — costs platform-limited Auto-log until an independently verified no-prompt provider exists; Ask execution remains supported. No global interaction toggle or new OS helper/dependency.

15. Ruling: prepare shared host-key account/credential/network proof outside lifecycle, then revalidate current format/account/scope/generation/effective endpoint/CAS and cancellation at pin commit; explicit human host-key trust may use per-call human credential reads without unlocking background work — Ask/native trust is the human interaction already authorized by that individual request, while Auto-log never pins — costs focused stale/cancel proof tests and a narrow trusted-operation credential interface; generic programmatic focus still cannot unlock background work.

16. Ruling: repair native auth resolve deadline together with Ask approval deadline — same authoritative pending/late-answer boundary and UI contract — costs one focused regression; new broader feature work remains excluded.

17. Ruling: two-phase confirmed pin preserves the existing fresh_account_gate wrapper for other callers; new prepare is credential/relay only and publish preserves format-publication/core discipline — isolate the MCP lifecycle repair without changing shared-command atomicity — costs a small default HostDirectory method and optional Records callback. Reject any generation change during preparation conservatively, rather than attempt to merge a reviewed target across it; users can refresh/review again. External approved-target/directory/key guards run outside lifecycle to avoid reentrant deadlock; commit rechecks use current snapshot/pure resolution.

18. Ruling: paired monotonic plus absolute UTC expiry for approval/native-auth snapshots, rejecting when either expires — Rust Instant docs explicitly do not guarantee whether suspend advances elapsed time, so monotonic-only late-answer repair cannot establish sleep/resume expiry — costs controlled paired-clock regressions and conservative early rejection after a forward clock correction; backward clock changes cannot extend the monotonic limit. Primary source https://doc.rust-lang.org/std/time/struct.Instant.html (verified2026-10-15). This amends Task3 fix round1 before commit, no new dependencies or live OS sleep test.

19. Ruling: native-auth answer and expired/abandoned/error status occupy a fixed bottom area above Cancel/Submit; trusted hop and complete server prompt remain scrollable — actual480x360 long-prompt view hid the primary input below the scroll body while footer stayed visible — costs small presentation adjustment/markup regression, preserves answer secrecy/deadline/escaped prompt semantics. Root fixture now uses real #root100%height; initial #preview root mismatch was a harness issue, not a product defect.

20. Ruling: share existing PublicDirectory/CheckedEngine via minimal pub(crate) visibility/fields for deployment's independent target/key guard — existing wrappers avoid lifecycle-held material readiness and enforce per-hop connect checks without duplicating logic — costs a cross-module dependency to review; no MCP policy/grant/behavior change. Existing untouched CLI human material-precheck lifecycle remains baseline outside this new deployment path, explicitly documented rather than broadly refactored. Disabled MCP/zero grants must not block human deployment regression.

21. Ruling: deployment audit helper returns that write's error while preserving existing record API behavior — reading global latest audit_error after releasing the writer can race another execution — costs a narrow internal result helper and completed-exec/auditfail regression; no lifecycle/policy lock across I/O.

22. Ruling: deployment dialog fixes header and action/result/error footer, scrolls reviewed body, places fingerprint beside destination before long route — actual800x560dark16-hop preview put Close/Confirm at783..813px outside560px viewport (dialogclient530/scroll814) — costs small presentation adjustment/markup regression; fullroute and fresh explicit authorization remain required. New native select computed dark; actualWindowspopup stillunverified.

23. Ruling: repair shared CheckedEngine/ApprovedTarget actual-target binding for both MCP and deployment, preserving legitimate new pins — current-directory rechecks alone allow a transient unreviewed Target to enter engine — costs a minimal shared contract change and both consumer regressions; no broader connector refactor.

24. Ruling: bind actual resolved target strictly (ignoring newly trusted pins), permit only the existing Interactive-to-Password adaptation at engine/Connected.target checks while current directory identity stays strict — verified Connector changes Interactive after a human password reply, so full equality would reject legitimate login — costs a narrow tested exception for this existing auth adaptation, no other route/auth/key drift allowance.

25. Ruling: after preserving review/ledger/QA evidence in repository docs, archive this plan's ignored scratch by a reversible move rather than rm-rf — user's no-destructive-commands instruction overrides skill cleanup wording; no other plan/worktree belongs to this run — costs retained local scratch disk usage, no irreversible deletion or extra approval.

26. Ruling: run final read-only whole-branch review concurrently with Development bundle compilation of immutable5eb8b7f after fullRust/frontend verification — these independent gates require no product edits; merge still waits for both — costs reviewer context refresh/scoped review if compilation requires code repair, no premature integration/publication.

27. Ruling: final fix wave binds the complete Group deletion review atomically, also repairs audit bounded read and historical-row React identity in the same worker — all are concrete review findings and M1/M2 are narrow correctness/robustness repairs — costs a small delete API/overview contract plus affected regression revalidation; no new feature expansion.

28. Ruling: defer M3 broad concurrency formatting and keep baseline dead-code warnings/Vite advisory as explicit maintenance debt — final reviewer found no behavioral breakage, broad formatting would obscure the load-bearing CAS repair and touch baseline CLI — costs slower future concurrency maintenance; no warning-free claim.

29. Ruling: use a required overview SHA-256 Group-deletion token over all public Group/host raw/effective/revision projection, freeze it in the UI candidate and atomically compare before mutation — covers reviewed descendants, affected hosts and outside ancestors without process-restart generation ABA or private material — costs conservative rejection after unrelated Group/host edits and a fresh manual confirmation; missing/old token fails closed.

30. Ruling: use full public audit event plus duplicate occurrence for stateless recent-row React keys — historical process-local IDs are not globally unique, including identical timestamps — costs small view-key allocation for at most10rows, preserves persisted log/protocol compatibility.

31. Ruling: freeze codex/groups-mcp-beta3 at d1642a8 while next/own-ssh receives docs-only remote handoff — user requested immediate wrap-up and remote continuation; frozen source preserves the exact successful CI commit — costs one retained remote branch and an explicit source-head check before Beta dispatch; no runtime changes or untested release source.
