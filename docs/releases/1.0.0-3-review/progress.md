# SDD ledger — plan: /Users/ysya/project/sideproj/sshelter/docs/superpowers/plans/2026-10-14-groups-mcp-completion.md

Baseline: 0e9c727f35f6f704e443d694c1c62f08432ca389; branch codex/groups-mcp-beta3.
Spec: docs/superpowers/specs/2026-10-14-groups-mcp-completion-design.md.
User authorized completion and Beta update; previous autonomous decision authorization persists.

## Rulings

- Ruling: use the existing clean checkout on a dedicated feature branch, without changing the user-retained phase-1c worktree — avoids new out-of-root writes and concurrent checkout changes — costs branch isolation rather than a separate directory.
- Ruling: self-review the written design and plan and continue under delegated design/workflow decisions — user explicitly requested autonomous completion — costs visible rework if the user steers the design.
- Ruling: retain the previous exact-code native CI as baseline instead of rerunning unchanged Rust — 0e9c727 differs from tested 07e669a only in documentation — new behavior receives focused RED/GREEN and full integration/native CI.
- Ruling: sequential implementation agents, task-scoped review and a final broad review — interfaces span groups, resolution and authorization — costs extra review contexts but avoids conflicting writes.

## Preflight table

| Tasks | Shared file/interface | Check/result |
|---|---|---|
| 1 / 2 | Overview, raw/effective payload, Group commands | Producer is backend; frontend consumes task report before coding. Empty extension fields remain schema-2 compatible. |
| 1 / 3 | Repository/directory, resolved route | MCP consumes effective values, never editor raw fallback. Task 3 must preserve Group API. |
| 1 / 5 | Effective endpoints/key metadata | Deployment compares resolved snapshot and selected authoritative public identity. |
| 2 / 5 | Records API library and Keys UI | Sequential changes; Task 5 appends deployment wrappers and preserves Group controls. |
| 3 / 4 | MCP status/mode/auth DTOs and commands | Backend report fixes actual DTO names before frontend implementation. |
| 3 / 5 | Auth/exec public interfaces | Human deployment has explicit authorization and does not grant MCP access. |
| 1 / 6 | Account/state format and lifecycle | Integration uses real fake-relay round trips and disposable SSH; no real data migration. |
| 3 / 6 | IPC, native profile and cancellation | CLI remains working; final native CI covers Windows/Unix. |
| 1 | Files, tests, APIs vs spec | Group/schema/lifecycle tests cover producer; no frontend ownership. |
| 2 | Editor/tree tests vs UI changes | Tests require raw inheritance preservation and stable-ID selection; no schema assertions via source scans. |
| 3 | Policy/exec/log tests vs backend | Own-engine execution; no lifecycle lock across waits. ssh_exec argument corrected to alias before dispatch. |
| 4 | Native auth/AI settings tests vs UI | Mode confirmation, canceled secrets and requester distinction are observable. |
| 5 | Real script tests vs deployment | Temporary HOME only; append/idempotency/symlink/stale-preview outcomes tested. |
| 6 | Integration/publication vs completion | Exact reviewed code CI before release, metadata coherence after release; device limitations remain explicit. |

## Tasks

- Task 1: in progress — agent /root/groups_backend; BASE bd36d41d69ae55f343c7c70de9d42d5e240e3dd9
- Task 2: pending
- Task 3: pending
- Task 4: pending
- Task 5: pending
- Task 6: pending

Baseline frontend: 65 files / 950 tests passed; /private/tmp/sshelter-beta3-baseline-frontend.log.

Task 1 progress: core Group RED/GREEN 13 focused tests reported; native DTOs, backup and account gate being integrated with lifecycle. Independent review not yet dispatched.
Ruling: a materialized ungrouped host moving from Local Groups into an account still at schema 3 must serialize compatible host schema 2, or first perform a safe advertised schema upgrade — otherwise old clients receive unsupported host payloads without the account gate — costs one focused cross-scope regression.
Ruling: Auto-log means no new interaction; already available local authentication may be used noninteractively, but missing/locked credentials or unpinned identity cannot trigger any prompt — matches noninteractive broker behavior — costs explicit noninteractive credential tests.

Ruling: add backward-compatible optional upgrade_confirmed to host create/update using the existing Group promotion path — Ungrouped app-default inheritance must not require creating a throwaway Group — costs two focused promotion tests; missing flag remains false and schema2 unchanged. Agent will finish the ongoing full suite before this repair, and report the full baseline plus amended focused coverage; final integration reruns the whole suite.

Task 1 implementation: 2b8ef00; full safe Rust 2468 pass/3 credential exclusions before optional API repair; final focused 331 pass. Report saved. Task review pending.

Task 1 review: spec issues / Needs fixes. Important I1: merge_space still validates raw jump and can block valid inherited routes/space pushes. Minor M1: three existing compiler warnings, baseline-known; record for final review, not a new task defect. Ingress state3 promotion/backup verified by reviewer. Fix round 1 follows on same implementer; re-review only new diff for I1.

Task 1: fix round 1/5 (I1 addressed, 1 open — R1 connection NeedsReview incorrectly blocks sync of imported warnings; commits 2b8ef00..bcfd05d). New Minor R2: unused TypedRecord means actual 4 warnings, report corrected in next round; original three-warning M1 remains baseline. Fix round 2 dispatched to same implementer with specific imported-warning regression.

Task 1: fix round 2/5 (R1/R2 addressed, 0 open; commits bcfd05d..f6bcf98; Spec compliant / quality Approved; final focused 105 passed).
Task 1: minor (deferred): M1 three baseline unused-function/method warnings; final branch review must triage, no warning-free claim.
Task 1 cannot-verify resolved: frontend contract belongs Task 2; MCP/deployment consumers Tasks 3/5; actual cross-platform and complete final-HEAD suite Task 6. Receiver state3 promotion/backup statically traced by initial reviewer, two-device round trip verified; final integration retains this as an explicit validation boundary. These future deliverables are not claimed complete by Task 1.
Task 1: complete (commits bd36d41..f6bcf98, review clean after 2 fix rounds).
Task 2: in progress — BASE f6bcf98edc56f3b99591649330dc9175e7dc1464; frontend Group UI only.

Ruling: put inheritance controls/provenance beside each existing field, display effective values in disabled inherited controls and retain raw overrides internally; advanced inheritance stays in Advanced — actual 1100x720 visual showed the separate seven-row card hides Alias/Hostname below fold and presents contradictory used/raw settings — costs presentation rework while preserving backend/raw semantics. Task2 implementer received this before final commit; behavioral tests and reinspection required.
Task2 preliminary actual-component visual uses an in-memory preview-only bridge, no native/remote calls; Vite port10496/session22049, browser4/tab3. Harness lives only in this plan workspace ui-review.html; final receipt must distinguish visual fixture checks from native execution.

Ruling: allow Task2's minimal operations.ts group_error guard and focused regression — the shared Connect helper also serves the palette, so Group diagnostics must block stale-ready UI entrypoints consistently — costs one presentation-layer guard while the backend directory remains authoritative.
Task2 preliminary visual: Group draft 'Production draft' survived Keys→Hosts; subsequent host selection showed Unsaved changes dialog with Keep editing focused. Final inline HostEditor at 800x560 displayed effective 2222/ops/key and key name, core identification visible; final-code screenshots/checks still pending after commit.

Task2 initial review: Spec/quality Needs fixes. I1 delete confirmation uses a boolean and refreshed pristine state can replace its reviewed CAS token; I2 saved Group error overwrites repaired draft's preview. Formal task-2-review.md. Fix round1 resumes original implementer with component/helper regressions.
User steering (2026-10-15): Windows native select does not follow dark mode; complete this within current Beta objective. Root diagnosis: CSS has no color-scheme declaration, actual browser root/all native selects stay computed normal in both app light/dark while foreground changes. MDN official color-scheme docs confirm UA form-control colors use this property. Native Windows popup not yet directly observed on this Mac.
Ruling: include minimal root light/.dark dark color-scheme declarations in Task2 fix round1, no native-control replacement or new dependency — app theme needs to govern UA native form colors as well as custom colors — costs cross-platform visual regression checks; actual Windows popup validation remains explicitly unclaimed.

Task2: fix round 1/5 (I1/I2 addressed, 0 open; commits f071333..a3ce927; Spec/quality Approved). New requested Windows select declaration reviewed, computed light/dark verified.
Task2 cannot-verify resolved: actual mounted delete race and valid/detached broken-host preview passed controller fixture at a3ce927; visual proof and limits in task-2-visual-verification.md. Task1 native Groups guarantees were independently reviewed/tested; MCP/deployment/CI/Beta remain later tasks. Actual Windows popup is not claimed verified; CSS cascade and UA mechanism are verified, Windows native CI still required.
Task2: complete (commits f6bcf98..a3ce927, review clean after 1 fix round).
Task3: in progress — BASE a3ce927276769d544e1e2ca749730e572a4d44bc; MCP backend only.

Task3 implementer: /root/records_mcp_backend (Astra high), no subagents.
Ruling: MCP uses protocol2 hello/tool/result frames while existing protocol1 Connect framing remains supported — shell protocol is unchanged and CLI can be older than running app during updates — costs explicit dual-version regression coverage; MCP protocol1/unsupported versions still refuse. Broker tracks MCP cancellation/drain through injected service; native auth hub is shared with future human deployment.

Ruling: extend per-call noninteractive credential/material/directory reads for Auto-log, including required sync/env/vault call sites; reject unsupported paths with needs interaction — existing Keychain.get/OsKeychain keyring read can invoke OS unlock/consent, so suppressing only SSHelter windows does not satisfy no-new-interaction — costs platform API/compatibility coverage and explicit support limits. No process-global interaction toggle, new dependency, globally-unlocked material bypass or real credential testing. Trace headless startup before requests for the same boundary.
Ruling: native auth questions must reliably attribute the trusted hop/request, adding minimal context DTO/default Owner method if current shown text cannot provide it — Task4 must distinguish destination/jump prompts rather than infer identity from server text — costs small backend/CLI-compatible interface expansion.

Ruling: support verified per-call noninteractive Windows CredReadW credentials; macOS/Linux credential paths fail closed with explicit capability/notice in MCP status — the existing macOS file-keychain provider ignores per-call authentication UI options and Linux has no verified no-prompt guarantee — costs platform-limited Auto-log until an independently verified no-prompt provider exists; Ask execution remains supported. No global interaction toggle or new OS helper/dependency.
Task3 recovery (2026-10-15): interrupted worker resumed in place; 33 focused tests reported before interruption. Auth deadline DTO is remaining_ms (relative <=120000), trusted hop context retained. Human background gate lifts only explicit second launch, Dock/Finder Reopen, or tray Open; generic programmatic window focus cannot lift it. Final report/review pending.

Task3 implementation complete at 66acc1cde84fbbc888438ce7de4a2d3bbed0eb93, scoped review pending. Safe Rust2501pass/3credential exclusions (before last Legacy/Connect self-review); broker43, post-review MCP35, Connect audit1 pass; production cargo check succeeds. Report exact command/output retained. Production check16 warnings includes baseline dead-code and Task5-facing re-export; final review must triage, no warning-free claim. Task3 source deliberately supports only Windows no-prompt stored credential reads; Task4/5 interfaces and pre-existing human material lifecycle concern in report/context.

Task3 initial review interim: reviewer traced PublicDirectory pin forwarding through FormatDirectory lifecycle into Space fresh-account credential read/relay pull. This is an actual MCP Ask path, not covered by the pre-existing human-only concern; Important finding to fix after formal review. No Task4 dispatch until review gate clean.

Task3 initial formal review: Spec/quality Needs fixes; I1 Space pin lifecycle over credential/relay wait, I2 late Ask Allow accepted after deadline. Report task-3-review.md. Fix round1 resumes original implementer. Minor M1 audit read allocation before32MiB check; M2 auth resolve expired success contract; M3 compressed new concurrency statements; M4 new Task5 ExecResult re-export warning plus baseline warnings retained for final triage.
Ruling: prepare shared host-key account/credential/network proof outside lifecycle, then revalidate current format/account/scope/generation/effective endpoint/CAS and cancellation at pin commit; explicit human host-key trust may use per-call human credential reads without unlocking background work — Ask/native trust is the human interaction already authorized by that individual request, while Auto-log never pins — costs focused stale/cancel proof tests and a narrow trusted-operation credential interface; generic programmatic focus still cannot unlock background work.
Ruling: repair native auth resolve deadline together with Ask approval deadline — same authoritative pending/late-answer boundary and UI contract — costs one focused regression; new broader feature work remains excluded.

Ruling: two-phase confirmed pin preserves the existing fresh_account_gate wrapper for other callers; new prepare is credential/relay only and publish preserves format-publication/core discipline — isolate the MCP lifecycle repair without changing shared-command atomicity — costs a small default HostDirectory method and optional Records callback. Reject any generation change during preparation conservatively, rather than attempt to merge a reviewed target across it; users can refresh/review again. External approved-target/directory/key guards run outside lifecycle to avoid reentrant deadlock; commit rechecks use current snapshot/pure resolution.

Ruling: paired monotonic plus absolute UTC expiry for approval/native-auth snapshots, rejecting when either expires — Rust Instant docs explicitly do not guarantee whether suspend advances elapsed time, so monotonic-only late-answer repair cannot establish sleep/resume expiry — costs controlled paired-clock regressions and conservative early rejection after a forward clock correction; backward clock changes cannot extend the monotonic limit. Primary source https://doc.rust-lang.org/std/time/struct.Instant.html (verified2026-10-15). This amends Task3 fix round1 before commit, no new dependencies or live OS sleep test.

Task3 fix round1 implementation e8b8da06faeaa70d840a04b329015aaebd13ae8b; scoped re-review dispatched to original reviewer, pending. I1/I2/M2 reported addressed; direct pin-waitRED then actual MCP path GREEN; pairedclock0/5RED→5/5GREEN; finalMCP40/auth9/clock1, connect43/Records directory11+Format3/record_round30 passed; compilation16classifiedwarnings. Package review-66acc1c..e8b8da0.diff82,221bytes. Fullsafe deferredfinalintegration. M1 audit full-readbefore32MiB/M3 compressednewloops remain explicitminors; M4Task5-facingExecResult re-export.

Task3: fix round1/5 (I1/I2/M2 ADDRESSED,0open; commits66acc1c..e8b8da0; scoped review Approved, no newCritical/Important). Report task-3-rereview-round1.md. Native frontend rendering/actualWindowsno-prompt and OS suspend runtime remain Task4/6 boundaries, controlled-clock semantics verified.
Task3: complete (commitsa3ce927..e8b8da0, review clean after1fixround).
Task4: in progress — BASEe8b8da06faeaa70d840a04b329015aaebd13ae8b; fresh frontend implementer; actual backend DTOs in task-3-report.md unchanged after fixes.

Task4 implementer /root/records_mcp_ui (Solhigh), no subagents. Root preview-only actual UI harness mcp-ui-review.html at Vite10496/session22049; fresh IABbrowser4/tab4 after previous interruptedturn tab3 expired. All native invocations stay fake; noactual MCP grants/credentials/network. Baseline mountedAI confirms metadata-only copy/raw deployuser (effective ops2222) beforeTask4; exports pending. Browserviewport temporary override persists1100x720; resetatfinish.

Ruling: native-auth answer and expired/abandoned/error status occupy a fixed bottom area above Cancel/Submit; trusted hop and complete server prompt remain scrollable — actual480x360 long-prompt view hid the primary input below the scroll body while footer stayed visible — costs small presentation adjustment/markup regression, preserves answer secrecy/deadline/escaped prompt semantics. Root fixture now uses real #root100%height; initial #preview root mismatch was a harness issue, not a product defect.

Task4 implementation246bd5677094fca25da3631878673ec3eafa38b9; fullfrontend71files997tests, tsc/Vitepass(chunksadvisory). Independent Task4Spec/qualityApproved,noCritical/Important; task-4-review.md. Minor automatedSSR/helpertests don'tdirectlyexerciseCardeffects/focus — recordforfinaltriage; controller actualmountednewID/answerclear/error/expiry/focus/mode flows passed, evidence task-4-visual-verification.md. BrowserCannotVerifyresolved; nativeOS and crossplatformCI stillTask6.
Task4: complete (commitse8b8da0..246bd56, reviewclean, controlleractualUIpass).
Task5: in progress — BASE246bd5677094fca25da3631878673ec3eafa38b9; public-key deployment plusnarrowhumanmateriallifecycleinterface.

Task5 implementer /root/records_key_deploy (Astrahigh), no subagents. Task4 actualUIreceipt completed before dispatch; Task3/4 interfaces approved.
Ruling: share existing PublicDirectory/CheckedEngine via minimal pub(crate) visibility/fields for deployment's independent target/key guard — existing wrappers avoid lifecycle-held material readiness and enforce per-hop connect checks without duplicating logic — costs a cross-module dependency to review; no MCP policy/grant/behavior change. Existing untouched CLI human material-precheck lifecycle remains baseline outside this new deployment path, explicitly documented rather than broadly refactored. Disabled MCP/zero grants must not block human deployment regression.

Ruling: deployment audit helper returns that write's error while preserving existing record API behavior — reading global latest audit_error after releasing the writer can race another execution — costs a narrow internal result helper and completed-exec/auditfail regression; no lifecycle/policy lock across I/O.
Ruling: deployment dialog fixes header and action/result/error footer, scrolls reviewed body, places fingerprint beside destination before long route — actual800x560dark16-hop preview put Close/Confirm at783..813px outside560px viewport (dialogclient530/scroll814) — costs small presentation adjustment/markup regression; fullroute and fresh explicit authorization remain required. New native select computed dark; actualWindowspopup stillunverified.

Task5 implementation f292b462db23d190d7f7a4bf52fd18d782d3965a; clean checkout confirmed. Affected Rust159pass, frontend73files1001tests, tsc/check success (15 baseline warnings). Task-scoped Astra high reviewer /root/records_key_deploy_review dispatched with immutable246bd56..f292b46 package; final mounted UI and own-engine real SSH still pending.

Task5 review Needs fixes: I1 actual CRLF restricted-key duplicate append; I2 actual engine Target not bound to approved snapshot (ABA static evidence). No new Minor. Formal task-5-review.md; focused TempDir probe only, full existing logs independently read. Fix round1 original implementer, both findings and deterministic shared MCP/deploy coverage.
Ruling: repair shared CheckedEngine/ApprovedTarget actual-target binding for both MCP and deployment, preserving legitimate new pins — current-directory rechecks alone allow a transient unreviewed Target to enter engine — costs a minimal shared contract change and both consumer regressions; no broader connector refactor.
Ruling: bind actual resolved target strictly (ignoring newly trusted pins), permit only the existing Interactive-to-Password adaptation at engine/Connected.target checks while current directory identity stays strict — verified Connector changes Interactive after a human password reply, so full equality would reject legitimate login — costs a narrow tested exception for this existing auth adaptation, no other route/auth/key drift allowance.
Task5 final mounted QA f292b46 saved task-5-visual-verification.md: stale consent refresh, Keys entry, already-present+auditfailure, delayed cancellation, dark800x560 longroute and light1100x720 pass. Backend-only fixes retain frontend evidence unless presentation changes. TypeScript final integration will retain explicit exit status, resolving reviewer log evidence gap.

Task5 fixround1 commit85a902e21bd0bb2d27efbedd6bd03bf4145c355f (I1/I2 addressed by implementer, gate pending). Finaldeploy26/MCP45passed, check0/15warnings. Scoped Solhigh reviewer /root/records_key_deploy_rereview onlyf292b46..85a902e. Rootrelease drafts preserved, no push.

Final frontend verification at85a902e: npmtest73files1001pass, node_modules/.bin/tsc--noEmit exit0, Vitebuild exit0/21.57s (existing>500kB advisory). Explicit EXIT_CODE receipts /private/tmp/sshelter-beta3-final-{frontend,tsc,vite}.log. No frontend mutation after review/visual receipts.

Task5 fixround1/5 (I1/I2 addressed,0open,commitsf292b46..85a902e; scopedrereviewclean/nooutofscope). MountedUIreceiptretained(frontendunchanged).
Task5: complete (commits246bd56..85a902e, reviewcleanafter1fixround).
Task6: in progress — BASE85a902e21bd0bb2d27efbedd6bd03bf4145c355f; disposable realSSH coverageworker follows, Root owns integration/fullchecks/nativebundle/finalreview/CI/publish.

Read-only GitHub SSHELTER_RELAY_URL lookup: variable not found (exit1), so defaultless build remains supported and existing saved user relay persists; no repo variable mutation. Release notes retain manual HTTPS relay setup guidance. Final installer workflow notice will establish actual build setting.

Task6coverage5eb8b7f0c9094c34c9c47ac0a8819d9e1bfd2350: realSSHproductiongenerator/classifier, noPTY, explicitlyquotedTempHOME(spaces/apostrophe), Added→Present exactbytes/keyonce/perms/symlinkrefusal1/1exit0. cfgmacOS/Linux-onlytestchild, no productionvisibilitychange. Reporttask-6-ssh-report.md; fullsafeRust nowrunning exact5eb runtime/source.
Ruling: after preserving review/ledger/QA evidence in repository docs, archive this plan's ignored scratch by a reversible move rather than rm-rf — user's no-destructive-commands instruction overrides skill cleanup wording; no other plan/worktree belongs to this run — costs retained local scratch disk usage, no irreversible deletion or extra approval.

Full safe local Rust exact5eb8b7f: 2546passed/0failed/0ignored/3actualOScredential exclusions,130.85s,exit0; REQUIRE_OPENSSH=1 actualdisposablemacOSsshd, PAMruntime remainsLinuxCI gate. /private/tmp/sshelter-beta3-final-rust.log. Development debug bundle building isolatedid, no launch/Productionmutation.
Ruling: run final read-only whole-branch review concurrently with Development bundle compilation of immutable5eb8b7f after fullRust/frontend verification — these independent gates require no product edits; merge still waits for both — costs reviewer context refresh/scoped review if compilation requires code repair, no premature integration/publication.

Developmentbundleexact5eb8b7f exit0/2m36s; Info.plist org.homelab.sshelter.dev/SSHelterDev0.16.0 and executable120015304bytes verified; no App launch. Existing15Rustwarnings/Vitechunkadvisory. Final wholebranch reviewer /root/beta3_final_review Astraxhigh running immutable0e9c727..5eb8b7f, CI/merge/publish pending.

Finalreview interimImportant: Group delete CAS rootrevisiononly while expands current subtree; concurrentnew/reparenteddescendant withunchangedrootrevisionmaydeleteunreviewedGroups. Formalcompletefindinglistpending; onefinalfixwavewillbind whole reviewed delete scope, no merge/push/publication yet.

Final wholebranch review formal: With fixes, I1 Group delete reviewed-set CAS mustfix; MinorM1auditboundedread, M2persisted auditID/Reactkeyduplicates, M3compressednewconcurrencyformat. Full reportfinal-review.md. Singlefinalfixwavewilladdress I1/M1/M2; M3deferredbelow.
Ruling: final fix wave binds the complete Group deletion review atomically, also repairs audit bounded read and historical-row React identity in the same worker — all are concrete review findings and M1/M2 are narrow correctness/robustness repairs — costs a small delete API/overview contract plus affected regression revalidation; no new feature expansion.
Ruling: defer M3 broad concurrency formatting and keep baseline dead-code warnings/Vite advisory as explicit maintenance debt — final reviewer found no behavioral breakage, broad formatting would obscure the load-bearing CAS repair and touch baseline CLI — costs slower future concurrency maintenance; no warning-free claim.
Final Declined-to-judge handling: retain each reason verbatim in final-review.md. D1–4 realcredential/Winpopup/suspend/nativeOS remaindeviceacceptancelimits; D5same-userboundary,D6unchangedCLI,D7SSR,D8warnings,D9Beta2baseline,D10conservativegeneration,D11unknowninstall,D12remoteWindows retaindocumentedcontractandlimits; D13CI/PAM/Winengine andD14releaseassets/signatures/tag/Stable are mandatorylatergates; D15Productionrealdata/relay operation isoutofscope andunperformed. This isnot a passclaim forpendingverification.
Ruling: use a required overview SHA-256 Group-deletion token over all public Group/host raw/effective/revision projection, freeze it in the UI candidate and atomically compare before mutation — covers reviewed descendants, affected hosts and outside ancestors without process-restart generation ABA or private material — costs conservative rejection after unrelated Group/host edits and a fresh manual confirmation; missing/old token fails closed.
Ruling: use full public audit event plus duplicate occurrence for stateless recent-row React keys — historical process-local IDs are not globally unique, including identical timestamps — costs small view-key allocation for at most10rows, preserves persisted log/protocol compatibility.

Finalfixwave30c4a4c689b86a95bb17b8cc4fae90bb3469b686 committed15ownedfiles; I1/M1/M2 implementeraddressed, Group25Audit7FE49/tsc0. Workerusageinterruptionrecoveredinplace underusercontinue, no duplicatewave. Rootscopedreview /root/beta3_final_scoped_review Solhigh one5eb..30c package; RootfullFE/Rust/Vite nowrunning. QAserverresumedlocalhost10496session16014, previoussession22049expired; Browser4fresh2tabs, diagnosingnavigationdelay. No merge/push/release.

Finalscopedrereview30c4a4c: I1/M1/M2addressed,0newCritical/Important/Minor, M3deferred; final-scoped-review.md. FullpostfixRust2551pass/0fail/3credentialexcluded/134.59s, FE74files1006tests, tsc0,Vite0/12.81s; /private/tmp/sshelter-beta3-postfix-*.log. Developmentbundlefinal30cbuilding.

Final30c Developmentbundle exit0/2m32s, Devidentifier/name/versionverified, executable120090296bytes. Alllocaltests/builds/reviews complete. Remotetargetfreshstill0e9c727; v1.0.0-3tag/releaseunused. Preparingdocs-onlyreceiptcommit thenauthorizedFFmerge/push/exactCI.

Authorized integrationcomplete: docs-onlyevidencecommitd1642a8b5c57dc9eb1f8e23d5c36645d5082e056, verifiedruntimeunchangedfromreviewed/tested30c4a4c; cleanFFnext/own-ssh0e9→d164 andnonforcepush, remotere-readexactSHAconfirmed. Featurebranchretained, noothertreechanged. ExactCIpending; noBetadispatchyet. /private/tmp/sshelter-beta3-merge-push.log.

Exact-source CI complete: engine38678695179 frontend/macOS/Linux/PAM success; Windows38678695106 success including safe2359pass/1ignored, profile9, helper8+3, separate realconsole1, realOpenSSHengine1. All headSha d1642a8. Public JSON and selected summaries preserved in handoff receipts.
Ruling: freeze codex/groups-mcp-beta3 at d1642a8 while next/own-ssh receives docs-only remote handoff — user requested immediate wrap-up and remote continuation; frozen source preserves the exact successful CI commit — costs one retained remote branch and an explicit source-head check before Beta dispatch; no runtime changes or untested release source.
Task6: in progress — user requested wrap-up/push/remote handoff. No Beta3 dispatch/tag/release, no new stable-before baseline for Beta3. Runtime source frozen d1642a8, remote handoff docs/tools/screenshots being committed to next/own-ssh; exact-source native CI complete. Tasks1–5 remain complete. Scratch retained rather than deleted; own Vite stopped, viewport reset, QA tab closed.

Remote handoff push verified: f3fe1e700edca8cd867e75c95cbf7cb63166fd77 on origin/next/own-ssh; frozen origin/codex/groups-mcp-beta3=d1642a8b5c57dc9eb1f8e23d5c36645d5082e056. Atomic nonforce push succeeded, 21 docs/receipt/screenshot/helper files, clean worktree, runtime unchanged; /private/tmp/sshelter-beta3-handoff-push.log. CI watcher exited0/all success. Beta3 remains unstarted for remote continuation per user wrap-up request; no outstanding local preview server.

Publication resumed under explicit user request after handoff: fresh exact-source CI both successful, frozen remote d1642a8 and v1.0.0-3 tag unused; baseline freshly captured Stablev0.16.0 in /private/tmp/sshelter-beta3-publication-20261015/stable-before.json. beta.yml dispatched on codex/groups-mcp-beta3, run38680461866, headSha d1642a8; prepare success, four installers in progress. No runtime mutation or installed-app update. Completion still waits all builds/manifest and independent receipt validation.
Updater question source audit: Beta1 22855e70 RecordsWorkspace and App root omit useSyncBackendSettings (LegacyApp only), so missing-panel Records Beta1 does not auto-check. Beta2 07e669a and current d164 RecordsWorkspace mount it independently of SettingsDialog. Production autoCheck true default, Stable channel default, initial5s/period4h/focus1h throttle, prompt requires Install & restart, Dev disabled. Actual installed user version/channel not read; answer is conditional, no device update claim.

Publication verified 2026-10-15T04:35:03.871665+00:00: beta.yml38680461866 all6jobs success, v1.0.0-3tag exactd1642a8, prerelease/non-draft, 20uploaded/nonemptyassets and 15manifestentries, Release/channelcanonicalmatch and downloaded .sig coherence. Stablebefore/afterv0.16.0/id400974628 unchanged; notes match dispatched frozen source. Metadata verification is not full installer cryptographic/device acceptance. Docs receipt/checklist/handoff updated.
Task 6: complete (runtime85a902e..30c4a4c, frozen released-source d1642a8, native CI and Beta publication/independent receipt complete; docs-only final receipt push follows, device acceptance limits retained; scratch reversible archive only).
