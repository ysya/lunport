# Final integration checklist (publication complete; device acceptance pending)

- [x] Tasks1–5 implementation/review gates complete; no repeats. Task5 scoped fixes85a902e clear.
- [x] Verify final public bindings/frontend wrappers, native capability/window routes, existing Legacy and unknown/profile guards.
- [x] Full safe Rust excludes only 3 actual OS credential tests locally; full frontend, tsc/Vite, Development debug bundle. No warning-free claim (3 test / 15 production dead-code warnings; Vite advisory).
- [x] Disposable SSH fixture covers auth/exec endings/cancel and actual generated public deployment script; no real hosts/credentials/permission grants.
- [x] Actual mounted Group/MCP/Authentication/Deploy fixtures passed normal/minimum light/dark, compact auth, long text and cancellation/focus/expiry. Separate task2/4/5 receipts; public fake native transport only.
- [x] Windows native select computed color-scheme fixed; actual Windows popup visual remains unverified; native CI does not establish popup appearance.
- [ ] Actual Windows popup/device acceptance remains for the user.
- [x] One broad final review including baseline warnings and all rulings; one fix wave/scoped re-review if needed.
- [x] Release notes remove prior missing Groups/MCP exec/deployment limitation only when implemented; include schema4 first use/old clients/update-stop guidance, state backup is not vault credential backup, Auto-log macOS/Linux credential limit, POSIX remote deployment only, same-user MCP boundary.
- [x] Persist task reports/reviews/ledger and rulings in repo docs before scratch cleanup.
- [x] Fresh remote branch/tag check; merge reviewed branch into next/own-ssh with no force, push authorized.
- [x] Wait exact source macOS/Linux/frontend/PAM and Windows actual OpenSSH/console CI.
- [x] Capture fresh stable-before.json then choose next unused Beta suffix; dispatch beta.yml with structured notes JSON.
- [x] Four installer jobs + manifest succeed; verify exact tag/source, all actual uploaded nonempty asset/platform/signatures, canonical Release/channel manifests and Stable id/tag unchanged. Metadata check is not independent installer crypto verification.
- [x] Save validation receipt/inspection list, docs commit/push; installed Production untouched; stop only own preview server/reset viewport/close own tabs.

Read-only live relay /v1/info checked 2026-10-15: version0.2.0, features pull-batch/freeze. No relay mutations or deployment.

Beta3 publication subsequently authorized and completed: run38680461866, frozen source d1642a8, four installers/manifest success, independent public receipt verified. See ../../2026-10-15-beta3-remote-handoff.md. Own preview stopped and viewport reset; plan scratch may be reversibly archived, no duplicate implementation/review required.
