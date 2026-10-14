# Phase 1c foundation review fixes

Standing authorization: complete autonomous development while the user rests. One TDD fix pass after immutable review of 5222cf5..aa7126c; no repeated review of this same plan.

## Accepted findings and ownership

All eight concrete findings were checked against the indicated source paths. Preserve Production behavior and originals.

- Root: Development legacy system-SSH refusal, quoted IdentityAgent, compact dev agent IPC path, full safe CI suites and frontend CI.
- Compatibility worker: latest observed format/material transaction boundary; start_rotation entry preflight; retirement caller preflight using writer helper.
- Writer worker: no-write retirement plan and Fix Include guard before document/config/backup mutation.
- Importer worker continues independent read-only preview work.

## Root tasks

1. Add temp-only regressions: both effective-config entrypoints refuse Development before Match exec; MCP execution refuses; quoted spaced endpoint parses via OpenSSH; dev listener/client endpoint share compact IPC path and accept a common long macOS username. Observe behavioral RED.
2. Add one compiled-profile legacy SSH guard. Public wrappers use CURRENT without cfg(test) override. Production-only pure-profile helpers let existing temp-config OpenSSH tests keep exercising their original process/timeouts. Gate deploy before version/Keychain probes and again at process boundary; gate MCP before approvals and subprocess boundary. No real config, SSH connection or credentials in tests.
3. Keep legacy agent config under sandbox home, put dev socket and lock under data/ipc/a. Listener and endpoint consume one helper; ordinary production path unchanged. Quote only endpoints needing quotes and escape double quotes/backslashes according to OpenSSH config parsing. Verify actual temp config with ssh -G.
4. Replace CI name substrings with complete safe lib suite (three credential tests excluded), preserve dedicated PAM/Windows real server checks, add frontend Vitest/typecheck/build job with pinned pnpm from existing CI.
5. Focused GREEN then latest integrated safe suite/profile matrix. Exact-owned-file commits. Ledger records concrete findings, regression evidence and decisions. No app launch until isolation fixes pass. No main merge, release or real migration.

## Rulings and costs

- Development legacy external SSH fails closed until records adapter supplies normal connections. A -F flag cannot isolate tilde expansion, Match exec, ControlPath or known-host writes. Cost: legacy Connect/deploy/MCP execution is unavailable in Development during this transition.
- IPC remains under confined app data, using data/ipc/a rather than sandbox-home/.ssh/sshelter/agent. Arbitrarily long OS app-data roots still receive the existing explicit socket-length refusal; no unconfined temporary-directory workaround.
- Complete safe CI tests are preferable to brittle substring filters. Cost: longer CI; excludes OS credential integration from automated gates.
- Record mutation race fix must serialize observed-format publication with material transactions and reject the newest gate before materials, not just after vault mutation.
