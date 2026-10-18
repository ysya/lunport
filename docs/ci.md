# CI and release checks

Application checks run on pull requests, once per revision. A newer revision cancels
obsolete checks. Merging does not repeat the same test suites; `Release - Stable`
runs release-please and builds installers only when a release PR is merged.

| Workflow | When | Responsibility |
| --- | --- | --- |
| CI - App | Every PR; manual full run | Version consistency, CI policy tests and workflow syntax; frontend tests/build for UI changes; macOS and Linux Rust/SSH tests for native changes |
| CI - Windows | Native paths; manual | Windows Rust/SSH, console, GUI startup and one native tray smoke test |
| CI - macOS credentials | Credential/signing/build scripts or Rust dependencies; manual | Disposable Keychain authorization, frozen helper transport/recovery, signed universal app and updater |
| CI - Relay | Relay paths; manual | Relay tests, deployed update script and self-host integration |
| Packages - Linux upgrade | Installer, icon or meaningful Tauri config changes; manual | DEB/RPM packaging and upgrade from published SSHelter |
| Packages - Windows upgrade (manual) | Explicit dispatch | NSIS/MSI contents and upgrade; supports reuse of verified candidates |
| Release - Stable | Push to main; manual | Release PR/tag, signed installers and update channels |
| Release - Beta (manual) | Explicit version and notes | Beta installers and update channel |
| Recovery - Release platform (manual) | Existing stable tag and platform | Repair one failed platform build |
| Recovery - Beta manifest (manual) | Existing release tag | Refresh the Beta manifest after a repaired build |

## Selecting PR checks

`scripts/ci-changes.mjs` compares the PR base and head, including both sides of a
rename. It shares one policy across the app, Windows, Linux package and macOS
credential workflows. Workflow files keep their existing paths and native job IDs
so dispatch scripts and Rust caches continue to work.

- UI changes run frontend tests/build without three native suites.
- Rust changes run native suites without rebuilding the UI. Changes spanning both
  areas run both. Rust dependency changes also run credential checks.
- Docs changes run the inexpensive policy/version/workflow check.
- Pure application version changes in package.json, Tauri config, Cargo.toml and
  the root Cargo.lock package skip compilation. Dependency, capability, installer
  or configuration edits in the same PR still run their relevant checks.
- All five version carriers, including release-please's manifest and Cargo.lock,
  must agree. Missing or malformed files fail the gate; they cannot silently skip
  validation.
- A manual application/package/credential dispatch runs its full scope. For a
  deliberate direct push without a PR, dispatch the affected checks explicitly.

The policy has Node-only regression tests, including release version changes,
dependency/configuration changes, missing files and manual runs:

```sh
node --test scripts/ci-changes.test-node.mjs
```

## Tray and Keychain regressions

The normal Windows job runs the native tray regression in **one process**. The
existing test still exercises startup and concurrent updates. For an intermittent
native regression, dispatch `CI - Windows` with `native_probe=true`, choose `tray`
or `handles`, and supply `baseline_ref`. Only that explicit comparison runs ten
independent processes for each source; it does not run the full application suite.

Keychain probes run only in their dedicated workflow on disposable macOS runners.
The helper Rust job includes the native metadata probe and partition regression;
the separate identity job is reserved for `identity_only=true` or fork PRs without
signing secrets. Ordinary releases verify and embed the frozen helper; they never
rebuild it. `freeze_helper` remains an explicit candidate-generation operation.

Workflow syntax is checked on every PR with the existing pinned actionlint image.
The relay's deployed workflow retains its separate shellcheck validation.

## Action versions and runtime

Audited against upstream stable releases on 2026-10-18. Workflows use the
maintained major tags; `dtolnay/rust-toolchain@stable` deliberately tracks the
stable Rust channel. The deployed relay workflow follows the same versions.

| Action | Workflow ref | Stable release checked | Action runtime |
| --- | --- | --- | --- |
| actions/checkout | v7 | [v7.0.1](https://github.com/actions/checkout/releases/tag/v7.0.1) | Node 24 |
| actions/setup-node | v7 | [v7.1.0](https://github.com/actions/setup-node/releases/tag/v7.1.0) | Node 24 |
| actions/upload-artifact | v7 | [v7.0.2](https://github.com/actions/upload-artifact/releases/tag/v7.0.2) | Node 24 |
| pnpm/action-setup | v6 | [v6.1.0](https://github.com/pnpm/action-setup/releases/tag/v6.1.0) | Node 24 |
| googleapis/release-please-action | v5 | [v5.0.0](https://github.com/googleapis/release-please-action/releases/tag/v5.0.0) | Node 24 |
| tauri-apps/tauri-action | v1 | [action-v1.0.0](https://github.com/tauri-apps/tauri-action/releases/tag/action-v1.0.0) | Node 24 |
| Swatinem/rust-cache | v2 | [v2.9.2](https://github.com/Swatinem/rust-cache/releases/tag/v2.9.2) | Node 24 |
| dtolnay/rust-toolchain | stable | stable channel | Composite; no Node runtime |
| rhysd/actionlint (Docker) | 1.7.12 | [v1.7.12](https://github.com/rhysd/actionlint/releases/tag/v1.7.12) | Container; no Node runtime |

`setup-node`'s `node-version: lts/*` selects Node for project commands; it does not
change the runtime declared inside another Action. Node 24 Actions require runner
v2.327.1 or newer; these workflows use GitHub-hosted runners.

Tauri Action v1 uploads to the existing release by **release ID**, bypassing its
new behavior that edits an existing release's name/body when resolving a tag.
Stable, Beta and repair workflows retain their existing release metadata. The
macOS wrapper still verifies the original local archive before upload; v1 adds
version information to its uploaded name. Updater manifests now use GitHub asset
API URLs and retain universal macOS entries alongside architecture aliases. The
shipped Tauri updater downloads with `Accept: application/octet-stream`, and Beta
promotion accepts these URLs and additional aliases without rewriting signatures.
Old published releases and their manifests are left intact.

Workflow artifacts explicitly retain ZIP archiving for the existing `gh run
download` consumers. Windows candidate provenance checks use the workflow file
path, so display-name changes do not invalidate candidates.
