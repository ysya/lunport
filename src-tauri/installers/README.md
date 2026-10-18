# Installer identities across the Lunport rename

`nsis.nsi` and `main.wxs` derive from the MIT-licensed templates in Tauri CLI **2.11.2**. The license is in `LICENSE_TAURI_MIT`. Rebase and rerun the upgrade checks when updating the CLI; do not replace these templates with the defaults without preserving the identities below.

Upstream sources:

- https://github.com/tauri-apps/tauri/blob/tauri-cli-v2.11.2/crates/tauri-bundler/src/bundle/windows/nsis/installer.nsi — SHA-256 `ee84148e405adc4d736a46456dd8345a644751bd1f28a335dd7fd833a32d7c3e`
- https://github.com/tauri-apps/tauri/blob/tauri-cli-v2.11.2/crates/tauri-bundler/src/bundle/windows/msi/main.wxs — SHA-256 `e371a01628a06730828f9bd24111feacb8bec53c250ccec4b46df756fe0a0198`

Visible product names, metadata and shortcuts use Lunport / Lunport Dev. These persisted identities stay as they were in SSHelter 1.0.0:

| Contract | Production | Development |
| --- | --- | --- |
| Application identifier and data root | `org.homelab.sshelter` | `org.homelab.sshelter.dev` |
| NSIS uninstall key and manufacturer product key | `SSHelter` | `SSHelter Dev` |
| MSI manufacturer product key | `SSHelter` | `SSHelter Dev` |
| MSI UpgradeCode | `d00b09d3-45df-5130-b6d5-52034e820843` | Selected in `tauri.dev.conf.json` from the old product name |
| Login-item identity | `SSHelter` | `SSHelter Dev` (OS integration remains disabled) |

The NSIS template separates `INSTALLERIDENTITY` from `PRODUCTNAME`, accepts the previous MSI display name, and removes the existing login entry on uninstall. `hooks.nsh` renames only old shortcuts that target the installed executable; it leaves unrelated shortcuts alone. The WiX template keeps the existing registry paths so the previous install directory survives and removes the old product's shortcuts on a major upgrade. Handlebars consumes one backslash before its expressions, so the template keeps doubled separators before manufacturer expressions and a single separator before WiX variables. Rendered registry keys must contain one separator and no unexpanded expressions; both previous-directory searches are checked before saving a candidate.

The main executable (`sshelter`, Windows `sshelter.exe`) and Windows console helper (`sshelter-cli.exe`) keep their names. Saved MCP commands and terminal launches continue to use them. Keychain services, SSH paths, local-storage keys, IPC roles, crypto contexts and updater public key retain their existing values. Active repository URLs use ysya/lunport; GitHub redirects the previous repository and release download URLs.

On macOS, the startup migration moves a legacy `SSHelter.app` bundle to sibling `Lunport.app` without replacing an occupied destination. A relative symlink preserves the old absolute executable path for MCP, CLI and unknown integrations. The process re-executes from the canonical path before Cocoa, the broker or updater initialize, and refreshes the new bundle registration. An existing enabled login entry keeps its identity and arguments while its executable path is repaired; an absent entry is not created. The frozen credential helper and signed bundle contents are unchanged by the move. See [migration and client setup design](../../docs/2026-10-18-macos-rename-and-agent-setup.md) for recovery and validation requirements.

Linux uses the new `lunport` / `lunport-dev` package names. DEB provides/conflicts/replaces and RPM provides/obsoletes refer to the previous packages, `ss-helter` / `ss-helter-dev` (the actual package names inside the published 1.0.0 packages). Package upgrades are checked separately from GUI validation.

The Windows bundle workflow preserves unsigned test candidates for three days, with source and package checksums. Its upgrade job uses a clean runner, separate from administrative MSI extraction and console tests. A manual run can reuse a previous candidate run ID for upgrade-only diagnostics; it rejects changed product sources or package checksums. These artifacts are not published releases.

For installer-only repairs, the Windows workflow can repackage an earlier verified candidate with `tauri bundle` instead of recompiling Rust. It checks repository/source provenance and package checksums, rejects runtime or configuration changes, and records the original runtime source in the new candidate.
