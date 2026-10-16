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

The NSIS template separates `INSTALLERIDENTITY` from `PRODUCTNAME`, accepts the previous MSI display name, and removes the existing login entry on uninstall. `hooks.nsh` renames only old shortcuts that target the installed executable; it leaves unrelated shortcuts alone. The WiX template keeps the existing registry paths so the previous install directory survives and removes the old product's shortcuts on a major upgrade.

The main executable (`sshelter`, Windows `sshelter.exe`) and Windows console helper (`sshelter-cli.exe`) keep their names. Saved MCP commands and terminal launches continue to use them. Keychain services, SSH paths, local-storage keys, IPC roles, crypto contexts and updater public key retain their existing values. Active repository URLs use ysya/lunport; GitHub redirects the previous repository and release download URLs.

Linux uses the new `lunport` / `lunport-dev` package names. DEB provides/conflicts/replaces and RPM provides/obsoletes refer to the previous packages, `ss-helter` / `ss-helter-dev` (the actual package names inside the published 1.0.0 packages). Package upgrades are checked separately from GUI validation.
