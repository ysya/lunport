# Automatic macOS rename and multi-client MCP setup

## User outcome

An SSHelter installation updates normally and next opens as Lunport, without reinstalling it or re-registering existing MCP clients. Launch at login retains its previous enabled/disabled state. New users choose an AI tool and add Lunport from Settings, without copying a terminal command.

## Evidence and existing contracts

- Published v1.7.0-2 contains `Lunport.app`, `CFBundleName=Lunport` and `CFBundleDisplayName=Lunport`. Its executable remains `sshelter` and bundle ID remains `org.homelab.sshelter`.
- `tauri-plugin-updater` 2.10.1 removes the archive's outer directory and writes contents back to the installed bundle path. It therefore preserves `SSHelter.app` after an in-app upgrade.
- Existing MCP registrations and CLI commands can refer to the absolute executable path inside that old bundle. Rewriting only known client configurations cannot preserve unknown integrations.
- Login integration intentionally retains the `SSHelter` launch identity. Its enabled state must survive a path change; disabling it must remain effective.
- Current Settings exposes only a Codex command to copy. The existing stdio adapter already serves any compatible local MCP client; the broker and per-host permission model remain applicable.

## Proposed installation migration

Run a narrowly scoped migration before the macOS desktop runtime, broker, autostart plugin and updater initialize. Recognize only the running production app's original SSHelter bundle name; keep user-selected parent directories. Development uses disposable fixture locations for validation and never migrates Production.

1. Serialize migration attempts and validate source/destination paths. A same-name unrelated destination is a recoverable conflict, never a replacement target.
2. Rename the running bundle to sibling `Lunport.app` without overwriting a destination.
3. Preserve the original bundle path as a compatibility symlink to `Lunport.app`. Existing absolute MCP/CLI/launch paths continue to resolve, including clients that Lunport does not recognize. Do not modify signed bundle contents, application identifiers, credentials or data roots.
4. Re-execute from the canonical new executable before initializing Cocoa/Tauri, preserving the original desktop mode and arguments. CLI/stdin requests already in progress do not attempt a live bundle move.
5. Refresh the app's system registration and verify the visible Dock/application name in the native upgrade fixture. Existing Dock references must keep opening the migrated app.
6. Repair an already-enabled login entry to the canonical path using the existing plugin identity. Leave a disabled entry disabled. Preserve other login items.
7. Make the operation repeatable and recoverable after an interrupted rename. Roll back on compatibility-link creation failure when safe; otherwise preserve both the usable canonical bundle and a recoverable status. Never silently overwrite an occupied path.
8. If an installation requires administrator authorization, use a bounded macOS installation authorization flow; cancellation leaves a working app and an in-app retry. The recovery path must not require reinstalling.

This introduces an installation-path compatibility contract. The user approved this implementation plan on 2026-10-18 under the supplied Agent.md instruction, “Ask before making architectural changes.”

## MCP connection UX

Settings → AI access starts with **Connect an AI tool**, followed by host permissions, command review and recent activity. Keep server command/JSON details in an expandable manual-setup area.

| Client | Proposed primary setup |
| --- | --- |
| Codex | Add the app's stdio entry to the user TOML configuration, preserving comments and unrelated settings. |
| Claude Code | Add the stdio entry to user-scoped MCP settings, preserving unrelated projects, servers and login data. |
| Claude Desktop | Add the stdio entry to its desktop MCP configuration; retain existing entries and explain the restart requirement. |
| Cursor | Open the documented MCP installation deep link; let Cursor confirm installation. |
| VS Code / Copilot | Open the documented `vscode:mcp/install` flow. |
| Other agents | Copy/export `mcpServers` JSON and separate command/argument fields, with optional TOML and VS Code variants. |

Display **Not added**, **Configured**, **Disabled**, and **Needs repair**; errors retain a manual setup path. Keep actual recent AI activity separate from configuration state. Writing configuration is not proof that the client loaded it and must never produce a Connected badge. Provide repair for stale app paths and show actionable parse/conflict errors. Do not replace an unrelated server that happens to use the same ID. Existing Lunport/SSHelter entries should not produce new duplicate tool sets.

One-click writes happen only after the user selects that client and presses Add/Repair. Back up the original file, write atomically, recheck for concurrent modifications and retain restrictive permissions. Reading or editing client configuration must not expose its secrets in logs or UI. Development writes only inside its sandbox home. Adding a client does not enable AI access, allow hosts, acknowledge Auto-log or change the broker authorization rules.

MCP standardizes communication and capability discovery; client configuration formats and installation entry points differ. This proposal keeps the current stdio transport and adds client-specific setup plus a portable export. A network listener, HTTP authentication service, public registry listing or externally distributed plugin is outside this change.

## Validation required before merge

- Failing baseline: old bundle path survives the existing updater; record the native name/path and old absolute MCP command.
- Disposable macOS upgrade: canonical bundle and visible name; old absolute MCP command still completes initialize/tools-list; login enabled and disabled fixtures; duplicate launch; repeated migration and a later update.
- Failure cases: destination conflict, denied permission, cancelled authorization, compatibility-link failure and interrupted migration. Preserve the working app and unrelated files.
- MCP config fixtures: each format, fresh/existing configuration, unknown keys/comments, malformed files, symlinks, unrelated same-name server, concurrent edit and backup/restore. No live user-client registration during automated tests.
- Native settings: minimum window size, keyboard access, loading/error states, selected client and manual setup. Verify that Configured and Connected cannot be confused.
- Appropriate frontend, Rust and cross-platform CI checks. Do not repeat unrelated tray-icon scenarios.

## Primary sources checked

- [Pinned updater implementation](https://github.com/tauri-apps/plugins-workspace/blob/updater-v2.10.1/plugins/updater/src/updater.rs)
- [Codex MCP configuration](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)
- [Claude Code MCP](https://code.claude.com/docs/en/mcp)
- [Claude Desktop local MCP](https://support.claude.com/en/articles/10949351-getting-started-with-local-mcp-servers-on-claude-desktop)
- [Cursor install links](https://prod.cursor.com/docs/mcp/install-links)
- [VS Code installation URLs](https://code.visualstudio.com/api/extension-guides/ai/mcp)
- [MCP Bundles](https://github.com/modelcontextprotocol/mcpb)

MCPB is a useful packaging format for supporting clients, especially Claude Desktop, but is not a universal install action across all clients. A future signed/distributed bundle can reuse this server after the core migration and setup flow are verified.
