<div align="center">
  <img src="public/lunport-icon.svg" width="96" height="96" alt="Lunport Folded L icon" />
  <h1>Lunport</h1>
  <p><strong>Your SSH workspace.</strong></p>
  <p>Keep your hosts, keys and Groups together.<br />Connect from your terminal. Bring your library to your other devices with encrypted sync.</p>
  <p><a href="https://github.com/ysya/lunport/releases/latest">Download</a> · <a href="docs/usage.md">User guide</a> · <a href="docs/development.md">Development</a> · <a href="https://github.com/ysya/lunport/issues">Issues</a></p>
</div>

Lunport is a desktop SSH workspace for **macOS, Windows and Linux**, formerly named **SSHelter**. It combines a local host library, a private-key vault and a built-in SSH engine with optional encrypted sync and AI access.

> **Upgrading from SSHelter:** Lunport continues the same project with a new name and Folded L icon. Existing data, credentials and command-line integrations keep their established identities. Historical [SSHelter 1.0.0](https://github.com/ysya/lunport/releases/tag/v1.0.0) installers retain their original names; use [Releases](https://github.com/ysya/lunport/releases/latest) for the current Stable.

## A workspace for your connections

- **Hosts and Groups** — organize connections with nested Groups, shared defaults and tags. Search the library, revisit recent hosts and connect from the command palette.
- **Your terminal, Lunport's SSH engine** — open sessions in your preferred terminal, verify server fingerprints and enter passwords or authentication codes in Lunport. Save host passwords in this device's system credential store when desired. Jump hosts use `ProxyJump`.
- **Keys in one place** — generate keys or import an OpenSSH private key with the system file picker or by pasting. Imports copy into the local vault and preserve the source file. Key sharing has separate controls.
- **Encrypted library sync** — connect your computers with a private 24-word code. Hosts and Groups travel together; passwords stay on each device, and private keys sync only when explicitly shared. The relay stores ciphertext and can be self-hosted.
- **AI access you control** — allow individual hosts for local MCP clients. Review proposed connections, verify fingerprints in the app, and choose Ask or explicitly acknowledged Auto-log for remote commands.
- **A home for existing OpenSSH setups** — Legacy mode edits your local SSH configuration while preserving comments, ordering and unknown directives. Migration into the Records library requires an explicit review.
- **Consistent preferences** — searchable settings, six built-in color palettes with independent light/dark/system modes, reduced motion, an animated collapsible sidebar and signed Stable/Beta updates. **Settings → About** collects the installed version, project links and license.

## Install

Choose an installer from [Releases](https://github.com/ysya/lunport/releases/latest). Files ending in `.sig` are updater signatures, not installers.

| Platform | Download |
| --- | --- |
| macOS, Apple Silicon or Intel | Universal `.dmg` |
| Windows x64 | `.exe` installer |
| Linux x64 or ARM64 | `.AppImage`, `.deb` or `.rpm` for your architecture |

**macOS:** builds use a fixed project signing certificate, keeping their designated requirement stable. This is not an Apple Developer ID; builds are not yet notarized. A self-signed certificate does not guarantee Keychain authorization across updates: items restricted to a particular build's `cdhash` can request authorization again even after **Always Allow**. See the [Keychain follow-up](docs/2026-10-18-keychain-partition-followup.md). Drag Lunport into Applications and, if Gatekeeper blocks it, run:

```bash
xattr -dr com.apple.quarantine /Applications/Lunport.app
```

For the historical SSHelter 1.0.0 app, use `/Applications/SSHelter.app` instead. Subsequent in-app updates do not require this step again.

**Windows:** the installer is not code-signed, so SmartScreen may show a warning. Choose **More info → Run anyway** to proceed. Connections use the installed console helper and open in Windows Terminal when available, otherwise Command Prompt. See [Windows integrations](docs/usage.md#windows-integrations) for OpenSSH deployment and Git/agent setup.

## Get started

1. Open the app. A new Records library works without an existing `~/.ssh/config`.
2. Add a host, or open **Import** to review and copy entries from an existing SSH configuration.
3. Open **Keys → Import private key → From a file** to choose a key. Pasting a supported OpenSSH private key is also available.
4. Select the host's login key, verify its server fingerprint against a trusted source and connect in your terminal.
5. Optionally open **Sync** to connect your devices, or **Settings → AI access** to enable selected hosts for an MCP client.

Existing Legacy workspaces keep their OpenSSH files. Use the offered migration review when you are ready to move them into the Records library.

## Self-host sync

Run the encrypted relay on Cloudflare Workers or your own server with Docker Compose. The [relay guide](relay/README.md) covers setup, and [Updating your relay](relay/README.md#updating-your-relay) covers existing deployments.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/ysya/lunport/tree/main/relay)

## Learn more

- [User guide](docs/usage.md) — connections, keys, sync, MCP and Legacy mode.
- [Development and release workflow](docs/development.md) — local setup, profile isolation, checks and publishing.
- [Self-host the sync relay](relay/README.md) — Cloudflare Workers or Docker Compose.
- [Release notes](https://github.com/ysya/lunport/releases) and [changelog](CHANGELOG.md).
- [Rename and upgrade compatibility](src-tauri/installers/README.md).

## License

[PolyForm Noncommercial 1.0.0](LICENSE). Copyright © 2026 Frank Sung.
