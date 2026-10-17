# Using Lunport

Lunport is your SSH workspace for hosts, keys and Groups, formerly named SSHelter. Download the current Stable from [Releases](https://github.com/ysya/lunport/releases/latest). Existing SSHelter installations retain their data, credentials and command-line integrations through the rename.

## Your host library

A new installation opens a Records workspace without requiring an SSH config or an existing data directory. The first save creates the local library. Add a host with its hostname, username and port, or use **Import** to review entries from OpenSSH files. Import copies the selected data and preserves the sources.

Groups provide shared connection defaults and can contain other Groups. Host overrides remain explicit. The full-height sidebar is reserved for Library navigation; use tags, Recent and Needs attention to find connections, or open the command palette with **⌘K / Ctrl+K**. **Import hosts** sits beside **New host** in the host list. **Settings** opens from the upper-right toolbar or **⌘, / Ctrl+,** and provides search across the preferences available in your workspace.

## Connect in your terminal

Choose a terminal in **Settings → Connections**; individual hosts can override that choice. A connection opens in the terminal while Lunport's built-in SSH engine handles authentication and server identity. New or changed server fingerprints require a decision in Lunport. Check fingerprints against a trusted source before accepting them.

Use a key from the local vault, a saved password or an interactive authentication prompt. Passphrases and two-factor codes are requested for the connection. The SSH engine supports `ProxyJump`; `ProxyCommand` connections are not supported. It signs with keys kept in Lunport, so an external `IdentityFile` must be imported or moved into the vault before this engine can use it. A host relying on an implicit `~/.ssh/id_*` key must select its key explicitly.

The command-line entry point remains `sshelter connect <host>` through the rename. Windows terminals use `sshelter-cli.exe`, installed beside `sshelter.exe`. Saved MCP commands keep working with these executable names.

## Import and manage keys

Open **Keys → Import private key → From a file** to choose a supported OpenSSH private key with the system picker. You can also paste it. Lunport copies the key into its encrypted local vault and preserves the original file. Passphrase-protected keys retain their protection.

To change a key's name, select it in **Keys**, choose **Rename**, and save the new name. The key ID, fingerprint, private material and host references stay the same. Account key names sync to your other devices; a conflicting or deleted key must be resolved before renaming.

Generating a key, importing it, or adding a host does not by itself enable private-key sync. Review each key's sharing controls separately. Passwords and key passphrases are not synced. Stopping key sync does not erase copies already held by other devices.

Lunport's SSH agent provides vault keys to compatible local SSH clients while the app is running and asks before a program uses a key. Keep the app running, or enable launch at login when you need that integration. Exporting a private key creates an ordinary key file outside the vault; other programs can then use that copy independently.

## Sync your library

Open **Sync** in the upper-right toolbar, or **Settings → Local data → Open sync**. Enter and save your HTTPS relay URL if one is not built into the app. Create a sync chain on the first computer, save its **24-word sync code**, and choose **Join with sync code** on the others. Anyone holding the code can access and change the encrypted library, so keep it in a password manager.

Creating or joining includes existing hosts and Groups on that device. Previously connected devices enable **Library sync** once from the Sync workspace. Review any naming conflicts and the acknowledgement for a shared Group-format upgrade; update or stop older clients before approving that upgrade. Setup preserves source records and can resume after an interruption.

New and imported records then sync with the library. You can edit cached records offline; changes queue until the next connection. Each private key retains its own sharing decision. The relay receives ciphertext; server passwords remain local.

**Forget device** removes a device from the list. A computer that still holds the sync code may keep syncing. If a device is lost, use **Change sync code** and reconnect the computers you keep. A relay update may be required for code rotation.

The relay can run on Cloudflare Workers or your own server with Docker Compose. See [relay setup and updates](../relay/README.md). Relay URLs require HTTPS; localhost HTTP is allowed for development.

## AI access through MCP

Open **Settings → AI access**, enable access and choose the individual hosts a client may use. The pane provides the `codex mcp add` command for the installed app. The registration alias remains `sshelter` for compatibility. Reconnect your MCP client after an app update to refresh its tools.

The Records adapter uses an OS-authenticated local session broker. It can start Lunport in the background; approvals and server trust decisions appear in the app when needed.

| Tool | Behavior |
| --- | --- |
| `list_hosts` | List individually permitted hosts. |
| `get_host` | Read sanitized public settings for a permitted host. |
| `ssh_exec` | Execute a bounded command under Ask or explicitly acknowledged Auto-log. |
| `create_host` | Propose public connection settings for your review. Saving does not grant AI access or trust a server key. |
| `verify_host_key` | Verify a permitted host's fingerprint, with an in-app trust decision for a new or changed key. |

For example, a client can propose `create_host` with `{"alias":"web","hostname":"server.example.com","user":"deploy","port":22}`. Review the settings in Lunport, then separately allow that host in AI access before inspection, fingerprint verification or command execution. Creation fields cannot supply passwords, private keys, host-key pins or AI permission grants.

`verify_host_key` accepts a host ID or exact alias; the client cannot supply a trust decision. You can also use **Edit host → Server identity → Verify server fingerprint**. Verification stops before destination login or remote commands. Jump hosts may need their own credentials. A matching saved fingerprint does not prompt again; a changed destination, route, permission or pin requires verification again.

Ask reviews the exact command and can request credentials through Lunport. Auto-log execution never prompts for credentials or silently trusts a new key; complete fingerprint verification first. Authentication answers and command output are not retained in the public audit log. This permission gate covers Lunport MCP requests; other local programs still have their own operating-system access.

## Existing Legacy workspaces

Legacy mode keeps your OpenSSH configuration as the source of truth. It preserves comments, blank lines, ordering and unknown directives, changing only the edited lines. Included files remain part of the workspace. Every write is backed up; restoring also backs up the current file first.

Legacy tools include effective configuration, key hygiene, jump-chain inspection, lint, discovery from `known_hosts` or Tailscale, and host-key cleanup. Settings uses **Files & backups**, **Sync**, and **Discovery & checks** for the corresponding controls. Use the explicit migration review to copy selected hosts and keys into Records.

### Legacy sync

Open **Settings → Sync** to manage devices and selected spaces. Each selected space has a file in `~/.ssh/sshelter/`, included from your main SSH config so ordinary `ssh` can read it. These compatibility paths keep their names after the Lunport rename.

If an alias appears in more than one source, OpenSSH combines matching blocks and takes the first value for most settings; repeatable options may accumulate. Lunport blocks ambiguous edits and identifies the sources to review. Resolve duplicates before moving, renaming or removing that alias.

Turning a space off removes that device's managed file. Deleting a space removes it across the synced devices. Leaving a chain moves the local space files to `~/.ssh/sshelter-local/`, where OpenSSH continues reading them as local files. The leave review explains any changes that have not uploaded yet.

A key slot under `~/.ssh/sshelter/keys/` holds the public key; the private material lives in the vault, and the agent signs with it. Each device can use the shared key or choose its own local key for that slot. Existing file-based keys stay files until you move them into the vault. Hosts carrying sensitive directives from sync require local review before use; unsupported or unsafe configuration stays visible for correction.

### Legacy MCP

The Legacy adapter uses an authenticated localhost bridge and exposes `list_hosts`, `get_effective_config` and `run`. Each remote `run` waits for an in-app **Allow once** decision. It uses non-interactive OpenSSH authentication (`BatchMode=yes`), so key or agent authentication must already work without prompts. Passwords and passphrases are not forwarded to the AI process.

## Windows integrations

Connections use Lunport's engine and bundled console helper. Vault keys do not require Windows' ssh-agent service. For external key files that you want Windows OpenSSH to keep loaded, enable the **OpenSSH Authentication Agent** service once from an administrator PowerShell:

```powershell
Set-Service ssh-agent -StartupType Automatic
Start-Service ssh-agent
```

In-app key deployment uses Windows OpenSSH; Windows does not include `ssh-copy-id`. The app's deployment check identifies unsupported older OpenSSH builds and explains the next step.

Git for Windows has its own SSH executable, which cannot use Lunport's Windows agent pipe. To use Windows OpenSSH with Git, run:

```bash
git config --global core.sshCommand C:/Windows/System32/OpenSSH/ssh.exe
```

## Updates and help

**Settings → Updates** shows the installed version, release notes, download progress and Stable/Beta channel. Switching from Beta to Stable keeps the installed version until a newer stable version is available. Installing an update restarts the app and ends active sessions.

**Settings → About** contains the Lunport identity, installed version, project, releases, issues and license links. On macOS, **Lunport → About Lunport** also opens the native panel. Local diagnostic logs are available in **Settings → Diagnostics** in Records, or **Discovery & checks** in Legacy.
