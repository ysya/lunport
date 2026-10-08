# SSHelter

A cross-platform desktop app for managing your **local OpenSSH** setup — `~/.ssh/config`, keys, `ssh-agent`, and `known_hosts` — with lossless, format-preserving editing. macOS + Linux first (Windows later).

## Why

Editing `~/.ssh/config` by hand is fiddly and error-prone. SSHelter gives it a clean GUI **without** rewriting your file: comments, blank lines, ordering, and unknown directives are preserved byte-for-byte (only the lines you actually change are touched).

## Stack

- **Shell:** [Tauri 2](https://v2.tauri.app/) (Rust backend) — all privileged file IO and SSH-tool invocation happen in Rust; the WebView gets **zero** filesystem/shell permission. The security boundary is the Rust command surface.
- **Frontend:** React + TypeScript + Vite, [shadcn/ui](https://ui.shadcn.com/) + Tailwind v4, TanStack Query (backend state) + Zustand (UI state).
- **Approach:** hybrid — pure-Rust where it's byte-compatible (config CST parser, keys, known_hosts), shell-out only where the system tool is clearly better (`ssh-add` Keychain/FIDO, launching `ssh` in a terminal).

## Features

- **Lossless config editing** — a clean GUI host editor over `~/.ssh/config` and every `Include`d file; only the lines you change are touched, so comments, ordering, and unknown directives survive byte-for-byte. Create new config files from any file picker: SSHelter detects an existing `Include` glob (like `config.d/*`) and drops the file where it's already loaded, or adds the `Include` line for you.
- **Connect** — launch `ssh <host>` into your terminal of choice (macOS Terminal/iTerm2, common Linux emulators), from a per-row button, the editor header, or the menubar tray's quick-connect list. Hosts with a saved password (see the editor's Password section) log in automatically: the password is auto-filled through the built-in `SSH_ASKPASS` helper straight from your OS keychain — it never appears in the launch command. Auto-fill deliberately steps aside for jump hosts, first-time hosts (confirm the host key manually once), and keyboard-interactive/2FA hosts.
- **Command palette (⌘K)** — fuzzy-jump to any host with your recent connections surfaced first; <kbd>Enter</kbd> connects, <kbd>⌘Enter</kbd> edits, plus quick actions (new host, deploy key, toggle theme, reload).
- **Config intelligence** — per-host **key hygiene** (which IdentityFiles exist, IdentitiesOnly/explicit state), **ProxyJump chain** visualization (flags hops not defined in your config), and the resolved **effective config** (`ssh -G`); plus a global **linter** (invalid ports, unresolvable hosts, missing keys, shadowed aliases, duplicate directives).
- **Host discovery** — surface candidate hosts from `known_hosts` and your Tailscale network.
- **Backup history & restore** — every write is snapshotted; browse and restore prior versions (restore is itself backed up first and validated against managed paths).
- **Key management** — list `~/.ssh` keypairs with fingerprints and agent status, generate ed25519 keys (passphrase flow via your terminal), and copy public keys.
- **In-app key deployment** — right-click a host → *Deploy key…*: the host key is verified first (`ssh-keyscan` + fingerprint confirmation, hard abort on mismatch), then your public key is appended to the remote `authorized_keys` without opening a terminal — the password is auto-filled through a built-in `SSH_ASKPASS` helper, sent once, and never appears on a command line. Optionally remember it per host: it's stored in your operating system's keychain, never written to `~/.ssh/config` (the terminal `ssh-copy-id` flow is still available in the Keychain: *Export to host…* → *In Terminal (ssh-copy-id)*).
- **known_hosts editor** — view, search, and safely remove host-key entries (lossless line removal, backed up first) — the "host key changed after a reinstall" cleanup without the terminal.
- **Host organization** — group the sidebar by source file or by tag (tag chips on rows, toggleable), search with `#tag` / `@user` prefixes, drag-to-reorder within a file or drop onto another file group to move, ⌘-click/Shift-click to multi-select with batch move / tag / remove, per-row hover actions (connect, deploy, move, remove), duplicate as a template, rename the `Host` line itself, and give source files custom display names.
- **Settings (⌘,)** — System-Settings-style preferences: theme (system/light/dark), text size, menu bar icon & close-to-tray, launch at login, global quick-connect hotkey, default + per-host terminal, new-tab launch (iTerm2), custom config path, backup retention, discovery sources, drift auto-check, per-rule lint toggles, and settings export/import.
- **AI Access (MCP)** — expose an explicit host allowlist to local MCP clients such as Codex. Read-only host/config tools stay scoped to that list; every remote command opens SSHelter, shows the resolved destination and exact command, and waits for an in-app **Allow once** or **Deny** decision. Recent decisions and exit codes remain visible in the interface.
- **Sync (no account)** — create a sync account on one computer, enter its 24-word sync code on the others, choose which spaces of hosts each computer syncs, and your synced hosts follow you. Records are end-to-end encrypted before they reach the relay (which is open source and self-hostable). Hosts sync, and the keys they use can too: when a host starts syncing, SSHelter asks once per key whether it goes to your other computers (end-to-end encrypted like the hosts; a passphrase is never synced, so a protected key stays protected) or stays on this computer (each other computer then picks its own key once). Your servers are never changed. Passwords stay on each device.
- **Auto-update** — signed updates (minisign) delivered from GitHub Releases via the Tauri updater; checks on launch (optional) or on demand from Settings. Pick the Stable or Beta update channel in Settings → General.

## Install

Download the installer for your platform from [Releases](https://github.com/ysya/sshelter/releases/latest) (`.dmg` for macOS, `.AppImage`/`.deb`/`.rpm` for Linux, `.exe` NSIS installer for Windows — ignore the `.sig` files; they're update signatures).

**Windows:** the installer is not code-signed, so SmartScreen may warn — choose "More info → Run anyway". SSHelter drives the built-in OpenSSH client (`ssh` on PATH); connections open in Windows Terminal when installed, otherwise Command Prompt. Windows has no `ssh-copy-id`, so the terminal-based deploy is hidden there — the in-app key deploy is the Windows path, and it works with the bundled OpenSSH on both Windows 10 (8.1) and Windows 11 (8.6+). Only pre-8.1 builds (Windows 10 1809 and older) are blocked; the deploy dialog will say so — update via `winget install Microsoft.OpenSSH.Preview`. The ssh-agent ships as the "OpenSSH Authentication Agent" Windows service and is **disabled by default** — enable it once (`Set-Service ssh-agent -StartupType Automatic; Start-Service ssh-agent` in an admin PowerShell) if you want passphrase-protected key files kept loaded. Keys in SSHelter don't need that service: SSHelter runs its own agent. Git for Windows uses its own `ssh`, which can't reach SSHelter's agent; point Git at Windows' OpenSSH once with `git config --global core.sshCommand C:/Windows/System32/OpenSSH/ssh.exe` (the Keychain shows this command when Git needs it).

**macOS:** builds are not yet notarized with Apple, so Gatekeeper blocks the downloaded app (often as "damaged"). After dragging SSHelter to Applications, clear the quarantine flag once:

```bash
xattr -dr com.apple.quarantine /Applications/SSHelter.app
```

Subsequent auto-updates install in-app and don't need this again.

## AI Access (MCP)

Open **Settings → AI Access**, enable access, and explicitly select each host an AI client may see. The same pane provides a ready-to-copy `codex mcp add` command that registers the installed SSHelter executable as a local stdio MCP server.

The MCP adapter connects to the running SSHelter desktop app over an authenticated `127.0.0.1` bridge. When SSHelter isn't running, the adapter starts it in the background, without a window: the window opens when you open SSHelter (from its menu bar or tray icon, or by launching it again) or when a `run` request needs your approval. Only one SSHelter runs at a time; launching it again brings up the one already running. The adapter exposes three tools: `list_hosts`, `get_effective_config`, and `run`. `run` never executes until the desktop interface approves that exact request, and SSH output is bounded before it is returned to the client.

MCP execution uses non-interactive OpenSSH authentication (`BatchMode=yes`), so the host must already work with a key, agent, or other non-prompting authentication method. SSHelter does not forward passwords or key passphrases to the AI process. This gate controls requests made through SSHelter MCP; it is not an operating-system sandbox and cannot prevent another process running as your user from invoking `ssh` directly.

## Sync

Sync is in beta. Open **Settings → Sync**. *Create* shows a 24-word sync code — store it in a password manager; it is the only secret, and anyone holding it can read and change your synced hosts. Any computer that already syncs can show it again. On another computer choose *Join with a sync code*, paste the words, and pick the spaces to sync there. SSHelter needs an existing SSH config: on a new machine create an empty `~/.ssh/config` first.

Synced hosts live in **spaces** — for example *Personal* and *Work* — and each computer chooses which spaces it syncs. Every synced space is one file in `~/.ssh/sshelter/`, and SSHelter keeps one `Include` line at the top of your main config that lists exactly those files, so plain `ssh` keeps working and the files survive uninstalling SSHelter. If a name is in two files (two spaces, or a space and your own config), ssh applies both copies and takes each setting from the first one that sets it — the space listed first, then the rest of your config — so a setting only the later copy has (a `ProxyCommand`, say) still applies, and options that can repeat, like `IdentityFile` and `LocalForward`, add up. Until only one copy is left, SSHelter does not edit, rename, move or remove that name (it could change the wrong copy), and the editor pane explains the copies instead. When the copy ssh reads first and a later copy in another file both begin their `Host` line with the name, the sidebar marks the later copy and offers to keep it under another name or remove it. For every other copy (the one ssh reads first, a second block in its file, a name that comes second on a line like `Host db web`) the pane names the file, and you rename or remove the copy there in a text editor and choose Reload from disk. Use *Move hosts into a space* to move existing hosts in, or create one space per file (hosts from included files can be tagged with their file name). Hosts in other files stay local to that computer. Edits to a space's file made outside SSHelter sync like any other edit, including deletions; if the file disappears or is emptied, SSHelter restores it from the relay. Turning a space off removes only that computer's file; deleting a space removes it from every computer. Leaving the sync account moves that computer's space files to `~/.ssh/sshelter-local/`, where ssh keeps reading them as ordinary local files (changes to your hosts that were not uploaded yet stay in those files, and the Leave dialog says how many there are).

A synced host points its `IdentityFile` at a key slot, `~/.ssh/sshelter/keys/<name>-<id>`, and each computer decides which key that slot gives: the synced key, or, for a key that stays on each computer, one you pick there. So the same host text works on every computer. The private key lives in SSHelter's vault on each computer (encrypted, with its key in your operating system's keychain); the slot holds only the public key, and `ssh` gets the key from SSHelter's agent, which asks you before a program uses it. Keys in SSHelter work only while SSHelter is running, so turn on launch at login (the Keychain suggests it). Nothing in your own `~/.ssh` keys is moved or changed: setting up a key copies it into SSHelter, and your file stays where it is. Keys a computer already used as files before this version stay files until you press *Move* in the Keychain. The *Keychain* (next to Hosts in the sidebar) lists every key with where each computer keeps it; when you need a file, *Export private key…* saves one, which any program can then use without asking and SSHelter doesn't keep track of. *Stop syncing* never deletes the copies other computers already have, and a key that's replaced on a computer is kept, never deleted. Only OpenSSH-format private keys can be synced (convert an older PEM key with `ssh-keygen -p -f <file>`); any key can be kept on its computer. A synced key without a passphrase can be used by anyone who has your sync code, and by every computer that joins; a key with a passphrase is still protected by it, because the passphrase is never synced.

A synced host that brings `ProxyCommand`, `RemoteCommand`, `ForwardAgent`, `StrictHostKeyChecking` or another setting that runs programs, shares your credentials, environment or network, or relaxes host-key checks waits until you approve it on each computer (while the sync code is being changed or was changed on another computer, or SSHelter needs an update, hosts can't be approved or rejected, and Settings → Sync says why). Synced hosts can't use `Include`, and their `HostName`, `User`, `HostKeyAlias` and `ProxyJump` must each be one word without characters a shell would interpret; SSHelter lists the local hosts it can't move into a space, with the reason, and pauses a space whose file contains one (the Status row, the Spaces list and the space's group header in the sidebar say why).

*Forget* (in the Devices list) only removes a computer from that list; a computer that still has the sync code keeps syncing. If a computer is lost, use *Change sync code*: the old code stops working, and each of your other computers asks for the new one (changes they had not uploaded yet are kept). Changing the sync code needs a relay that can freeze data; SSHelter tells you when yours needs an update first.

Computers that synced with SSHelter 0.16 (or the 0.17.0-1 beta) upgrade by themselves: their synced hosts move into a space named *Synced*. Update SSHelter on all of them — a computer still on 0.16 (or the 0.17.0-1 beta) does not see changes made after the upgrade.

The relay stores only ciphertext and is open source (`relay/`). Builds made without a built-in relay ask for one first, so deploy your own to Cloudflare. The free Workers plan covers a few computers syncing a handful of spaces; Cloudflare's free daily limits (100,000 Durable Object requests and 100,000 rows written) are the ceiling:

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/ysya/sshelter/tree/main/relay)

The button copies `relay/` into a new repository on your GitHub or GitLab account and deploys it to your Cloudflare account. When it finishes, enter the Worker's `https://…workers.dev` URL in *Settings → Sync → Relay URL* on every computer you sync, then create or join. To deploy from a checkout instead: `cd relay && npm install && npx wrangler login && npx wrangler deploy`. To run it on your own server, use Docker Compose ([relay/README.md](relay/README.md#self-host-with-docker-compose)). To update a relay you deployed, see [Updating your relay](relay/README.md#updating-your-relay). Relay URLs must use `https://`, except `localhost` for development.

## Development

Prerequisites: Rust (rustup), Node + pnpm, and platform build deps (macOS: Xcode Command Line Tools; Linux: `libwebkit2gtk-4.1-dev build-essential libssl-dev librsvg2-dev`).

```bash
pnpm install            # install JS deps
pnpm tauri dev          # run the desktop app (Rust + Vite dev server)
pnpm build              # type-check + build the frontend
```

Tests:

```bash
pnpm test               # frontend unit tests (vitest)
cd src-tauri && cargo test   # backend tests
```

### Publishing a beta

Betas reach machines whose **Settings → General → Update channel** is **Beta**. In GitHub Actions run **publish beta** with a version `X.Y.Z-N` (numeric suffix only, e.g. `0.16.1-1`) newer than the current release. The workflow creates the prerelease `vX.Y.Z-N`, builds every platform, then points the `updater-beta` release's `latest.json` at it. Stable releases keep going through release-please and are offered on the Beta channel too.

If a build leg fails, use **Re-run failed jobs** on that run: it keeps the same inputs and commit, and the manifest job then runs. Never use `build-platform.yml` for a beta: it builds the tag's commit without the beta version stamp and does not update the Beta manifest, so it refuses beta tags. To publish the same version again, delete both the prerelease and its tag first. When the manifest job runs for a republished or rebuilt version, it replaces the channel's copy, so the old signatures do not linger. Machines that already installed that version are not offered it again; publish the next `-N` for them.

To point the Beta channel at a release by hand, run **update beta channel** with its tag (for example `v0.16.0`). It is the recovery path after `build-platform.yml` rebuilt a platform of a stable release (that workflow leaves the Beta manifest alone, and the rebuilt installer has a new signature), and for a **beta-manifest** job that was cancelled or skipped. It first checks that the release's `latest.json` is complete, never moves the channel backwards, and leaves an up-to-date channel alone, so re-running it is safe.

## Recommended IDE Setup

[VS Code](https://code.visualstudio.com/) + [Tauri](https://marketplace.visualstudio.com/items?itemName=tauri-apps.tauri-vscode) + [rust-analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer).

## License

[PolyForm Noncommercial](LICENSE) © Frank Sung
