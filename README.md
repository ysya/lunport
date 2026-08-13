# SSHelter

A cross-platform desktop app for managing your **local OpenSSH** setup — `~/.ssh/config`, keys, `ssh-agent`, and `known_hosts` — with lossless, format-preserving editing. macOS + Linux first (Windows later).

## Why

Editing `~/.ssh/config` by hand is fiddly and error-prone. SSHelter gives it a clean GUI **without** rewriting your file: comments, blank lines, ordering, and unknown directives are preserved byte-for-byte (only the lines you actually change are touched).

## Stack

- **Shell:** [Tauri 2](https://v2.tauri.app/) (Rust backend) — all privileged file IO and SSH-tool invocation happen in Rust; the WebView gets **zero** filesystem/shell permission. The security boundary is the Rust command surface.
- **Frontend:** React + TypeScript + Vite, [shadcn/ui](https://ui.shadcn.com/) + Tailwind v4, TanStack Query (backend state) + Zustand (UI state).
- **Approach:** hybrid — pure-Rust where it's byte-compatible (config CST parser, keys, known_hosts), shell-out only where the system tool is clearly better (`ssh-add` Keychain/FIDO, launching `ssh` in a terminal).

## Features

- **Lossless config editing** — a clean GUI host editor over `~/.ssh/config` and every `Include`d file; only the lines you change are touched, so comments, ordering, and unknown directives survive byte-for-byte.
- **Connect** — launch `ssh <host>` into your terminal of choice (macOS Terminal/iTerm2, common Linux emulators), from a per-row button, the editor header, or the menubar tray's quick-connect list.
- **Command palette (⌘K)** — fuzzy-jump to any host; <kbd>Enter</kbd> connects, <kbd>⌘Enter</kbd> edits, plus quick actions (new host, toggle theme, reload).
- **Config intelligence** — per-host **key hygiene** (which IdentityFiles exist, IdentitiesOnly/explicit state), **ProxyJump chain** visualization (flags hops not defined in your config), and the resolved **effective config** (`ssh -G`); plus a global **linter** (invalid ports, unresolvable hosts, missing keys, shadowed aliases, duplicate directives).
- **Host discovery** — surface candidate hosts from `known_hosts` and your Tailscale network.
- **Backup history & restore** — every write is snapshotted; browse and restore prior versions (restore is itself backed up first and validated against managed paths).
- **Key management** — list `~/.ssh` keypairs with fingerprints and agent status, generate ed25519 keys (passphrase flow via your terminal), and copy public keys.
- **In-app key deployment** — right-click a host → *Deploy key…*: the host key is verified first (`ssh-keyscan` + fingerprint confirmation, hard abort on mismatch), then your public key is appended to the remote `authorized_keys` without opening a terminal — the password is auto-filled through a built-in `SSH_ASKPASS` helper, sent once, and never appears on a command line. Optionally remember it per host: it's stored in your operating system's keychain, never written to `~/.ssh/config` (the terminal `ssh-copy-id` flow is still available from the Keys dialog).
- **known_hosts editor** — view, search, and safely remove host-key entries (lossless line removal, backed up first) — the "host key changed after a reinstall" cleanup without the terminal.
- **Host organization** — drag-to-reorder within a file, move hosts between config files (byte-identical block moves), duplicate as a template, rename the `Host` line itself, and give source files custom display names.
- **Settings (⌘,)** — System-Settings-style preferences: theme (system/light/dark), text size, menu bar icon & close-to-tray, launch at login, global quick-connect hotkey, default + per-host terminal, new-tab launch (iTerm2), custom config path, backup retention, discovery sources, drift auto-check, per-rule lint toggles, and settings export/import.
- **Auto-update** — signed updates (minisign) delivered from GitHub Releases via the Tauri updater; checks on launch (optional) or on demand from Settings.

## Install

Download the installer for your platform from [Releases](https://github.com/ysya/sshelter/releases/latest) (`.dmg` for macOS, `.AppImage`/`.deb`/`.rpm` for Linux — ignore the `.sig` files; they're update signatures).

**macOS:** builds are not yet notarized with Apple, so Gatekeeper blocks the downloaded app (often as "damaged"). After dragging SSHelter to Applications, clear the quarantine flag once:

```bash
xattr -dr com.apple.quarantine /Applications/SSHelter.app
```

Subsequent auto-updates install in-app and don't need this again.

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

## Recommended IDE Setup

[VS Code](https://code.visualstudio.com/) + [Tauri](https://marketplace.visualstudio.com/items?itemName=tauri-apps.tauri-vscode) + [rust-analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer).

## License

[PolyForm Noncommercial](LICENSE) © Frank Sung
