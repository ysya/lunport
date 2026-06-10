# SSHelter

A cross-platform desktop app for managing your **local OpenSSH** setup — `~/.ssh/config`, keys, `ssh-agent`, and `known_hosts` — with lossless, format-preserving editing. macOS + Linux first (Windows later). Inspired by [hejki SSH Editor](https://www.hejki.org/ssheditor/).

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

## Status

🚧 Early development, but well past a usable editor. The security boundary is strict: the WebView has **zero** filesystem/shell permission — all privileged IO and SSH-tool invocation happen in audited Rust commands (argv vectors only, never `sh -c`; alias inputs are charset-validated and reject option-injection).

- **Phase 0 — foundation:** app scaffold, least-privilege capability, unified `AppError`, safe file-IO (`fsutil`: atomic write, secure perms, timestamped backup, hash drift detection), TanStack Query + Zustand wiring, ts-rs type bridge.
- **Phase 1a — config core (Rust):** a custom **lossless CST** parser/serializer (byte-identical round-trip, golden-file tested), edit operations (single-line minimal change), multi-file `Include` loading, host DTOs, and the `config_*` Tauri command surface with a safe write path that **refuses to overwrite externally-changed files** (drift conflict guard) and backs up before writing.
- **Phase 1b — editor UI (React):** master-detail host list (search + collapsible source-file grouping), a System-Settings-style grouped host editor (Connection / Authentication / Forwarding / Reliability + Advanced raw options), add/remove host, tags, a live `ssh_config` inspector, and a drift banner. Edits send only changed fields, so untouched lines stay byte-identical.
- **v0.2 — connect, intelligence & discovery:** terminal launcher + menubar tray, ⌘K command palette, per-host config intelligence (key hygiene / ProxyJump chain / effective config), global lint, `known_hosts`+Tailscale discovery, and backup history/restore.

130 automated tests pass (116 Rust + 14 frontend). Not yet implemented: in-app key management, ssh-agent control, a full `known_hosts` editor, and signed/notarized distribution.

See the design and plans:

- Design spec: [`docs/superpowers/specs/2026-06-08-ssh-config-manager-design.md`](docs/superpowers/specs/2026-06-08-ssh-config-manager-design.md)
- Plans: [`docs/superpowers/plans/`](docs/superpowers/plans/)

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
