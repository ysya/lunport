# SSHelter

A cross-platform desktop app for managing your **local OpenSSH** setup — `~/.ssh/config`, keys, `ssh-agent`, and `known_hosts` — with lossless, format-preserving editing. macOS + Linux first (Windows later). Inspired by [hejki SSH Editor](https://www.hejki.org/ssheditor/).

## Why

Editing `~/.ssh/config` by hand is fiddly and error-prone. SSHelter gives it a clean GUI **without** rewriting your file: comments, blank lines, ordering, and unknown directives are preserved byte-for-byte (only the lines you actually change are touched).

## Stack

- **Shell:** [Tauri 2](https://v2.tauri.app/) (Rust backend) — all privileged file IO and SSH-tool invocation happen in Rust; the WebView gets **zero** filesystem/shell permission. The security boundary is the Rust command surface.
- **Frontend:** React + TypeScript + Vite, [shadcn/ui](https://ui.shadcn.com/) + Tailwind v4, TanStack Query (backend state) + Zustand (UI state).
- **Approach:** hybrid — pure-Rust where it's byte-compatible (config CST parser, keys, known_hosts), shell-out only where the system tool is clearly better (`ssh-add` Keychain/FIDO, launching `ssh` in a terminal).

## Status

🚧 Early development. **Phase 0 (foundation & boundary)** is complete: app scaffold, least-privilege capability, unified `AppError`, safe file-IO utilities (`fsutil`: atomic write, secure perms, timestamped backup, drift detection), an `app_platform` IPC smoke command, the TanStack Query + Zustand wiring, and a ts-rs Rust→TS type bridge.

See the design and plans:

- Design spec: [`docs/superpowers/specs/2026-06-08-ssh-config-manager-design.md`](docs/superpowers/specs/2026-06-08-ssh-config-manager-design.md)
- Phase 0 plan: [`docs/superpowers/plans/2026-06-08-sshelter-phase0-foundation.md`](docs/superpowers/plans/2026-06-08-sshelter-phase0-foundation.md)

## Development

Prerequisites: Rust (rustup), Node + pnpm, and platform build deps (macOS: Xcode Command Line Tools; Linux: `libwebkit2gtk-4.1-dev build-essential libssl-dev librsvg2-dev`).

```bash
pnpm install            # install JS deps
pnpm tauri dev          # run the desktop app (Rust + Vite dev server)
pnpm build              # type-check + build the frontend
```

Backend tests:

```bash
cd src-tauri && cargo test
```

## Recommended IDE Setup

[VS Code](https://code.visualstudio.com/) + [Tauri](https://marketplace.visualstudio.com/items?itemName=tauri-apps.tauri-vscode) + [rust-analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer).
