# SSHelter

A cross-platform desktop app for managing your **local OpenSSH** setup — `~/.ssh/config`, keys, `ssh-agent`, and `known_hosts` — with lossless, format-preserving editing. macOS + Linux first (Windows later). Inspired by [hejki SSH Editor](https://www.hejki.org/ssheditor/).

## Why

Editing `~/.ssh/config` by hand is fiddly and error-prone. SSHelter gives it a clean GUI **without** rewriting your file: comments, blank lines, ordering, and unknown directives are preserved byte-for-byte (only the lines you actually change are touched).

## Stack

- **Shell:** [Tauri 2](https://v2.tauri.app/) (Rust backend) — all privileged file IO and SSH-tool invocation happen in Rust; the WebView gets **zero** filesystem/shell permission. The security boundary is the Rust command surface.
- **Frontend:** React + TypeScript + Vite, [shadcn/ui](https://ui.shadcn.com/) + Tailwind v4, TanStack Query (backend state) + Zustand (UI state).
- **Approach:** hybrid — pure-Rust where it's byte-compatible (config CST parser, keys, known_hosts), shell-out only where the system tool is clearly better (`ssh-add` Keychain/FIDO, launching `ssh` in a terminal).

## Status

🚧 Early development. **Phase 1 (a working lossless config editor)** is complete:

- **Phase 0 — foundation:** app scaffold, least-privilege capability (WebView gets zero fs/shell), unified `AppError`, safe file-IO (`fsutil`: atomic write, secure perms, timestamped backup, hash drift detection), TanStack Query + Zustand wiring, ts-rs type bridge.
- **Phase 1a — config core (Rust):** a custom **lossless CST** parser/serializer (byte-identical round-trip, golden-file tested), edit operations (single-line minimal change), multi-file `Include` loading, host DTOs, and the `config_*` Tauri command surface with a safe write path that **refuses to overwrite externally-changed files** (drift conflict guard) and backs up before writing.
- **Phase 1b — editor UI (React):** master-detail host list (search + grouping), a tabbed host editor (Connection / Authentication / Forwarding / Reliability + Advanced raw options), add/remove host, group/tags, and a drift banner. Edits send only changed fields, so untouched lines stay byte-identical.

75 automated tests pass (61 Rust + 14 frontend). Not yet implemented: launching connections, key management, ssh-agent, known_hosts UI, and signed/notarized distribution (Phases 2–6).

See the design and plans:

- Design spec: [`docs/superpowers/specs/2026-06-08-ssh-config-manager-design.md`](docs/superpowers/specs/2026-06-08-ssh-config-manager-design.md)
- Plans: [`docs/superpowers/plans/`](docs/superpowers/plans/) (Phase 0 foundation, Phase 1a config core, Phase 1b editor UI)

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

## License

[PolyForm Noncommercial](LICENSE) © Frank Sung
