# Changelog

## [0.5.1](https://github.com/ysya/sshelter/compare/v0.5.0...v0.5.1) (2026-06-12)


### Bug Fixes

* **ui:** keep toasts clickable above modal dialogs ([cf668fd](https://github.com/ysya/sshelter/commit/cf668fddba13bbb787b61384c8fb98a2fe29ff88))
* **updater:** keep checking for updates while the app runs ([2b0a1ab](https://github.com/ysya/sshelter/commit/2b0a1aba5990e1d7a8ba7fdc1ea8ea598e8b1fa9))

## [0.5.0](https://github.com/ysya/sshelter/compare/v0.4.0...v0.5.0) (2026-06-11)


### Features

* **app:** launch-at-login, global hotkey, settings export/import, ⌘F/⌘N ([636144b](https://github.com/ysya/sshelter/commit/636144b7dfec191bc515ff7b7db0776235ce86b0))
* **hosts:** move/duplicate host across files, per-host terminal override, raw file viewer ([4eb8e52](https://github.com/ysya/sshelter/commit/4eb8e52751db1dc8a29733f1497b4cd4b162801c))
* **keys:** SSH key management — list/fingerprints/agent status, generate ed25519, copy pubkey, ssh-copy-id deploy via terminal ([c54f1ab](https://github.com/ysya/sshelter/commit/c54f1ab1038a8154dca0ab2c3cc3f869d09b32b7))
* **known-hosts:** known_hosts viewer — search + safe entry removal (lossless, backed up) ([0130f51](https://github.com/ysya/sshelter/commit/0130f510fbddd2f9bd375a914cef7191fbc63a7d))
* **ui:** drag-to-reorder hosts within a config file ([2226433](https://github.com/ysya/sshelter/commit/2226433cf3cba13036fe7df03a76c23f5799820e))
* **ui:** user-adjustable text size (Settings &gt; Appearance, scales the rem-based UI) ([09b9d2a](https://github.com/ysya/sshelter/commit/09b9d2ab0e316399af4826c18f0f4a5d307b3d86))


### Bug Fixes

* **config:** address option toggles by occurrence index (same-keyword pairs hit the wrong line) ([bbbf10f](https://github.com/ysya/sshelter/commit/bbbf10f96c5506418c59881504ffd274976cf41d))
* **ui:** overlay buttons centered with translate (-translate-y-1/2) lost ([4eb8e52](https://github.com/ysya/sshelter/commit/4eb8e52751db1dc8a29733f1497b4cd4b162801c))

## [0.4.0](https://github.com/ysya/sshelter/compare/v0.3.0...v0.4.0) (2026-06-11)


### ⚠ BREAKING CHANGES

* **config:** existing next-to-file .bak snapshots are moved into the new backups root on first load; restore only accepts backups inside the new location.

### Features

* **config:** rename host — lossless Host-line pattern editing from the editor header ([6ea2e1a](https://github.com/ysya/sshelter/commit/6ea2e1a979cb0e482cbde85ea99b635fff0ad4da))
* **ui:** sidebar v2 — file scope filter, compact rows, sticky headers, wildcard defaults footer, persisted nav state ([0e7cb97](https://github.com/ysya/sshelter/commit/0e7cb97b00d0430dae6a19ea1ba68812d0f05414))
* **ui:** user-defined display aliases for config file groups (double-click to rename) ([b450afc](https://github.com/ysya/sshelter/commit/b450afce1a5c1651781a3a438ee20ce56e807995))


### Bug Fixes

* **config:** relocate backups out of ssh-visible dirs (glob Includes were loading .bak files) ([c7c4707](https://github.com/ysya/sshelter/commit/c7c47078a24c427bfb12bfe5f54b70c4bb63e706))
* **ui:** label colliding config files by their distinctive ancestor (orbstack, not ssh/config) ([0c236ac](https://github.com/ysya/sshelter/commit/0c236ac891a94332044ad5f3ef4a97d551c76ff9))

## [0.3.0](https://github.com/ysya/sshelter/compare/v0.2.0...v0.3.0) (2026-06-10)


### Features

* **app:** auto-update via tauri-plugin-updater ([10f096b](https://github.com/ysya/sshelter/commit/10f096ba5f193d2ade835cb6ab8dbb51fa9851a9))

## 0.2.0 (2026-06-10)


### Features

* add app_platform smoke command and wire error/fsutil modules ([55b35a2](https://github.com/ysya/sshelter/commit/55b35a2e26d0ca40f42a5fbf9e90129694ee95de))
* add AppError unified command error type ([af03563](https://github.com/ysya/sshelter/commit/af03563bcd9af9692e4b9bd53fb69b2f44114d6d))
* **config:** app state + config_* Tauri commands + safe write path ([5647071](https://github.com/ysya/sshelter/commit/5647071468752d17298580d52da12c9417b16fb7))
* **config:** backup history listing + safe restore ([26cc242](https://github.com/ysya/sshelter/commit/26cc242d88a8a17153850232e0d0a315a4fec071))
* **config:** CST edit operations (set/add/remove/toggle/reorder/group) ([a4a5099](https://github.com/ysya/sshelter/commit/a4a5099a5d46b8fd35d42a0a0eb387201e6f4edf))
* **config:** CST model + quote-aware single-line lexer ([fa67dec](https://github.com/ysya/sshelter/commit/fa67dec2bce93f63bcfc9a147200f94fbe13859c))
* **config:** intelligence module — effective-config (ssh -G), linter, ProxyJump chain, key-hygiene ([3a70ba8](https://github.com/ysya/sshelter/commit/3a70ba8ba946ffeb9e12e0fa81ca5bd13dfe1c96))
* **config:** lossless parser + serializer with golden round-trip corpus ([de4b150](https://github.com/ysya/sshelter/commit/de4b150f51b52cffc1ba219f602bbbbc63e96346))
* **config:** multi-file Include loading + host DTOs ([2d196b6](https://github.com/ysya/sshelter/commit/2d196b6fe68e9878f538ee936391343c31673948))
* **connect:** terminal launcher with per-emulator argv + alias validation ([05f10f1](https://github.com/ysya/sshelter/commit/05f10f110b949328d8f1ab58a894b7f1e2e0d3b2))
* **core:** settings backend — lint rule ids, backup retention, tray toggle, close-to-tray, iTerm2 new-tab ([c92ed27](https://github.com/ysya/sshelter/commit/c92ed27ac5a073230f84580afe1ae70990cb9f09))
* **discover:** known_hosts + Tailscale host discovery ([c861d81](https://github.com/ysya/sshelter/commit/c861d81a664dd6994c5c3d9092719c138aad6139))
* **error:** add AppError::Parse variant ([7136393](https://github.com/ysya/sshelter/commit/7136393551de59c48b60a3bb32603fc5c1ec638e))
* establish ts-rs Rust-&gt;TS type bridge (Fingerprint) ([9d36ce3](https://github.com/ysya/sshelter/commit/9d36ce3be6e98f17a097fb76ea3ee5f57c99b479))
* **fsutil:** fsync parent dir after rename; document symlink/perms semantics ([43db87b](https://github.com/ysya/sshelter/commit/43db87b8ddb0129b7a0885ee145a9509b3740c0a))
* **fsutil:** safe file IO — atomic write, perms, backup, drift detection ([95d273b](https://github.com/ysya/sshelter/commit/95d273bf432ebcd994275fdc93dbc4820df246ec))
* **tray:** menubar quick-connect menu rebuilt on config load ([bae8a6e](https://github.com/ysya/sshelter/commit/bae8a6ea38430ff87e51378c7afc7b0e4754e8fb))
* **ui:** center the host editor at a comfortable column width (System Settings style) ([e04ddd4](https://github.com/ysya/sshelter/commit/e04ddd450b3b41d8e73bbbabca3f3d149011224b))
* **ui:** collapsible sidebar groups + disambiguate duplicate group labels (shortest-unique path) ([36ec195](https://github.com/ysya/sshelter/commit/36ec195d565be69019988143286eb6fa5625c068))
* **ui:** command palette (⌘K) with connect/edit + terminal picker + per-row connect ([7d7ad65](https://github.com/ysya/sshelter/commit/7d7ad65aa8f6802ac19b32f7caeef29bbf2dd169))
* **ui:** config editor data layer, field-diff logic, app shell + host list ([ef06e51](https://github.com/ysya/sshelter/commit/ef06e51f40a69a416fda97ee00cd4152bc3aac52))
* **ui:** config intelligence panels + lint/discover/history dialogs ([17b09d9](https://github.com/ysya/sshelter/commit/17b09d9f1304614ac4b32dc8d8a357b1158693a4))
* **ui:** host editor, add/remove host, group/tags, drift banner ([4713c29](https://github.com/ysya/sshelter/commit/4713c2900dc8f9b373131456e701d5dbc0686f30))
* **ui:** native instrument-panel redesign — stacked editor, system fonts (mono for values), graphite + system-blue, source-list, refined chrome ([ed87420](https://github.com/ysya/sshelter/commit/ed87420d0b15a0446567aa86cc17a97755ec9f12))
* **ui:** native macOS desktop shell — fixed scroll regions, overlay titlebar, compact density, settings-style editor ([3cb1974](https://github.com/ysya/sshelter/commit/3cb197406776d85f68bffa097e66b3b3a140c62d))
* **ui:** refined terminal-shelter redesign + dark mode ([d230b9e](https://github.com/ysya/sshelter/commit/d230b9e18b751cc103461d81064c3e61fc2f3c96))
* **ui:** Settings sheet (⌘,) — move theme + default terminal out of the toolbar ([efbc506](https://github.com/ysya/sshelter/commit/efbc50623af52022c53476b15a02a34d8eb7807f))
* **ui:** sidebar Settings window — tray, close-to-tray, new-tab connect, config path, backup retention, discovery/drift/lint controls ([1697c82](https://github.com/ysya/sshelter/commit/1697c82eefcc7cb52bd7fe14c4329c471d40cdb8))
* **ui:** toolbar reload-from-disk button (manual refresh after external edits) ([30c3575](https://github.com/ysya/sshelter/commit/30c3575351c0c8f56ca335b1544849842249f207))
* **ui:** two-pane host editor — live ssh_config preview fills wide windows, stacks when narrow ([a5c76c3](https://github.com/ysya/sshelter/commit/a5c76c3dbfaf9a39f17c087b215bf5bb07b8f81d))
* wire TanStack Query + Zustand + app_platform IPC smoke ([29a8fb9](https://github.com/ysya/sshelter/commit/29a8fb947d36560938422e6c0c643724157ffc0d))


### Bug Fixes

* **config:** clamp backup retention to &gt;=1 (0 would prune the fresh backup) ([231b874](https://github.com/ysya/sshelter/commit/231b874cea7a6e3b2158c9ba7de327f4264d7b74))
* **config:** lint matches secondary host aliases, skips disabled directives + ProxyJump none; chain handles cross-host cycles ([5f66f19](https://github.com/ysya/sshelter/commit/5f66f19e97dbd11dcb4742c6a447d27ae512a590))
* **config:** preserve trailing whitespace in lexer split via trailing_ws field ([bfd5f1f](https://github.com/ysya/sshelter/commit/bfd5f1ff8f6a3bc71302dd1d315e788fa33ca33b))
* **config:** refuse to overwrite externally-changed files (drift conflict guard) ([235cf20](https://github.com/ysya/sshelter/commit/235cf20514f6abf090d233cdedd05c8f70c64c9d))
* **config:** skip unreadable Include files instead of aborting whole load ([f5510b5](https://github.com/ysya/sshelter/commit/f5510b585d4fc75390b2c483b64a576a7efc1183))
* **config:** strip newlines from values, insert new fields before trailing blank, doc host-disable asymmetry ([d602570](https://github.com/ysya/sshelter/commit/d602570902893da6cbfae56bcdb68a84c01df0f5))
* **connect:** reject leading-dash aliases (ssh argument-injection / -F config RCE) ([c58c733](https://github.com/ysya/sshelter/commit/c58c733903a8d46ef18039a1b79354de93796c54))
* **ui:** bump root font-size 13px→15px so body text lands at the intended ~13px (was rendering too small) ([b618d4c](https://github.com/ysya/sshelter/commit/b618d4c62346525b002bf4c5f0f9c68157d2d209))
* **ui:** hide number-input spinner steppers (type the value directly) ([482812c](https://github.com/ysya/sshelter/commit/482812c0f1b3e1364dd2dd24dfcb0197bdc87dd5))
* **ui:** host rows show resolved user@hostname as a distinct subtitle (no more duplicated alias) ([52c1292](https://github.com/ysya/sshelter/commit/52c129237454fb36a2685e63cffa9bedcb7735e7))
* **ui:** tri-state (yes/no/unset) selects so editing never silently deletes an explicit 'no' line ([4f8ecf3](https://github.com/ysya/sshelter/commit/4f8ecf387781a5770c3facaa79d7eb84daa1e85d))
* **window:** grant core:window start-dragging + toggle-maximize so the toolbar drags the window ([8a19dc0](https://github.com/ysya/sshelter/commit/8a19dc06651fa778de5662c5fa1c3ea71ed46d44))


### Miscellaneous Chores

* release 0.1.0 ([bc44ffa](https://github.com/ysya/sshelter/commit/bc44ffa6817fd9627d7fe3fc0d077b230a3fc2a2))
* release 0.2.0 ([237c744](https://github.com/ysya/sshelter/commit/237c744b72a0412bd007d1e4528400bfe363cae4))
