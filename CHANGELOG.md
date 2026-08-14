# Changelog

## [0.13.0](https://github.com/ysya/sshelter/compare/v0.12.0...v0.13.0) (2026-08-14)


### Features

* **keys:** hint how to enable the Windows ssh-agent service ([122b0a3](https://github.com/ysya/sshelter/commit/122b0a3c1f5d762a4844abd5fb48120ac37220a1))
* **mcp:** add UI-controlled SSH access ([963467e](https://github.com/ysya/sshelter/commit/963467e5b5d26b8d9d78ea6e56a27e1ca14f7836))

## [0.12.0](https://github.com/ysya/sshelter/compare/v0.11.0...v0.12.0) (2026-08-14)


### Features

* **windows:** build Windows installers and launch wt/cmd terminals ([455fa6b](https://github.com/ysya/sshelter/commit/455fa6ba61b6a38479a0e4e8f5e17ff20f8c3d37))

## [0.11.0](https://github.com/ysya/sshelter/compare/v0.10.0...v0.11.0) (2026-08-13)


### Features

* **config:** new-config-file dialog with live include preview ([9c3ac32](https://github.com/ysya/sshelter/commit/9c3ac32b1b58e87f70f2b3ce9dffae42004d25c0))
* **config:** plan and create included config files ([f1fe215](https://github.com/ysya/sshelter/commit/f1fe215a8d16d4b49e8fcef3a3b55cbad4a17561))
* **host-list:** create a new config file from every file picker ([b3668d0](https://github.com/ysya/sshelter/commit/b3668d0df7a17fd8e2ad62014ae1d64a927dba4d))

## [0.10.0](https://github.com/ysya/sshelter/compare/v0.9.0...v0.10.0) (2026-08-13)


### Features

* **host-list:** drag a host onto another file group to move it ([453593f](https://github.com/ysya/sshelter/commit/453593f268643e1de4219e58fc1f2082defa4676))
* **host-list:** hover actions menu with move and remove ([efb67e4](https://github.com/ysya/sshelter/commit/efb67e48fd620d864669d66be3513274ad0968ee))
* **host-list:** multi-select with batch move, tag and remove ([c8e375a](https://github.com/ysya/sshelter/commit/c8e375a7cddb8153bda3d9c33e67d22c0109d01f))

## [0.9.0](https://github.com/ysya/sshelter/compare/v0.8.0...v0.9.0) (2026-08-13)


### Features

* **host-list:** add #tag [@user](https://github.com/user) search prefixes ([9e26e08](https://github.com/ysya/sshelter/commit/9e26e083f09243a83e539a116d22acfd10dfbfa2))
* **host-list:** group hosts by file or by tag ([4bc643b](https://github.com/ysya/sshelter/commit/4bc643b3ba6f9344e6e509826fc88688e574632c))
* **host-list:** show tag chips on host rows ([9c7b905](https://github.com/ysya/sshelter/commit/9c7b905a3fba7867087fc77e8fae0f1262d76e36))
* **palette:** surface recent connections first ([daae0d2](https://github.com/ysya/sshelter/commit/daae0d297a3dd5f8a068ff16c51ab860e80fb87b))


### Bug Fixes

* **host-editor:** demote deploy button to the menu once a key is configured ([29df22f](https://github.com/ysya/sshelter/commit/29df22f7e95b7fad509538bd08144e94cafff8d6))

## [0.8.0](https://github.com/ysya/sshelter/compare/v0.7.0...v0.8.0) (2026-08-13)


### Features

* **deploy:** add editor, palette, hygiene and keys-dialog entry points ([b73501e](https://github.com/ysya/sshelter/commit/b73501e0b218cb5bccd870ae8f392f965b7c4677))
* **deploy:** add identity-file write-back decision helpers ([c690d74](https://github.com/ysya/sshelter/commit/c690d7450e452535e2443e5dad2e3792d9471e2a))
* **deploy:** write IdentityFile back after a successful deploy ([7c3169f](https://github.com/ysya/sshelter/commit/7c3169fb7c3248e605ceb9b922771c88f50fdca1))
* **host-editor:** pick IdentityFile from detected keys or a file dialog ([e939e1a](https://github.com/ysya/sshelter/commit/e939e1a24b86126678d5edff69ae141abd291d14))


### Bug Fixes

* **ui:** disable autocorrect and autocapitalize on all text inputs ([d806a66](https://github.com/ysya/sshelter/commit/d806a66ba7afcd59a1705df1f995ad493ec8f502))

## [0.7.0](https://github.com/ysya/sshelter/compare/v0.6.1...v0.7.0) (2026-08-13)


### Features

* **askpass:** add SSH_ASKPASS helper mode with prompt whitelist ([e413437](https://github.com/ysya/sshelter/commit/e413437095fcb199c2d5517e229fc242d0cfd2e0))
* **askpass:** dispatch to helper mode before Tauri init ([be79556](https://github.com/ysya/sshelter/commit/be79556b1ff7c295766123fa477fdcd8c7c90d54))
* **deploy:** add deploy/precheck/secrets Tauri commands ([1b1b449](https://github.com/ysya/sshelter/commit/1b1b4491f09c6f26de1491b92bc817bf8d72052e))
* **deploy:** add host key precheck against known_hosts ([dbd93c0](https://github.com/ysya/sshelter/commit/dbd93c0b4bf7633281678dad90d1b3e4e6a21cb6))
* **deploy:** add in-app key deployment dialog ([b3c3780](https://github.com/ysya/sshelter/commit/b3c3780a63944832f5a00e69fb2ffad32b70520d))
* **deploy:** add pure argv builder, remote script and outcome classifier ([a343133](https://github.com/ysya/sshelter/commit/a343133f5e57d6b416d123c681744a44db4de36e))
* **deploy:** warn about old OpenSSH and password-blocking config ([94c8b19](https://github.com/ysya/sshelter/commit/94c8b1981de7d575fa2c7550b4a0214d71203744))
* **host-editor:** manage the host password stored in the OS keychain ([79f70fd](https://github.com/ysya/sshelter/commit/79f70fdd0c74817179c92b84506ce70594892542))
* **host-list:** right-click a host to deploy a key ([777fe89](https://github.com/ysya/sshelter/commit/777fe89d99b2968278b6bc6e232eb86f6683ea53))
* **queries:** add deploy and host-password hooks ([d6a89a9](https://github.com/ysya/sshelter/commit/d6a89a9ba8ffab921ef7715d51c84814134e1eed))
* **secrets:** add OS keychain wrapper for per-host passwords ([be59a76](https://github.com/ysya/sshelter/commit/be59a76211a2c456fed964edde808c784f8ef3a5))


### Bug Fixes

* **askpass:** anchor prompt whitelist to real OpenSSH client behavior ([325b34c](https://github.com/ysya/sshelter/commit/325b34ce49810ad6cf3ba54e4dd4f749c141fd6e))
* **askpass:** correct module doc and use lossy argv decoding ([e1a3c68](https://github.com/ysya/sshelter/commit/e1a3c683729249182c093aed44bacf75a22dd4cf))
* **deploy-ui:** trust the host key by confirmed fingerprint, not key line ([d0ee77d](https://github.com/ysya/sshelter/commit/d0ee77d28aac33e279a2268652378752c03b430b))
* **deploy:** close config/timeout/keychain gaps in the deploy commands ([a075bbd](https://github.com/ysya/sshelter/commit/a075bbdb81d51166d3d2ea41f2159d9fce45aeae))
* **deploy:** guard authorized_keys corruption and misclassified auth failures ([aac2fc9](https://github.com/ysya/sshelter/commit/aac2fc9e228c37a6a3b893a401ecad192c146c33))
* **deploy:** parse known_hosts markers so CA-trusted and revoked hosts are handled correctly ([646ac75](https://github.com/ysya/sshelter/commit/646ac75f278335787b78a620de8e4a11d9dbe1e1))
* **secrets:** trust any keyring error as unavailable, guard test cleanup ([5f1e44a](https://github.com/ysya/sshelter/commit/5f1e44a4f264614ed4725c3b0f267871d678e66a))

## [0.6.1](https://github.com/ysya/sshelter/compare/v0.6.0...v0.6.1) (2026-06-19)


### Bug Fixes

* **host-list:** show the Defaults group at the top of each file section ([022087a](https://github.com/ysya/sshelter/commit/022087a90dd58c55e1c72338e5229e472d08f9c6))

## [0.6.0](https://github.com/ysya/sshelter/compare/v0.5.1...v0.6.0) (2026-06-19)


### Features

* **host-list:** add target-file resolver for right-click add-host ([3934ab1](https://github.com/ysya/sshelter/commit/3934ab1d50f41658c75bcedc37aa41269bb45dbd))
* **host-list:** right-click file headers to add a host, view, or rename ([b809e95](https://github.com/ysya/sshelter/commit/b809e95ddf5bcc81eee4d984ee46ea920777e036))
* **host-list:** seed AddHostDialog target from right-click file ([c71a7a7](https://github.com/ysya/sshelter/commit/c71a7a75c2fa41bf2841fd73a6e479577af2e2c1))
* **host-list:** track right-click add-host target file in ui store ([33288f2](https://github.com/ysya/sshelter/commit/33288f2aa0821a2d8311a2cab5a960a33cbe6788))
* **ui:** add context-menu primitive ([80155e0](https://github.com/ysya/sshelter/commit/80155e03ac7d3061c285b4fe6144c6d4ae8684fc))

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
