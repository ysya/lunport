# Password entry and stable detail overlays

## Behavior

Desktop SSH sessions now ask for passwords, key passphrases and keyboard-interactive answers in Lunport's existing authentication window. Trusted host context stays separate from server text. Answers are temporary; the terminal still receives server banners and public authentication notices. Brokers without a desktop authentication owner retain their terminal prompts.

The Records host editor offers an explicit device-only password save, replacement and removal. It reads only saved-status metadata. Password drafts stay outside record payloads, sync and the query cache. The saved host ID addresses the existing system credential store. A credential-store failure after creation keeps the saved ID and revision, displays an error beside the save actions, and allows retry without creating a duplicate host.

Host and Key Vault inspectors overlay the right edge of the workspace. Opening, closing or resizing no longer changes catalog width or card wrapping. Narrow windows cover the content area while keeping the catalog mounted and inert behind the inspector. Escape closes details and returns focus to the selected item; nested dialogs keep their own Escape handling. Keys starts with the collection visible and no automatic selection.

The choice follows [PatternFly's drawer guidance](https://www.patternfly.org/components/drawer/design-guidelines/): an overlay keeps the underlying content in place, whereas an inline drawer makes it more compact. This is a behavior reference; the implementation uses Lunport's existing components and theme.

## Actual component previews

These development browser fixtures contain synthetic hosts and public keys. Their credential store is an in-memory map, and no real SSH login or system credential is used. Browser screenshots include the user's external Funlingo toolbar where present; it is not part of Lunport.

- [App password prompt](app-password.jpg), checked at the native authentication window's 480 × 360 size.
- [Key Vault overlay](vault-overlay.jpg).
- [Narrow Key Vault](vault-narrow.jpg), checked at the application's minimum 800 × 560 size. [Maximum 17px text](vault-narrow-large.jpg) keeps the same catalog width (564.125px) with the inspector closed/open.
- [Host password editor](host-password-editor.jpg).

Preview URLs with Vite running: `/dev-preview.html?scenario=authentication`, `?scenario=password`, `?scenario=password-save-retry`, and `?scenario=vault` (25 keys).

## Validation

The new broker regression failed before wiring the desktop authentication owner: the password appeared in the terminal instead of the App. It passes after the change. Broker coverage also exercises a rejected password followed by a fresh question, no automatic credential persistence, cancellation in the App, terminal disconnection, late answer rejection and an unavailable native question ending the terminal connection.

Browser checks cover explicit saving, saved status, replacement/removal controls, credential-store failure after creation and retry with one host, masked answers, show/hide, clearing after submission, inspector resizing, rename dialogs, keyboard close and minimum window size. DOM measurements at a 979px viewport show catalog width 770.875px, row width 714.875px and row height 64.75px with details closed/open/resized. A scrolled keyboard-open/close cycle preserves scrollTop 419px. At 800px the catalog stays 591.875px wide and retains the same scroll position beneath the full-content overlay. Locator clicks may center their target before opening, so the scroll assertion uses a focused row and Enter.

Local checks passed: TypeScript type-check, 89 frontend files / 1,099 tests, production build, 47 broker tests, two native authentication tests, and the CI-safe Rust suite (2,625 passed, one ignored, ten excluded). The CI-safe Rust suite excludes the same real credential-store and PAM cases as `.github/workflows/test-engine.yml`. Cross-platform CI is required before publication. No installer has been published for this change.
