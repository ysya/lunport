# Task 5 mounted UI verification

Code: f292b462db23d190d7f7a4bf52fd18d782d3965a. Actual RecordsKeysPanel and RecordsDeployKeyDialog mounted using Vite10496 and fake native invoke only. No actual host/credential/grant/relay/remote writes. Browser4/tab4; root CSS#root matches real application height.

- 800x560 dark, sixteen-hop reviewed route: effective ops@web-01.example.invalid:2222 and fingerprint precede route; details client300/scroll593. Close/Confirm top500 bottom530 inside dialog15..545; no horizontal overflow (scrollWidth800). Native select computed color-scheme dark. Screenshot sshelter-deploy-min-dark.jpg.
- Confirmation is initially disabled. Mock stale_preview after acknowledged Confirm remains visible, removes authorization input and disables Confirm. Refresh restores a new unchecked authorization input and still-disabled Confirm; Close explicitly dismisses the dialog.
- 1100x720 light: actual Keys Deploy public key action opens actual dialog, public destination/fingerprint/route and POSIX remote notice visible. Screenshot sshelter-deploy-normal-light.jpg.
- already_present plus audit write error is durably visible as preserved restrictions plus session-log failure; Confirm disabled and no automatic retry. Existing execution outcome is not represented as failed execution.
- 800x560 dark delayed fake confirmation: Cancel deployment stays visible while running, transitions to disabled Canceling and then durable canceled/remote-result-may-be-unknown message; Close reappears and Confirm remains disabled.

Screenshots at /Users/ysya/.codex/visualizations/2026/10/13/01a13783-b724-70b0-a06c-1dc8e89d7f7d/. Mock invocations establish browser presentation/effects only. Native execution/authentication/cancel integration and real Windows popup appearance are not established by these fixtures. Backend review, actual generated-script SSH acceptance and native CI remain separate gates.
