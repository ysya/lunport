# Choosing a sync server

Lunport starts locally without an account. Public Stable and Beta installers have a blank account-service URL; they do not select the maintainer's service. Deploy your own service using [Cloudflare Workers](../relay/security/README.md) or [Docker Compose](../relay/selfhost/central/README.md), then enter its HTTPS origin in Sync, for example `https://sync.example.com`. Use the same origin on your other devices.

Choose **Sign in and sync with Passkey** to connect your local library. Browser sign-in authorizes the app; set a **sync unlock password** in Lunport on the first device. On each new device, use the same server and account, then enter that password once. Vault initialization, device enrollment and the first library sync run automatically. Managed SSH private keys and saved SSH passwords are included. The sync unlock password is processed locally and is never sent to the server. Keep it in a password manager: Passkey sign-in cannot replace a forgotten encryption password.

Automatic setup requires the server capability `account-unlock-v1`. Update both the independent security service and private core from the same release, retaining their bindings, namespaces and persistent volumes. Saved SSH password sync also requires `ssh-password-sync-v1`. Update both server components before enabling this feature in new desktop clients; an older server retains pending changes and prompts for an upgrade. All participating desktop clients need a release supporting saved SSH passwords. Importing historical workspaces is a separate flow.

To change an already selected server, edit the account-service URL and choose **Change server and restart**. Restart closes terminal sessions and opens a separate empty local workspace for the new service. Reimport the SSH configuration and sign in on that service. Old memberships, Vaults, migration journals and managed key archives are not uploaded or relabelled for the new service. Existing SSH configuration and source files are not modified.

Each explicit server change creates an empty workspace, including when entering a previously used URL again. Old workspace files are not automatically restored. The desktop client no longer offers sync-code creation/join, per-key sync switches or background sync-code transport. The server rejects legacy chain requests and new migrations with chain sources. Historical local format readers remain for explicit imports; they do not run background synchronization.

Cloudflare stores account/device authority and encrypted Vault records in SQLite-backed Durable Objects. Docker keeps the equivalent storage in persistent volumes. Deployments should retain the independent security service, private core, installation identifier and monotonic security floor across updates. Never reuse a fresh-install migration history to overwrite existing namespaces.

## Account names and sign-in

Lunport is intended as a service for your homelab. On your own server, choose **Create an account**, enter an email as the account name, and create a Passkey. Account names are trimmed and case-insensitive; plus tags and dots are preserved. Email is **not verified** and is **not an account recovery method**. There is no SMTP configuration, verification mail, email login link or email password reset. Keep a backup Passkey using the browser's Passkey management flow.

On another device, use the same server, sign in with the account's Passkey, and enter the same sync unlock password in the app. Browser sign-in and the account name never supply the encryption password or Vault keys. If the Passkey provider does not make the credential available on that device, use its cross-device authentication or add a backup Passkey while signed in.

A local library stays bound to the account that created it. To start over with a new account on the same server, sign out, expand **Account and device settings**, and choose **Start with a new account and restart**. This opens an empty workspace and closes terminal sessions; it does not delete real SSH configuration or private-key files. An older Passkey can still sign in to its original account; creating an email-named account creates a separate account.

Both Cloudflare and Docker run the same registration and Passkey protocol. Neither deployment needs a mail provider. A server operator controls network access and registration exposure for their homelab.
