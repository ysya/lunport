# Choosing a sync server

Lunport starts locally without an account. Public Stable and Beta installers have a blank account-service URL; they do not select the maintainer's service. Deploy your own service using [Cloudflare Workers](../relay/security/README.md) or [Docker Compose](../relay/selfhost/central/README.md), then enter its HTTPS origin in Sync, for example `https://sync.example.com`. Use the same origin on your other devices.

Choose **Sign in and sync with Passkey** to connect your local library. Browser sign-in authorizes the app; set a **sync unlock password** in Lunport on the first device. On each new device, use the same server and account, then enter that password once. Vault initialization, device enrollment and the first library sync run automatically. Managed SSH private keys are included. The password is processed locally and is never sent to the server. Keep it in a password manager: Passkey sign-in cannot replace a forgotten encryption password.

Automatic setup requires the server capability `account-unlock-v1`. Update both the independent security service and private core from the same release, retaining their bindings, namespaces and persistent volumes. This release targets fresh account setup; importing historical workspaces is a separate flow.

To change an already selected server, edit the account-service URL and choose **Change server and restart**. Restart closes terminal sessions and opens a separate empty local workspace for the new service. Reimport the SSH configuration and sign in on that service. Old memberships, Vaults, migration journals and managed key archives are not uploaded or relabelled for the new service. Existing SSH configuration and source files are not modified.

Each explicit server change creates an empty workspace, including when entering a previously used URL again. Old workspace files are not automatically restored. The desktop client no longer offers sync-code creation/join, per-key sync switches or background sync-code transport. Historical format readers remain for explicit imports; they do not run background synchronization.

Cloudflare stores account/device authority and encrypted Vault records in SQLite-backed Durable Objects. Docker keeps the equivalent storage in persistent volumes. Deployments should retain the independent security service, private core, installation identifier and monotonic security floor across updates. Never reuse a fresh-install migration history to overwrite existing namespaces.
