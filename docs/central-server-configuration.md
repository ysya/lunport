# Choosing a sync server

Lunport starts locally without an account. Public Stable and Beta installers have a blank account-service URL; they do not select the maintainer's service. Deploy your own service using [Cloudflare Workers](../relay/security/README.md) or [Docker Compose](../relay/selfhost/central/README.md), then enter its HTTPS origin in Sync, for example `https://sync.example.com`. Use the same origin on your other devices.

The first sign-in uses your existing local library. Passkey registration/sign-in authenticates the account; Vault setup and device approval provide the separate end-to-end encryption keys. Review the library before enabling sync. Managed SSH keys are then included automatically.

To change an already selected server, edit the account-service URL and choose **Change server and restart**. Restart closes terminal sessions and opens a separate empty local workspace for the new service. Reimport the SSH configuration and sign in on that service. Old memberships, Vaults, migration journals and managed key archives are not uploaded or relabelled for the new service. Existing SSH configuration and source files are not modified.

Each explicit server change creates an empty workspace, including when entering a previously used URL again. Old workspace files are not automatically restored. The desktop client no longer offers sync-code creation/join, per-key sync switches or background sync-code transport. Historical format readers remain for explicit imports; they do not run background synchronization.

Cloudflare stores account/device authority and encrypted Vault records in SQLite-backed Durable Objects. Docker keeps the equivalent storage in persistent volumes. Deployments should retain the independent security service, private core, installation identifier and monotonic security floor across updates. Never reuse a fresh-install migration history to overwrite existing namespaces.
