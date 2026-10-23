# Lunport sync service

The desktop client uses self-hosted accounts with Passkey sign-in and end-to-end encrypted library sync. Email names are unverified and do not provide email recovery. The sync unlock password is processed only in the desktop app. Public installers start with a blank server URL; deploy your own service and enter its HTTPS origin in Sync. See [client server configuration](../docs/central-server-configuration.md).

- [Cloudflare gateway and private core](security/README.md): independent account/device authority and SQLite-backed Durable Object storage.
- [Docker Compose](selfhost/central/README.md): equivalent independent security storage and private application runtime.

The public account API uses `/v1/*`. The former chain API under `/legacy/v1/*` is retired and returns 404. Older clients must be updated; historical chain storage is not deleted by this code change. The desktop client no longer sends chain requests.

Deploy the security gateway and private core together from a reviewed release. Keep the core's HTTP endpoint private, preserve security namespaces and their high-water state in backups, and verify the restore procedure before enabling central sync. Follow the linked deployment guides for route, TLS, identity and storage checks.

## Development checks

```sh
npm run typecheck
npm run check:security-config
npm run test:security-config
npm test
```
