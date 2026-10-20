# workerd configuration for the self-hosted relay (see ../README.md, "Self-host with Docker Compose").
# It runs the same bundle `wrangler deploy` uploads to Cloudflare. check-config.mjs keeps the
# compatibility date and the Durable Object classes in step with ../wrangler.jsonc.
using Workerd = import "/workerd/workerd.capnp";

const config :Workerd.Config = (
  services = [
    (name = "relay", worker = .relay),
    # Every chain's SQLite database lives here: the Docker volume.
    (name = "storage", disk = (path = "/data", writable = true)),
  ],
  # Plain HTTP inside the compose network; Caddy terminates TLS in front of it.
  sockets = [(name = "http", address = "*:8080", http = (), service = "relay")],
);

const relay :Workerd.Worker = (
  modules = [(name = "index.js", esModule = embed "dist/index.js")],
  compatibilityDate = "2026-08-20",
  durableObjectNamespaces = [
    # A uniqueKey names its objects' storage on disk: changing it orphans every stored chain.
    (className = "ChainStore", uniqueKey = "sshelter-relay-ChainStore", enableSql = true),
    (className = "IpLimiter", uniqueKey = "sshelter-relay-IpLimiter", enableSql = true),
    # Security state has separate storage and no expiry. Preserve this namespace on restore.
    (className = "LegacyRetirementStore", uniqueKey = "sshelter-relay-LegacyRetirementStore", enableSql = true),
    (className = "AccountStore", uniqueKey = "sshelter-relay-AccountStore", enableSql = true),
    (className = "VaultStore", uniqueKey = "sshelter-relay-VaultStore", enableSql = true),
    (className = "PasskeyStore", uniqueKey = "sshelter-relay-PasskeyStore", enableSql = true),
  ],
  durableObjectStorage = (localDisk = "storage"),
  bindings = [
    (name = "CHAIN", durableObjectNamespace = "ChainStore"),
    (name = "IP_LIMIT", durableObjectNamespace = "IpLimiter"),
    (name = "LEGACY_RETIREMENT", durableObjectNamespace = "LegacyRetirementStore"),
    (name = "ACCOUNT", durableObjectNamespace = "AccountStore"),
    (name = "VAULT", durableObjectNamespace = "VaultStore"),
    (name = "PASSKEY", durableObjectNamespace = "PasskeyStore"),
  ],
);
