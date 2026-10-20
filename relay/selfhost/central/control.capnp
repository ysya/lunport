using Workerd = import "/workerd/workerd.capnp";
using Shared = import "/tmp/services.capnp";
const config :Workerd.Config = (
  services = [Shared.security, Shared.core, Shared.securityStorage, Shared.applicationStorage,
    (name = "authorityRead", disk = (path = "/security-data", writable = false)),
    (name = "privateControl", worker = (
      modules = [(name = "control.js", esModule = embed "/relay/control/index.js")],
      compatibilityDate = "2026-08-20",
      bindings = [
        (name = "SECURITY_FLOOR", durableObjectNamespace = (className = "SecurityFloorStore", serviceName = "security")),
        (name = "LEGACY_RETIREMENT", durableObjectNamespace = (className = "LegacyRetirementStore", serviceName = "security")),

        (name = "ACCOUNT", durableObjectNamespace = (className = "AccountStore", serviceName = "security")),
        (name = "VAULT", durableObjectNamespace = (className = "VaultStore", serviceName = "security")),
        (name = "PASSKEY", durableObjectNamespace = (className = "PasskeyStore", serviceName = "security")),
        (name = "SELFHOST_EXPECTED_AUTHORITY", fromEnvironment = "SELFHOST_EXPECTED_AUTHORITY"),
        (name = "SELFHOST_AUTHORITY_RECEIPT", fromEnvironment = "SELFHOST_AUTHORITY_RECEIPT"),
        (name = "SELFHOST_AUTHORITY_IMPORT", text = embed "/tmp/authority-import.json"),
        (name = "AUTHORITY_READ", service = "authorityRead"),
        (name = "SECURITY_INSTALLATION", fromEnvironment = "SECURITY_INSTALLATION"),
        (name = "SELFHOST_CONTROL_MODE", fromEnvironment = "SELFHOST_CONTROL_MODE"),
        (name = "SELFHOST_EXPECTED_REGISTRY", fromEnvironment = "SELFHOST_EXPECTED_REGISTRY"),
        (name = "SELFHOST_CONFIRM_NEW_INSTALLATION", fromEnvironment = "SELFHOST_CONFIRM_NEW_INSTALLATION"),
        (name = "SELFHOST_MINIMUM_FLOOR", fromEnvironment = "SELFHOST_MINIMUM_FLOOR"),
      ],
    )),
  ],
  # No HTTP listener, inspector, public provisioning or reset endpoint.
  sockets = [],
);
