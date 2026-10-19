using Workerd = import "/workerd/workerd.capnp";
using Shared = import "/tmp/services.capnp";
const config :Workerd.Config = (
  services = [Shared.security, Shared.core, Shared.securityStorage, Shared.applicationStorage,
    (name = "privateControl", worker = (
      modules = [(name = "control.js", esModule = embed "/relay/control/index.js")],
      compatibilityDate = "2026-08-20",
      bindings = [
        (name = "SECURITY_FLOOR", durableObjectNamespace = (className = "SecurityFloorStore", serviceName = "security")),
        (name = "LEGACY_RETIREMENT", durableObjectNamespace = (className = "LegacyRetirementStore", serviceName = "security")),
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
