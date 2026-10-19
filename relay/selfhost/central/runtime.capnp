using Workerd = import "/workerd/workerd.capnp";
using Shared = import "/tmp/services.capnp";
const config :Workerd.Config = (
  services = [Shared.security, Shared.core, Shared.securityStorage, Shared.applicationStorage],
  # The application core has no socket. Only the proxy-capability-protected gateway is reachable.
  sockets = [(name = "http", address = "*:8080", http = (), service = "security")],
);
