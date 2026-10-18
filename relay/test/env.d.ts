declare module "cloudflare:workers" {
  interface ProvidedEnv extends Env {
    SECURITY_FLOOR: DurableObjectNamespace<
      import("../src/security/floor").SecurityFloorStore
    >;
  }
}

declare namespace Cloudflare {
  interface Env {
    SECURITY_FLOOR: DurableObjectNamespace<
      import("../src/security/floor").SecurityFloorStore
    >;
    CENTRAL_PRIVATE_CORE?: string;
  }
}
