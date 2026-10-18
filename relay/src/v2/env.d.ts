/** Optional until the account service is explicitly configured and enabled. */
interface Env {
  CENTRAL_ENABLED?: string;
  CENTRAL_ORIGIN?: string;
  OIDC_ISSUER?: string;
  OIDC_JWKS_URL?: string;
  OIDC_API_AUDIENCE?: string;
  OIDC_NATIVE_CLIENT_ID?: string;
  OIDC_SYNC_SCOPE?: string;
}
