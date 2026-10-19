/** Stable namespace witnesses, independently pinned before restoring application data. */
export const AUTHORITY_HEADER = "x-lunport-security-authority";
const NAME = "lunport-central-authority-v1";
export type AuthorityEnv = Pick<Env, "ACCOUNT" | "VAULT" | "PASSKEY">;
export function authorityWitness(env: AuthorityEnv): string {
  return [env.ACCOUNT, env.VAULT, env.PASSKEY]
    .map((namespace) => namespace.idFromName(NAME).toString())
    .join(":");
}
export const validAuthority = (value: unknown): value is string =>
  typeof value === "string" &&
  /^[0-9a-f]{64}:[0-9a-f]{64}:[0-9a-f]{64}$/.test(value);
