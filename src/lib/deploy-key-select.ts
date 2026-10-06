import type { KeyInfo } from "@/bindings/KeyInfo";

/**
 * Decide which public key the deploy dialog should preselect.
 *
 * Priority: the `.pub` matching one of the host's IdentityFiles → the single
 * deployable key in `~/.ssh` → null (let the user pick). Keys without a `.pub`
 * cannot be deployed and are excluded throughout.
 */
export function pickDefaultPublicKey(
  identityFiles: string[],
  keys: KeyInfo[],
): string | null {
  const deployable = keys.filter((k) => k.public_path !== null);

  // ssh_config stores IdentityFile verbatim, so `~/.ssh/work` never string-equals
  // the absolute private_path reported by keys_list (which uses `\` on Windows).
  // Compare the `~/`-relative tail against the end of the absolute path.
  const matches = (identity: string, privatePath: string) => {
    const [id, path] = [identity.replace(/\\/g, "/"), privatePath.replace(/\\/g, "/")];
    return path === id || (id.startsWith("~/") && path.endsWith(id.slice(1)));
  };

  for (const identity of identityFiles) {
    const match = deployable.find((k) => matches(identity, k.private_path));
    if (match) return match.public_path;
  }
  if (deployable.length === 1) return deployable[0].public_path;
  return null;
}
