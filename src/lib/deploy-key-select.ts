import type { KeyInfo } from "@/bindings/KeyInfo";
import { identityPointsAt } from "@/lib/identity-file";

/**
 * Decide which public key the deploy dialog should preselect.
 *
 * Priority: the `.pub` matching one of the host's IdentityFiles → the single
 * deployable key in `~/.ssh` → null (let the user pick). Keys without a `.pub`
 * cannot be deployed and are excluded throughout.
 *
 * ssh_config stores IdentityFile verbatim (`~/.ssh/work`), while keys_list
 * reports absolute paths (with `\` on Windows): `identityPointsAt` compares
 * them, with `home` (null while unknown) standing in for `~`.
 */
export function pickDefaultPublicKey(
  identityFiles: string[],
  keys: KeyInfo[],
  home: string | null,
): string | null {
  const deployable = keys.filter((k) => k.public_path !== null);

  for (const identity of identityFiles) {
    const match = deployable.find((k) => identityPointsAt(identity, k.private_path, home));
    if (match) return match.public_path;
  }
  if (deployable.length === 1) return deployable[0].public_path;
  return null;
}
