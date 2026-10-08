import type { KeyHygiene } from "@/bindings/KeyHygiene";
import type { KeyInfo } from "@/bindings/KeyInfo";
import { identityFileAction, identityPointsAt } from "@/lib/identity-file";

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

/** One choice of the deploy dialog's key picker: the public key file, its label, and the key's name for the attach text. */
export interface KeyOption {
  value: string;
  label: string;
  name: string;
  keyType: string | null;
}

/**
 * The keys the deploy dialog offers: the ~/.ssh keys that have a .pub, and first the key the Keychain handed over when it isn't
 * one of them. That is a key in SSHelter, whose .pub is in the slot directory, which `keys_list` doesn't scan. It goes under
 * `handedOverName` (the slot's name), or else its file name.
 */
export function keyOptions(keys: readonly KeyInfo[], handedOver: string | null, handedOverName: string | null): KeyOption[] {
  const options: KeyOption[] = keys
    .filter((k) => k.public_path !== null)
    .map((k) => ({ value: k.public_path as string, label: `${k.name}.pub`, name: k.name, keyType: k.key_type === "unknown" ? null : k.key_type }));
  if (handedOver !== null && !options.some((o) => o.value === handedOver)) {
    const name = handedOverName ?? (handedOver.split(/[\\/]/).pop() ?? handedOver).replace(/\.pub$/, "");
    options.unshift({ value: handedOver, label: name, name, keyType: null });
  }
  return options;
}

/**
 * What the deploy does to the host's IdentityFile once the key is on the host:
 * - a plain deploy (`identityFileAction`): write it when the host names no key, say so when it already names this one, and
 *   otherwise offer the switch, never replacing the user's choice by itself;
 * - Export to host from the Keychain (`attach`, key vault spec §7.3.1): point the host at this key, its other IdentityFile lines
 *   going, unless it already uses only this key.
 */
export function afterDeploy(identityFiles: string[], privateAbs: string, home: string | null, attach: boolean): "write" | "already" | "offer" {
  if (!attach) return identityFileAction(identityFiles, privateAbs, home);
  return identityFiles.length > 0 && identityFiles.every((f) => identityPointsAt(f, privateAbs, home)) ? "already" : "write";
}

/**
 * The host's IdentityFile values (its key checks, `useKeyHygiene`) once they are read; null while the read is on its way, and
 * after it failed. A failed read is not a host without IdentityFile: Export to host's attach line would say "{host} will use
 * {key}" while the write replaces the host's lines (key vault spec §7.3.1).
 */
export function knownIdentityFiles(hygiene: { isSuccess: boolean; data?: KeyHygiene }): string[] | null {
  return hygiene.isSuccess && hygiene.data ? hygiene.data.identity_files.map((f) => f.path) : null;
}
