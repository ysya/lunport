/**
 * Decision helpers for writing IdentityFile back to a host after a successful
 * in-app key deploy. Pure string logic — the actual write goes through the
 * regular config_save_host machinery.
 */

/** Rewrite an absolute path under a `.ssh` directory to its `~/.ssh/…` form. */
export function toTildeSshPath(absPath: string): string {
  const marker = "/.ssh/";
  const at = absPath.indexOf(marker);
  if (at === -1) return absPath;
  return `~/.ssh/${absPath.slice(at + marker.length)}`;
}

/** True when a config IdentityFile entry points at the deployed private key. */
function pointsAt(entry: string, deployedPrivateAbs: string): boolean {
  if (entry === deployedPrivateAbs) return true;
  // ssh_config keeps `~` verbatim; compare the `~/`-relative tail against the
  // end of the absolute path, segment-aligned via the leading `/`.
  return entry.startsWith("~/") && deployedPrivateAbs.endsWith(entry.slice(1));
}

/**
 * What the deploy result screen should do about this host's IdentityFile:
 * - `"write"`   — host has none; write the deployed key automatically.
 * - `"already"` — an entry already points at the deployed key; say so.
 * - `"offer"`   — a different key is configured; offer a button, never
 *   auto-replace the user's explicit choice.
 */
export function identityFileAction(
  existingIdentityFiles: string[],
  deployedPrivateAbs: string,
): "write" | "already" | "offer" {
  if (existingIdentityFiles.length === 0) return "write";
  return existingIdentityFiles.some((e) => pointsAt(e, deployedPrivateAbs))
    ? "already"
    : "offer";
}
