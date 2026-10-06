/**
 * Key paths in ssh_config: writing a picked or deployed key as IdentityFile, and telling whether an IdentityFile
 * value names a given key file. Pure string logic — the actual write goes through the regular config_save_host
 * machinery. `home` is the current user's home directory (`useHomeDir`); null while it isn't known.
 */

/** Forward slashes, so Windows paths compare and print like the ones in ssh_config. */
function slashes(path: string): string {
  return path.replace(/\\/g, "/");
}

/** A Windows home (`C:\Users\me`, or a profile on a share): paths under it compare without regard to case. */
function isWindowsHome(home: string): boolean {
  return /^[A-Za-z]:[\\/]/.test(home) || home.startsWith("\\\\");
}

/** Same path, ignoring the separator; on Windows also ignoring case. */
function samePath(a: string, b: string, windows: boolean): boolean {
  const [x, y] = [slashes(a), slashes(b)];
  return windows ? x.toLowerCase() === y.toLowerCase() : x === y;
}

/**
 * The part of `absPath` after the current user's `.ssh/` directory (with `/` separators), or null when the path is
 * somewhere else — another drive, a WSL or network share, a backup's `.ssh` — or the home isn't known yet.
 */
function homeSshTail(absPath: string, home: string | null): string | null {
  if (!home) return null;
  const dir = `${slashes(home).replace(/\/+$/, "")}/.ssh/`;
  const path = slashes(absPath);
  if (path.length <= dir.length || !samePath(path.slice(0, dir.length), dir, isWindowsHome(home))) return null;
  return path.slice(dir.length);
}

/**
 * The value to write for a key the user picked or deployed (spec §8): `~/.ssh/…` for a key inside the current user's
 * `.ssh` directory — the same file on every computer, either separator, any case on Windows — and any other path as
 * given (a WSL or backup `.ssh` is a different key). Paths stay as given while the home isn't known.
 */
export function toTildeSshPath(absPath: string, home: string | null): string {
  const tail = homeSshTail(absPath, home);
  return tail === null ? absPath : `~/.ssh/${tail}`;
}

/**
 * True when an ssh_config IdentityFile value names the key file at `absPath`. ssh_config keeps the value verbatim
 * (maybe quoted, maybe `~/` or `%d/` for the home): those stand for the current user's home only, so they never match
 * a key in another `.ssh`. Separators don't matter; on Windows neither does case. While the home isn't known only the
 * same absolute path matches.
 */
export function identityPointsAt(entry: string, absPath: string, home: string | null): boolean {
  const quoted = entry.length >= 2 && entry.startsWith('"') && entry.endsWith('"');
  const value = quoted ? entry.slice(1, -1) : entry;
  const windows = home !== null && isWindowsHome(home);
  const rest = ["~/", "~\\", "%d/", "%d\\"].find((prefix) => value.startsWith(prefix));
  if (rest === undefined) return samePath(value, absPath, windows);
  if (!home) return false;
  return samePath(`${slashes(home).replace(/\/+$/, "")}/${value.slice(rest.length)}`, absPath, windows);
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
  home: string | null,
): "write" | "already" | "offer" {
  if (existingIdentityFiles.length === 0) return "write";
  return existingIdentityFiles.some((e) => identityPointsAt(e, deployedPrivateAbs, home))
    ? "already"
    : "offer";
}
