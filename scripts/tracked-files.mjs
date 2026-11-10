// What the guards that scan every file git tracks (scripts/identity-guard.mjs, scripts/note-citation-guard.mjs) share.
import { readFileSync } from "node:fs";

// An allowlist path, from the repository root as `git ls-files` prints it, as a pattern. Only `**` is a wildcard (any text, slashes
// included), as in `dir/**`.
export function globToRegExp(glob) {
  const source = glob.split("**").map(part => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join(".*");
  return new RegExp(`^${source}$`);
}

// The text of a file, or undefined for a binary file (it holds a NUL byte, which is also how git tells) and for a path that git still
// lists but that is gone from the working tree.
export function readText(path) {
  let bytes;
  try {
    bytes = readFileSync(path);
  } catch (error) {
    if (error.code === "ENOENT") return undefined;
    throw error;
  }
  return bytes.includes(0) ? undefined : bytes.toString("utf8");
}
