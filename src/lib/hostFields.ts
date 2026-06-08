import type { HostOption } from "@/bindings/HostOption";
import type { HostFieldChange } from "@/bindings/HostFieldChange";

/**
 * A first-class (curated) SSH config field surfaced as a dedicated form control.
 * Anything whose keyword is not in {@link FIRST_CLASS_KEYS} is treated as an
 * "advanced / raw" option (free-form keyword + value rows).
 */
export interface FieldDef {
  keyword: string;
  label: string;
  group: "Connection" | "Authentication" | "Forwarding" | "Reliability";
  kind: "text" | "number" | "toggle" | "select";
  /** Allowed values when `kind === "select"`. */
  options?: string[];
  /** Field is only meaningful on macOS (e.g. UseKeychain). */
  macOnly?: boolean;
}

export const FIELD_DEFS: FieldDef[] = [
  // --- Connection ---
  { keyword: "HostName", label: "HostName", group: "Connection", kind: "text" },
  { keyword: "User", label: "User", group: "Connection", kind: "text" },
  { keyword: "Port", label: "Port", group: "Connection", kind: "number" },

  // --- Authentication ---
  { keyword: "IdentityFile", label: "IdentityFile", group: "Authentication", kind: "text" },
  { keyword: "IdentitiesOnly", label: "IdentitiesOnly", group: "Authentication", kind: "select", options: ["yes", "no"] },
  {
    keyword: "AddKeysToAgent",
    label: "AddKeysToAgent",
    group: "Authentication",
    kind: "select",
    options: ["yes", "no", "ask", "confirm"],
  },
  { keyword: "UseKeychain", label: "UseKeychain", group: "Authentication", kind: "select", options: ["yes", "no"], macOnly: true },
  { keyword: "ForwardAgent", label: "ForwardAgent", group: "Authentication", kind: "select", options: ["yes", "no"] },

  // --- Forwarding ---
  { keyword: "ProxyJump", label: "ProxyJump", group: "Forwarding", kind: "text" },
  { keyword: "LocalForward", label: "LocalForward", group: "Forwarding", kind: "text" },
  { keyword: "RemoteForward", label: "RemoteForward", group: "Forwarding", kind: "text" },
  { keyword: "DynamicForward", label: "DynamicForward", group: "Forwarding", kind: "text" },

  // --- Reliability ---
  { keyword: "ServerAliveInterval", label: "ServerAliveInterval", group: "Reliability", kind: "number" },
  { keyword: "ServerAliveCountMax", label: "ServerAliveCountMax", group: "Reliability", kind: "number" },
  { keyword: "ConnectTimeout", label: "ConnectTimeout", group: "Reliability", kind: "number" },
  { keyword: "Compression", label: "Compression", group: "Reliability", kind: "select", options: ["yes", "no"] },
  {
    keyword: "RequestTTY",
    label: "RequestTTY",
    group: "Reliability",
    kind: "select",
    options: ["no", "yes", "force", "auto"],
  },
  {
    keyword: "StrictHostKeyChecking",
    label: "StrictHostKeyChecking",
    group: "Reliability",
    kind: "select",
    options: ["yes", "accept-new", "ask", "no"],
  },
];

/**
 * Lowercased keywords of every first-class field. Used to split a host's option
 * list into curated fields vs. advanced/raw rows. Everything not in this set is
 * advanced.
 */
export const FIRST_CLASS_KEYS: Set<string> = new Set(
  FIELD_DEFS.map((f) => f.keyword.toLowerCase()),
);

/**
 * Compute the minimal change set to send to `config_save_host`.
 *
 * - `original` = the host's options as loaded.
 * - `desired`  = the full intended option list from the form (first-class fields
 *   with values + advanced entries), each `{keyword, value}`.
 *
 * Keywords are compared case-insensitively, and only the FIRST occurrence of a
 * keyword wins on each side — matching the backend's first-match semantics. The
 * desired keyword's original casing is preserved in the emitted change.
 *
 * Rules:
 *  - desired has a non-empty value differing from original (or absent in
 *    original) → `{keyword, value, remove:false}` (set)
 *  - original had a keyword that is absent or empty in desired
 *    → `{keyword, value:"", remove:true}` (remove)
 *  - unchanged → omitted (so the backend never rewrites that line)
 *  - empty desired value with no original entry → omitted (no spurious remove)
 */
export function computeChanges(
  original: HostOption[],
  desired: { keyword: string; value: string }[],
): HostFieldChange[] {
  // First-occurrence-wins maps keyed by lowercased keyword.
  const origMap = new Map<string, { keyword: string; value: string }>();
  for (const o of original) {
    const key = o.keyword.toLowerCase();
    if (!origMap.has(key)) origMap.set(key, { keyword: o.keyword, value: o.value });
  }

  const desiredMap = new Map<string, { keyword: string; value: string }>();
  for (const d of desired) {
    const key = d.keyword.toLowerCase();
    if (!desiredMap.has(key)) desiredMap.set(key, { keyword: d.keyword, value: d.value });
  }

  const changes: HostFieldChange[] = [];

  // Walk desired: detect sets (new / changed).
  for (const [key, d] of desiredMap) {
    const value = d.value.trim();
    const orig = origMap.get(key);
    const origValue = orig ? orig.value.trim() : "";

    if (value === "") {
      // Empty desired value: only meaningful if original had a real value.
      // (Removal of such keys is handled in the original-walk below.)
      continue;
    }

    if (!orig || value !== origValue) {
      changes.push({ keyword: d.keyword, value, remove: false });
    }
    // else unchanged → omit
  }

  // Walk original: detect removals (present-with-value originally, now absent or emptied).
  for (const [key, orig] of origMap) {
    const origValue = orig.value.trim();
    if (origValue === "") continue; // nothing to remove if it was already empty

    const d = desiredMap.get(key);
    const desiredValue = d ? d.value.trim() : "";
    if (desiredValue === "") {
      // Preserve original casing for the removal keyword.
      changes.push({ keyword: orig.keyword, value: "", remove: true });
    }
  }

  return changes;
}
