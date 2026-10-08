import type { KeyAlgorithm } from "@/bindings/KeyAlgorithm";
import type { KeyInfo } from "@/bindings/KeyInfo";
import type { SyncKeySlotView } from "@/bindings/SyncKeySlotView";
import { listNames, plural } from "@/lib/format";
import { identityPointsAt } from "@/lib/identity-file";
import { revealHidden } from "@/lib/sync-approvals";

/**
 * The Keychain (key vault spec §7): what its list, banners and detail show. Pure helpers; the components are in
 * src/components/keychain.
 */

/**
 * What the Keychain's main pane shows: a key slot (by id), a key file in ~/.ssh (by its private path), or the New key / Generate key
 * form (New key with a file already chosen, from a key file's "Import into SSHelter…").
 */
export type KeychainSelection =
  | { kind: "slot"; id: string }
  | { kind: "file"; path: string }
  | { kind: "new"; mode: "import" | "generate"; path: string | null };

/** The kinds Generate key offers (spec §7.5), with the name each suggests. */
export const KEY_TYPES: { algorithm: KeyAlgorithm; label: string; name: string }[] = [
  { algorithm: "ed25519", label: "Ed25519", name: "id_ed25519" },
  { algorithm: "rsa3072", label: "RSA 3072", name: "id_rsa" },
  { algorithm: "rsa4096", label: "RSA 4096", name: "id_rsa" },
  { algorithm: "ecdsa_p256", label: "ECDSA P-256", name: "id_ecdsa" },
];

export interface KeyBadge {
  label: string;
  tone: "plain" | "warning" | "error";
}

/** A slot the user has to act on here (spec §7.2): no key on this computer yet (not one on its way), or an error. Listed first. */
export function needsAttention(slot: SyncKeySlotView): boolean {
  const s = slot.status;
  return (s.kind === "needs_key" && !s.waiting_for_sync) || s.kind === "error";
}

/** A slot's badges (spec §7.2): how it is shared, then what needs doing. A key only on this computer has one badge that says both. */
export function slotBadges(slot: SyncKeySlotView): KeyBadge[] {
  const shared = slot.local_only ? "This computer only" : slot.mode === "synced" ? "Synced" : "Own key on each computer";
  const badges: KeyBadge[] = [{ label: shared, tone: "plain" }];
  const s = slot.status;
  if (s.kind === "needs_key" && !s.waiting_for_sync) badges.push({ label: "Needs a key", tone: "warning" });
  if (s.kind === "error") badges.push({ label: "Error", tone: "error" });
  if (!slot.in_account && !slot.local_only) badges.push({ label: "Not in your sync account", tone: "warning" });
  if (slot.file_for_now) badges.push({ label: "File for now", tone: "warning" });
  return badges;
}

/** The synced key's fingerprint, or else the one of the key this computer uses. */
export function slotFingerprint(slot: SyncKeySlotView): string | null {
  return slot.fingerprint ?? (slot.status.kind === "ready" ? slot.status.fingerprint : null);
}

/** A day as YYYY-MM-DD in this computer's time zone (the detail's "Created"). */
export function formatDay(ms: number): string {
  const d = new Date(ms);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

/** The detail's "Passphrase": the key in SSHelter's, else the synced key's; null when unknown. */
export function passphraseFact(slot: SyncKeySlotView): string | null {
  const has = slot.vault_has_passphrase ?? slot.has_passphrase;
  return has === null ? null : has ? "Yes" : "No";
}

/** Whether any field contains the search, ignoring case; an empty search matches everything. */
function matches(query: string, fields: (string | null)[]): boolean {
  const q = query.trim().toLowerCase();
  return q === "" || fields.some((f) => f !== null && f.toLowerCase().includes(q));
}

/** "In SSHelter" (spec §7.2): the slots matching the search (name, type, fingerprint), the ones needing attention first, then by name. */
export function keychainSlots(slots: readonly SyncKeySlotView[], query: string): SyncKeySlotView[] {
  return slots
    .filter((s) => matches(query, [s.name, s.key_type, slotFingerprint(s)]))
    .sort((a, b) => Number(needsAttention(b)) - Number(needsAttention(a)) || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
}

/** The same file: separators don't matter, and for a Windows path (a drive or a share) neither does case. */
function sameFile(a: string, b: string): boolean {
  const [x, y] = [a.replace(/\\/g, "/"), b.replace(/\\/g, "/")];
  const windows = /^[A-Za-z]:\//.test(x) || x.startsWith("//");
  return windows ? x.toLowerCase() === y.toLowerCase() : x === y;
}

/**
 * "Other key files in ~/.ssh" (spec §7.2): the key files no slot serves as a file on this computer, matching the search. A file a
 * slot only copied into SSHelter is the user's own again, so it is listed.
 */
export function otherKeyFiles(keys: readonly KeyInfo[], slots: readonly SyncKeySlotView[], query: string): KeyInfo[] {
  const served = slots.flatMap((s) => (!s.in_vault && "file" in s.status ? [s.status.file] : []));
  return keys.filter((k) => !served.some((f) => sameFile(f, k.private_path)) && matches(query, [k.name, k.key_type, k.fingerprint_sha256]));
}

/** The slots this computer still serves as a file (spec §8): what Move moves. */
export function moveCount(slots: readonly SyncKeySlotView[]): number {
  return slots.filter((s) => s.file_for_now).length;
}

export function moveBannerText(n: number): string {
  return `${plural(n, "key")} can move into SSHelter`;
}

/**
 * The launch hint (spec §5.7): keys in SSHelter work only while SSHelter runs. Shown once this computer has a key in SSHelter
 * while neither launch at login nor keeping running in the menu bar is on, until it is dismissed. `launchAtLogin` is null
 * until the OS answers.
 */
export function launchHintNeeded(o: { anyInVault: boolean; launchAtLogin: boolean | null; closeToTray: boolean; dismissed: boolean }): boolean {
  return o.anyInVault && !o.dismissed && o.launchAtLogin === false && !o.closeToTray;
}

/** A key's name from an IdentityFile value or a path: its last part, without quotes. */
export function keyNameOfPath(value: string): string {
  const v = value.trim().replace(/^"(.*)"$/, "$1");
  return v.split(/[\\/]/).pop() || v;
}

/**
 * What Export to host does to the host (spec §7.3.1): "{host} will use {key} instead of {old keys}". The old keys are the host's
 * own IdentityFile lines that name another key. Null when the host already uses only this key, and while `home` isn't known:
 * without it a `~/` or `%d/` value can't be matched against `keyPath`, so a host already on this key would read "{host} will use
 * {key} instead of {key}". `keyPath` is the key's private path (for a key in SSHelter, its slot path). Every name is shown through
 * `revealHidden`.
 */
export function attachText(host: string, key: string, identityFiles: readonly string[], keyPath: string, home: string | null): string | null {
  if (home === null) return null;
  const others = identityFiles.filter((f) => !identityPointsAt(f, keyPath, home));
  if (identityFiles.length > 0 && others.length === 0) return null;
  const uses = `${revealHidden(host)} will use ${revealHidden(key)}`;
  return others.length === 0 ? uses : `${uses} instead of ${listNames(others.map((f) => revealHidden(keyNameOfPath(f))))}`;
}

/** A slot's public key file (`<home>/.ssh/sshelter/keys/<file>.pub`, from its IdentityFile value); null while the home isn't known. */
export function slotPublicPath(slot: SyncKeySlotView, home: string | null): string | null {
  if (home === null || !slot.value.startsWith("~/")) return null;
  return `${home.replace(/[\\/]+$/, "")}/${slot.value.slice(2)}.pub`;
}

/** This computer has the slot's key, so its .pub is in the slot directory: Copy public key and Export to host work. */
export function hasKeyHere(slot: SyncKeySlotView): boolean {
  return ["ready", "synced_available", "source_changed", "not_in_use"].includes(slot.status.kind);
}
