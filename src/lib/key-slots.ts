import type { HostFieldChange } from "@/bindings/HostFieldChange";
import type { KeyCandidate } from "@/bindings/KeyCandidate";
import type { KeyCandidates } from "@/bindings/KeyCandidates";
import type { KeyChoice } from "@/bindings/KeyChoice";
import type { SlotStatusView } from "@/bindings/SlotStatusView";
import type { SyncKeySlotView } from "@/bindings/SyncKeySlotView";
import type { SyncOverview } from "@/bindings/SyncOverview";
import { listNames, plural } from "@/lib/format";
import { revealHidden } from "@/lib/sync-approvals";
import type { Tone } from "@/lib/sync-overview";

/**
 * Key slots (SP3 spec docs/superpowers/specs/2026-10-05-sp3-key-slots-design.md): pure helpers for the
 * "Keys used by synced hosts" dialog, the Keys dialog's slot section, Settings → Sync and the sidebar.
 */

/** Why the setup dialog opened: the hosts it is about (null = every host) and what opened it. */
export interface KeySetupRequest {
  aliases: string[] | null;
  reason: "moved" | "saved" | "upgrade" | "settings";
}

function hostsIn(k: KeyCandidate, aliases: string[] | null) {
  return (aliases === null ? k.hosts : k.hosts.filter((h) => aliases.includes(h.alias))).filter((h) => h.locked === null);
}

/** Keys to ask about: no slot yet, and at least one host (among `aliases`, when given) the setup would rewrite. */
export function keysToAsk(candidates: KeyCandidates | undefined, aliases: string[] | null): KeyCandidate[] {
  return (candidates?.keys ?? []).filter((k) => k.existing_slot === null && hostsIn(k, aliases).length > 0);
}

/** Keys that already have a slot here or in the account: set up without asking (spec §6.1). */
export function reuseChoices(candidates: KeyCandidates | undefined, aliases: string[] | null): KeyChoice[] {
  return (candidates?.keys ?? [])
    .filter((k) => k.existing_slot !== null && hostsIn(k, aliases).length > 0)
    .map((k) => ({ path: k.path, decision: { kind: "reuse", slot_id: k.existing_slot as string } }));
}

/** The backend's slot name rule (`slot_rules::valid_slot_name`). */
export function isValidSlotName(name: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(name) && !/\.pub$/i.test(name);
}

/** "web uses id_mac." / "web and db use id_mac." (only the hosts the setup changes). */
export function usesLine(k: KeyCandidate, name: string): string {
  const hosts = k.hosts.filter((h) => h.locked === null).map((h) => h.alias);
  return `${listNames(hosts)} ${hosts.length === 1 ? "uses" : "use"} ${name}.`;
}

export function passphraseNote(k: KeyCandidate): string | null {
  if (k.has_passphrase === null) return null;
  return k.has_passphrase
    ? "Has a passphrase — it stays on each computer."
    : "No passphrase — your sync code and every joined computer can use this key once it syncs.";
}

/** The lines the setup rewrites. The slot's id is only known once it exists, so its file name ends in "…". */
export function rewrittenLines(k: KeyCandidate, name: string): string[] {
  return k.hosts.filter((h) => h.locked === null).map((h) => `${h.alias}: IdentityFile ${h.value} → ~/.ssh/sshelter/keys/${name}-…`);
}

/** Hosts the setup leaves alone, and why. */
export function lockedNote(k: KeyCandidate): string | null {
  const locked = k.hosts.filter((h) => h.locked !== null);
  if (locked.length === 0) return null;
  return `Not changed: ${listNames(locked.map((h) => h.alias))} — ${locked[0].locked}`;
}

export function choiceFor(k: KeyCandidate, sync: boolean, name: string): KeyChoice {
  return { path: k.path, decision: sync ? { kind: "sync", name } : { kind: "keep", name } };
}

/** A host save that touched IdentityFile (any spelling) may need a key set up. */
export function identityFileChanged(changes: readonly HostFieldChange[]): boolean {
  return changes.some((c) => c.keyword.toLowerCase() === "identityfile");
}

export function notSetUpLabel(n: number): string {
  return `${plural(n, "key")} used by synced hosts ${n === 1 ? "isn't" : "aren't"} set up`;
}

export function needsKeyLabel(n: number): string {
  return `${plural(n, "key slot")} ${n === 1 ? "needs" : "need"} a key on this computer`;
}

/** Slots this computer needs a key for and the user has to pick one (not ones waiting for a synced key). */
export function slotsNeedingKey(o: SyncOverview): SyncKeySlotView[] {
  return o.key_slots.filter((s) => s.status.kind === "needs_key" && !s.status.waiting_for_sync);
}

/** After a sync code change: which synced keys to replace if a computer was lost (spec §6.6). */
export function syncedKeysNote(o: SyncOverview): string | null {
  const synced = o.key_slots.filter((s) => s.mode === "synced").map((s) => revealHidden(s.name));
  if (synced.length === 0) return null;
  return `If a computer was lost, also replace these synced keys on your servers: ${listNames(synced)}.`;
}

export function slotStatusText(status: SlotStatusView): { text: string; tone: Tone } {
  switch (status.kind) {
    case "ready":
      return { text: "Ready", tone: "ok" };
    case "needs_key":
      return status.waiting_for_sync
        ? { text: "Waiting for the synced key", tone: "busy" }
        : { text: "Needs a key on this computer", tone: "warning" };
    case "not_in_use":
      return { text: "Not in use", tone: "ok" };
    case "not_used_here":
      return { text: "Not used on this computer", tone: "ok" };
    case "synced_available":
      return { text: "A synced key is available", tone: "warning" };
    case "source_changed":
      return { text: "This computer's key changed — your other computers still have the previous one", tone: "warning" };
    case "error":
      return { text: status.message, tone: "error" };
  }
}

export interface SlotActions {
  syncThis: boolean;
  stopSyncing: boolean;
  pick: "pick" | "change" | null;
  useSynced: boolean;
  syncNew: boolean;
  deleteCopy: boolean;
}

export function slotActions(slot: SyncKeySlotView): SlotActions {
  const s = slot.status;
  return {
    syncThis: slot.mode === "own" && s.kind === "ready",
    stopSyncing: slot.mode === "synced",
    // A computer that uploaded the slot's key and then picked or regenerated another one lands in `source_changed`:
    // without Change it could only upload the new key again or stop syncing.
    pick:
      s.kind === "needs_key"
        ? "pick"
        : s.kind === "ready" || s.kind === "synced_available" || s.kind === "source_changed"
          ? "change"
          : null,
    useSynced: s.kind === "synced_available",
    syncNew: s.kind === "source_changed",
    deleteCopy: s.kind === "not_in_use",
  };
}

export function hostsLine(slot: SyncKeySlotView): string | null {
  return slot.hosts.length === 0 ? null : `Used by ${listNames(slot.hosts)}`;
}

/** The other computers' slots; their names come from those computers. */
export function deviceLine(slot: SyncKeySlotView): string | null {
  if (slot.devices.length === 0) return null;
  return slot.devices.map((d) => `${revealHidden(d.name)}: ${d.synced_copy ? "synced copy" : "its own key"}`).join(" · ");
}

/** Sidebar hosts whose key isn't on this computer: a slot that needs a key picked here, or failed (not one whose synced key is on its way). */
export function hostsMissingKey(o: SyncOverview | undefined): Set<string> {
  const out = new Set<string>();
  for (const slot of o?.key_slots ?? []) {
    const s = slot.status;
    if ((s.kind === "needs_key" && !s.waiting_for_sync) || s.kind === "error") slot.hosts.forEach((h) => out.add(h));
  }
  return out;
}

/** The setup dialog opens by itself once per computer after the SP3 update (spec §7.1). localStorage may be missing or throw. */
const ASKED_KEY = "sshelter.keySetupAsked";

export function keySetupAskedBefore(): boolean {
  try {
    return globalThis.localStorage?.getItem(ASKED_KEY) === "1";
  } catch {
    return false;
  }
}

export function rememberKeySetupAsked(): void {
  try {
    globalThis.localStorage?.setItem(ASKED_KEY, "1");
  } catch {
    // The prompt may show once more.
  }
}
