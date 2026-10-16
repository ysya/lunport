import type {
  HostPayload,
  HostScope,
  InheritedField,
  RecordOverview,
  RecordHostView,
} from "@/lib/records";
import { groupAncestors, scopeKey } from "./group-tree";
export const inheritedFields: Array<[InheritedField, string]> = [
  ["port", "Port"],
  ["user", "Username"],
  ["authentication", "Authentication"],
  ["jump", "Jump hosts"],
  ["keepalive_secs", "Keepalive interval"],
  ["keepalive_max_missed", "Missed keepalives"],
  ["connect_timeout_secs", "Connect timeout"],
];
export function toggleInheritance(
  payload: HostPayload,
  field: InheritedField,
  enabled: boolean,
): HostPayload {
  const selected = new Set(payload.inherit ?? []);
  if (enabled) selected.add(field);
  else selected.delete(field);
  return { ...payload, inherit: [...selected] };
}
// Presentation-only draft preview. Rust revalidates the authoritative effective settings on save/connect.
export function previewInheritance(
  overview: RecordOverview,
  scope: HostScope,
  raw: HostPayload,
) {
  const payload = structuredClone(raw),
    sources: Partial<Record<InheritedField, string>> = {};
  const chain = groupAncestors(overview, raw.group_id, scope);
  if (chain.error) return { payload, sources, error: chain.error };
  const defaults = {
    port: 22,
    user: "",
    authentication: { auth: "password" as const, key_id: null },
    jump: [] as string[],
    keepalive_secs: 30,
    keepalive_max_missed: 3,
    connect_timeout_secs: 15,
  };
  for (const field of raw.inherit ?? []) {
    const source = chain.groups.find((g) => g.payload.defaults[field] != null);
    sources[field] = source?.id ?? "default";
    if (field === "authentication") {
      const value =
        source?.payload.defaults.authentication ?? defaults.authentication;
      payload.auth = value.auth;
      payload.key_id = value.key_id;
    } else {
      const value = source?.payload.defaults[field] ?? defaults[field];
      Object.assign(payload, { [field]: structuredClone(value) });
    }
  }
  return { payload, sources, error: null };
}
export function effectiveField(
  payload: HostPayload,
  field: InheritedField,
): string {
  if (field === "authentication")
    return `${payload.auth}${payload.key_id ? ` · ${payload.key_id}` : ""}`;
  if (field === "user") return payload.user || "OS username";
  if (field === "jump")
    return payload.jump.length ? payload.jump.join(" → ") : "None";
  return String(payload[field]);
}

export function previewHostDraft(
  overview: RecordOverview,
  scope: HostScope,
  raw: HostPayload,
  saved: RecordHostView | null,
) {
  const preview = previewInheritance(overview, scope, raw);
  // The saved winning-record diagnosis remains authoritative for the same
  // dependency, even if a stale readable Group view exists. A replacement or
  // detached draft resolves its own dependency and must be reviewable before save.
  const sameDependency =
    saved &&
    scopeKey(saved.scope) === scopeKey(scope) &&
    (saved.payload.group_id ?? null) === (raw.group_id ?? null);
  if (sameDependency && saved.group_error) preview.error = saved.group_error;
  return preview;
}
