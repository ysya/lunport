import { queryOptions } from "@tanstack/react-query";
import { tauriInvoke } from "./ipc";
import type { RecordOverview } from "./records";

import type { StandardPostgresDraft } from "@/bindings/StandardPostgresDraft";
import type { StandardPostgresProfile } from "@/bindings/StandardPostgresProfile";

export type { StandardPostgresDraft, StandardPostgresProfile };

export const standardPostgresQuery = queryOptions({
  queryKey: ["standard-postgres"],
  queryFn: () => tauriInvoke<StandardPostgresProfile[]>("standard_postgres_list"),
  networkMode: "always",
  retry: false,
});

export function saveStandardPostgres(profile: StandardPostgresProfile | null, draft: StandardPostgresDraft, password: string | null, forgetPassword: boolean, expectedRoute?: string) {
  return tauriInvoke<StandardPostgresProfile>("standard_postgres_save", {
    id: profile?.id ?? null, expectedRevision: profile?.revision ?? null, draft, password, forgetPassword,
    ...(expectedRoute === undefined ? {} : { expectedRoute }),
  });
}

export function deleteStandardPostgres(profile: StandardPostgresProfile) {
  return tauriInvoke<void>("standard_postgres_delete", { id: profile.id, expectedRevision: profile.revision });
}

export function postgresAddress(profile: StandardPostgresProfile) {
  const host = profile.host.includes(":") ? `[${profile.host}]` : profile.host;
  return `${host}:${profile.port}`;
}

export function postgresRouteHost(overview: RecordOverview, profile: StandardPostgresProfile) {
  return profile.route_unavailable || profile.via_host === null
    ? null
    : overview.hosts.find((host) => host.id === profile.via_host) ?? null;
}
