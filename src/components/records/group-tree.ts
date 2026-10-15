import type {
  HostScope,
  RecordGroupView,
  RecordHostView,
  RecordOverview,
} from "@/lib/records";
export const scopeKey = (scope: HostScope) =>
  scope.kind === "local" ? "local" : `space:${scope.space_id}`;
export function selectGroup(
  groups: RecordGroupView[],
  id: string,
): RecordGroupView | null {
  const matching = groups.filter((g) => g.id === id);
  return matching.length === 1 ? matching[0] : null;
}
export function groupAncestors(
  overview: RecordOverview,
  id: string | null | undefined,
  scope: HostScope,
): { groups: RecordGroupView[]; error: string | null } {
  const groups: RecordGroupView[] = [],
    seen = new Set<string>();
  while (id) {
    if (seen.has(id))
      return { groups, error: "Group cycle. Review its parent." };
    if (groups.length >= 32)
      return { groups, error: "Group ancestry exceeds 32 levels." };
    seen.add(id);
    const group = selectGroup(overview.groups, id);
    if (!group)
      return { groups, error: `Missing or conflicting Group (${id}).` };
    if (scopeKey(group.scope) !== scopeKey(scope))
      return { groups, error: "Group belongs to another scope." };
    groups.push(group);
    if (group.group_error) return { groups, error: group.group_error };
    id = group.payload.parent_id;
  }
  return { groups, error: null };
}
export function groupPath(
  overview: RecordOverview,
  id: string | null | undefined,
  scope: HostScope,
): string {
  const chain = groupAncestors(overview, id, scope);
  return chain.error
    ? `Needs review: ${chain.error}`
    : chain.groups
        .map((g) => g.payload.name)
        .reverse()
        .join(" / ");
}
export type GroupNode = {
  group: RecordGroupView;
  children: GroupNode[];
  hosts: RecordHostView[];
};
export type ScopeRoot = {
  scope: HostScope;
  label: string;
  groups: GroupNode[];
  ungrouped: RecordHostView[];
  diagnostics: Array<{ group: RecordGroupView; error: string }>;
};
const byName = (a: RecordGroupView, b: RecordGroupView) =>
  a.payload.name.localeCompare(b.payload.name) || a.id.localeCompare(b.id);
const byAlias = (a: RecordHostView, b: RecordHostView) =>
  a.payload.alias.localeCompare(b.payload.alias) || a.id.localeCompare(b.id);
export function buildRecordTree(
  overview: RecordOverview,
  search = "",
): ScopeRoot[] {
  const scopes: Array<{ scope: HostScope; label: string }> = [
    { scope: { kind: "local" }, label: "Local" },
    ...overview.spaces
      .filter((s) => s.selected && !s.missing)
      .map((s) => ({
        scope: { kind: "space" as const, space_id: s.id },
        label: s.name,
      })),
  ];
  // Retain inspectable rows even when their scope is absent from the current list.
  for (const row of [...overview.groups, ...overview.hosts])
    if (!scopes.some((s) => scopeKey(s.scope) === scopeKey(row.scope)))
      scopes.push({ scope: row.scope, label: "Missing space" });
  const needle = search.trim().toLowerCase();
  return scopes
    .map(({ scope, label }) => {
      const same = (s: HostScope) => scopeKey(s) === scopeKey(scope);
      const groups = overview.groups.filter((g) => same(g.scope)).sort(byName);
      const diagnostics = groups.flatMap((group) => {
        const error = groupAncestors(overview, group.id, scope).error;
        return error ? [{ group, error }] : [];
      });
      const valid = groups.filter(
        (g) => !diagnostics.some((d) => d.group === g),
      );
      const hosts = overview.hosts.filter((h) => same(h.scope)).sort(byAlias);
      const matchesHost = (h: RecordHostView) =>
        recordHostSearchText(overview, h).toLowerCase().includes(needle);
      const matchingAncestorIds = new Set(
        hosts
          .filter(matchesHost)
          .flatMap((host) => [
            ...(host.payload.group_id ? [host.payload.group_id] : []),
            ...groupAncestors(
              overview,
              host.payload.group_id,
              scope,
            ).groups.map((group) => group.id),
          ]),
      );
      const node = (
        group: RecordGroupView,
        parentMatch: boolean,
      ): GroupNode | null => {
        const matched =
          parentMatch ||
          `${groupPath(overview, group.id, scope)}`
            .toLowerCase()
            .includes(needle);
        const children = valid
          .filter((g) => g.payload.parent_id === group.id)
          .map((g) => node(g, matched))
          .filter((g): g is GroupNode => g !== null);
        const members = hosts.filter(
          (h) => h.payload.group_id === group.id && (matched || matchesHost(h)),
        );
        return matched || children.length || members.length
          ? { group, children, hosts: members }
          : null;
      };
      return {
        scope,
        label,
        groups: valid
          .filter((g) => !g.payload.parent_id)
          .map((g) => node(g, false))
          .filter((g): g is GroupNode => g !== null),
        ungrouped: hosts.filter(
          (h) =>
            (!h.payload.group_id ||
              groupAncestors(overview, h.payload.group_id, scope).error) &&
            matchesHost(h),
        ),
        diagnostics: diagnostics.filter(
          (d) =>
            !needle ||
            matchingAncestorIds.has(d.group.id) ||
            `${d.group.payload.name} ${d.error}`.toLowerCase().includes(needle),
        ),
      };
    })
    .filter(
      (root) =>
        !needle ||
        root.groups.length ||
        root.ungrouped.length ||
        root.diagnostics.length,
    );
}
export function affectedRecords(
  overview: RecordOverview,
  group: RecordGroupView,
): { groups: number; hosts: number } {
  const descendant = (id: string | null | undefined, scope: HostScope) =>
    scopeKey(scope) === scopeKey(group.scope) &&
    groupAncestors(overview, id, scope).groups.some((g) => g.id === group.id);
  return {
    groups: overview.groups.filter(
      (g) => g.id !== group.id && descendant(g.id, g.scope),
    ).length,
    hosts: overview.hosts.filter((h) => descendant(h.payload.group_id, h.scope))
      .length,
  };
}
export function requiresFormatUpgrade(
  overview: RecordOverview,
  scope: HostScope,
): boolean {
  return (
    overview.format_upgrade_required ||
    (scope.kind === "space" && overview.shared_format_upgrade_required)
  );
}

export function recordHostSearchText(
  overview: RecordOverview,
  host: RecordHostView,
): string {
  return `${host.payload.alias} ${host.payload.hostname} ${host.payload.tags.join(" ")} ${groupPath(overview, host.payload.group_id, host.scope)} ${host.id}`;
}
