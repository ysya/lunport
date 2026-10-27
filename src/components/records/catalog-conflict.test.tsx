import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { text } from "@/components/keychain/test-markup";
import type { CatalogCollision, CatalogReview, CentralConflict } from "@/lib/central-sync";
import type { TunnelRule } from "@/lib/tunnels";
import { groupView, hostPayload, hostTransport, hostView, recordOverview } from "./fixtures";
import { CATALOG_CHOICE_NOTE, CatalogConflictView, catalogChoiceTitle } from "./CatalogConflict";
import { ConflictRow } from "./CentralConflicts";

/* Design 2026-10-27 (Collisions: the review): the Catalog's row in Central conflicts, in plain words. */

const jump = hostView({ id: "000000000000000a", payload: hostPayload({ alias: "prod-jump" }) });
const web = groupView({ id: "0000000000000010", payload: { schema: 1, name: "Web", parent_id: null, defaults: {} } });
const db = groupView({ id: "0000000000000011", payload: { schema: 1, name: "DB", parent_id: null, defaults: {} } });
const work = "c".repeat(64);
const overview = recordOverview({ hosts: [jump], groups: [web, db], spaces: [{ id: work, name: "Work", selected: true, missing: false }] });
const rule = (port: number, name = "Database"): TunnelRule => ({
  id: "000000000000000b",
  name,
  host_id: jump.id,
  forward: { kind: "local", bind_address: "127.0.0.1", port, target_host: "db.internal", target_port: 5432 },
});
const items: CatalogCollision[] = [
  { kind: "tunnel", id: "000000000000000b", local: rule(15432), remote: rule(15433) },
  { kind: "route", host_id: jump.id, local: hostTransport({ project: "acme-dev-654321", instance: "jumpbox", zone: "asia-east1-b" }, jump.id), remote: null },
  { kind: "collection", id: work, local: "Work", remote: "Clients" },
  { kind: "group_order", scope: { kind: "local" }, local: [web.id, db.id], remote: [db.id, web.id] },
];
const review = (p: Partial<CatalogReview> = {}): CatalogReview => ({ items, over: null, can_local: true, can_remote: true, ...p });
const shown = (r: CatalogReview) => text(renderToStaticMarkup(<CatalogConflictView review={r} overview={overview} disabled={false} choose={() => {}} />));
const ROOM = "Together, both devices’ changes hold 262 tunnels; a library holds at most 256. Remove some tunnels or routes on this device; Lunport combines both devices’ changes on the next sync.";

describe("a Catalog conflict", () => {
  it("names each colliding item and its two versions in plain words", () => {
    const words = shown(review());
    for (const expected of [
      "Another device changed the same items at the same time. When you choose, Lunport keeps every other change from both devices. Until then, changes to tunnels, routes and collections wait on this device.",
      "Tunnel “Database”",
      "127.0.0.1:15432 → db.internal:5432 through prod-jump",
      "127.0.0.1:15433 → db.internal:5432 through prod-jump",
      "Google Cloud route of “prod-jump”",
      "acme-dev-654321 / jumpbox · asia-east1-b, OS Login",
      "Removed",
      "Name of collection “Work”",
      "Clients",
      "Group order",
      "Web, DB",
      "DB, Web",
    ]) expect(words).toContain(expected);
  });

  it("names a search scope both devices changed, and its two versions", () => {
    const scope = { id: "00000000000000a1", parent: "folders/123456789012", location: "global", account: null };
    const words = shown(review({ items: [{ kind: "pam_scope", id: scope.id, local: { ...scope, account: "ops@example.com" }, remote: null }] }));
    expect(words).toContain("Search scope folder 123456789012 · global");
    expect(words).toContain("folder 123456789012 · global · ops@example.com");
    expect(words).toContain("Removed");
  });

  it("names a tunnel's two names only when they differ", () => {
    const renamed = shown(review({ items: [{ kind: "tunnel", id: "000000000000000b", local: rule(15432, "Postgres"), remote: rule(15432) }] }));
    expect(renamed).toContain("Tunnel “Postgres”");
    expect(renamed).toContain("“Postgres” · 127.0.0.1:15432 → db.internal:5432 through prod-jump");
    expect(renamed).toContain("“Database” · 127.0.0.1:15432 → db.internal:5432 through prod-jump");
  });

  it("names a route whose host is gone by its id", () => {
    const gone = "000000000000dead";
    expect(shown(review({ items: [{ kind: "route", host_id: gone, local: null, remote: hostTransport({}, gone) }] }))).toContain(`Google Cloud route of “${gone}”`);
  });

  it("offers only the choices that fit", () => {
    const words = shown(review({ can_local: false }));
    expect(words).not.toContain("Keep this device’s versions…");
    expect(words).toContain("Use the synced versions…");
    expect(shown(review())).toContain("Keep this device’s versions…");
  });

  it("says the merge waits for the next sync when nothing collides", () => {
    const words = shown(review({ items: [], can_local: false, can_remote: false }));
    expect(words).toContain("Lunport combines both devices’ changes on the next sync.");
    expect(words).not.toContain("versions…");
  });

  it("shows the room sentence instead of choices", () => {
    const colliding = shown(review({ over: ROOM, can_local: false, can_remote: false }));
    expect(colliding).toContain(ROOM);
    expect(colliding).not.toContain("versions…");
    const waiting = shown(review({ items: [], over: ROOM, can_local: false, can_remote: false }));
    expect(waiting.trim()).toBe(ROOM);
  });

  it("words the confirmation for the chosen side", () => {
    expect(catalogChoiceTitle("local")).toBe("Keep this device’s versions of these items?");
    expect(catalogChoiceTitle("remote")).toBe("Use the synced versions of these items?");
    expect(CATALOG_CHOICE_NOTE).toBe("Every other change from both devices stays. Previous versions are kept in an encrypted local recovery snapshot on this device.");
  });
});

describe("a conflict row", () => {
  const conflict = (p: Partial<CentralConflict> = {}): CentralConflict => ({
    id: "a".repeat(64),
    token: "b".repeat(64),
    kind: "host",
    name: "web",
    local: { alias: "web", hostname: "a.invalid" },
    remote: { alias: "web", hostname: "b.invalid" },
    local_deleted: false,
    remote_deleted: false,
    remote_revision: "2",
    can_resolve: true,
    can_remote: true,
    can_copy: true,
    catalog: null,
    ...p,
  });
  const row = (c: CentralConflict) => text(renderToStaticMarkup(<ConflictRow row={c} overview={overview} disabled={false} busy={false} pick={() => {}} />));

  it("keeps the host comparison for a host conflict", () => {
    const words = row(conflict());
    for (const expected of ["web · host", "Address", "a.invalid", "b.invalid", "Keep this device’s version…", "Use synced version…", "Keep both hosts…"]) expect(words).toContain(expected);
  });

  it("draws the Catalog as its items, not as a record", () => {
    const words = row(conflict({ kind: "meta", name: "meta", local: { tunnels: [] }, remote: { tunnels: [] }, can_copy: false, catalog: review() }));
    expect(words).toContain("Tunnels, routes and collections");
    expect(words).toContain("Tunnel “Database”");
    expect(words).not.toContain("meta");
    expect(words).not.toContain("key material or library structure");
    expect(words).not.toContain("Keep this device’s version…");
    expect(words).toContain("Keep this device’s versions…");
  });
});
