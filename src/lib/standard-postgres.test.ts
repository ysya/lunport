import { expect, it, vi } from "vitest";
import { tauriInvoke } from "./ipc";
import { deleteStandardPostgres, saveStandardPostgres, type StandardPostgresDraft, type StandardPostgresProfile } from "./standard-postgres";

vi.mock("./ipc", () => ({ tauriInvoke: vi.fn() }));

it("writes direct and SSH profiles with the revision and explicit credential choice in native commands", async () => {
  const draft: StandardPostgresDraft = {
    name: "Reports", host: "reports.example.com", port: 5432, database: "reports", username: "reader", via_host: null,
  };
  const profile: StandardPostgresProfile = {
    ...draft, id: "postgres-a1", revision: "rev-a1", has_password: true, route_unavailable: false, route_revision: null,
  };
  await saveStandardPostgres(null, draft, "synthetic-password", false);
  await saveStandardPostgres(profile, { ...draft, via_host: "00000000000000b1" }, null, true);
  await saveStandardPostgres(profile, { ...draft, via_host: "00000000000000b1" }, null, false, "route-a1");
  await deleteStandardPostgres(profile);
  expect(vi.mocked(tauriInvoke).mock.calls).toEqual([
    ["standard_postgres_save", { id: null, expectedRevision: null, draft, password: "synthetic-password", forgetPassword: false }],
    ["standard_postgres_save", { id: "postgres-a1", expectedRevision: "rev-a1", draft: { ...draft, via_host: "00000000000000b1" }, password: null, forgetPassword: true }],
    ["standard_postgres_save", { id: "postgres-a1", expectedRevision: "rev-a1", draft: { ...draft, via_host: "00000000000000b1" }, password: null, forgetPassword: false, expectedRoute: "route-a1" }],
    ["standard_postgres_delete", { id: "postgres-a1", expectedRevision: "rev-a1" }],
  ]);
});
