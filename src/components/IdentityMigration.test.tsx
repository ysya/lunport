import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { MigrationStatus } from "@/bindings/MigrationStatus";
import { credentialsNotice, IdentityMigrationGate, identityMigrationKey, statusCheckFailure } from "./IdentityMigration";

const status = (fields: Partial<MigrationStatus>): MigrationStatus => ({ state: "not_needed", old_path: null, new_path: null, detail: null, failed_step: null, credentials_left: 0, credentials_need_permission: 0, credentials_retry_helps: false, credentials_permission_put_off: 0, ...fields });

function render(value?: MigrationStatus | Error, earlier?: MigrationStatus) {
  // A failed status stays failed while it renders; the gate itself fetches it again only from its Retry. `earlier`: what the check before
  // the failed one said.
  const client = new QueryClient({ defaultOptions: { queries: { retryOnMount: false } } });
  if (value instanceof Error) client.getQueryCache().build(client, { queryKey: identityMigrationKey }).setState({ status: "error", error: value, data: earlier, fetchStatus: "idle" });
  else if (value) client.setQueryData(identityMigrationKey, value);
  return renderToStaticMarkup(
    <QueryClientProvider client={client}>
      <IdentityMigrationGate><p>Workspace</p></IdentityMigrationGate>
    </QueryClientProvider>,
  );
}

describe("IdentityMigrationGate", () => {
  it("opens the app once the data is where this version keeps it", () => {
    for (const state of ["not_needed", "completed", "credentials_pending"] as const) {
      expect(render(status({ state }))).toContain("Workspace");
    }
  });

  it("shows nothing before the backend has said where the data is", () => {
    expect(render()).toBe("");
  });

  it("keeps the app open when a later check fails: the notice says so instead", () => {
    const html = render(new Error("the backend is unavailable"), status({ state: "completed" }));
    expect(html).toContain("Workspace");
    expect(html).not.toContain("Lunport could not check where its data is");
    const blocked = render(new Error("the backend is unavailable"), status({ state: "deferred", detail: "an earlier Lunport still holds sync.lock" }));
    expect(blocked).toContain("an earlier Lunport still holds sync.lock");
  });

  it("does not open the app when the status cannot be read, and offers to ask again", () => {
    const html = render(new Error("the backend is unavailable"));
    expect(html).not.toContain("Workspace");
    expect(html).toContain("Lunport could not check where its data is");
    expect(html).toContain("the backend is unavailable");
    expect(html).toContain(">Retry<");
  });

  it("asks to quit the earlier Lunport and retry while one holds the old folder, and says which lock", () => {
    const html = render(status({ state: "deferred", detail: "an earlier Lunport still holds sync.lock in /data/old" }));
    expect(html).not.toContain("Workspace");
    expect(html).toContain("Quit other Lunport windows and AI client connections, then retry.");
    expect(html).toContain("Nothing has been deleted or merged.");
    expect(html).toContain("an earlier Lunport still holds sync.lock");
    expect(html).toContain(">Retry<");
    expect(html).not.toContain("Continue without moving");
  });

  it("says which folder failed to move and why, without blaming other windows, and lets the interface settings stay behind", () => {
    const html = render(status({ state: "deferred", failed_step: "webkit_store", detail: "cannot move /old to /new: Permission denied" }));
    expect(html).not.toContain("Workspace");
    expect(html).toContain("Lunport could not move the folder with its interface settings");
    expect(html).toContain("cannot move /old to /new: Permission denied");
    expect(html).not.toContain("Quit other Lunport windows");
    expect(html).toContain(">Retry<");
    expect(html).toContain("Continue without moving…");
  });

  it("lets the roaming backups stay behind too", () => {
    const html = render(status({ state: "deferred", failed_step: "backups_root", detail: "cannot move" }));
    expect(html).toContain("Lunport could not move the folder with its backups of your SSH configuration");
    expect(html).toContain("Continue without moving…");
  });

  it("offers no way around the data folder itself", () => {
    const html = render(status({ state: "deferred", failed_step: "data_root", detail: "cannot move /old to /new: Input/output error" }));
    expect(html).toContain("Lunport could not move its data folder");
    expect(html).toContain("Input/output error");
    expect(html).toContain(">Retry<");
    expect(html).not.toContain("Continue without moving");
    expect(html).not.toContain("Quit other Lunport windows");
  });

  it("opens the app while saved credentials have not moved, the notice saying why", () => {
    const pending = status({ state: "credentials_pending", failed_step: "credentials", detail: "the keyring is locked" });
    expect(render(pending)).toContain("Workspace");
    expect(credentialsNotice(pending)?.description).toContain("Why: the keyring is locked.");
  });

  it("names both folders and offers both choices when each holds data", () => {
    const html = render(status({ state: "conflict", old_path: "/data/old", new_path: "/data/new" }));
    expect(html).not.toContain("Workspace");
    expect(html).toContain("Nothing was merged or changed.");
    expect(html).toContain("/data/old");
    expect(html).toContain("/data/new");
    expect(html).toContain("Use the earlier data…");
    expect(html).toContain("Keep the new data…");
  });
});

describe("credentialsNotice", () => {
  it("asks for Retry where it can move them: the vault waits for its key, or the user has something to do", () => {
    for (const state of ["credentials_pending", "completed"] as const) {
      const notice = credentialsNotice(status({ state, failed_step: "credentials", detail: "the keyring is locked: unlock it, then retry" }));
      expect(notice?.warning).toBe(true);
      expect(notice?.retry).toBe(true);
      expect(notice?.allow).toBe(false);
      expect(notice?.title).toBe("Saved credentials have not moved yet");
      expect(notice?.description).toContain("some may be unavailable");
      expect(notice?.description).toContain("the keyring is locked: unlock it, then retry");
      expect(notice?.description).toContain("Nothing was deleted.");
      expect(notice?.description).toContain("Retry moves them, and Lunport restarts if what it uses has moved.");
    }
  });

  it("offers Allow… instead of a Retry that cannot help when only the user's permission holds the vault back", () => {
    const notice = credentialsNotice(status({ state: "credentials_pending", failed_step: "credentials", credentials_need_permission: 2, detail: "the vault's key has not moved" }));
    expect(notice?.warning).toBe(true);
    expect(notice?.allow).toBe(true);
    expect(notice?.retry).toBe(false);
    expect(notice?.description).toContain("2 saved items need your permission");
    expect(notice?.description).toContain("Allow… asks for it again");
    expect(notice?.description).toContain("Always Allow");
    expect(notice?.description).not.toContain("Retry");
    expect(credentialsNotice(status({ state: "credentials_pending", failed_step: "credentials", detail: "the keyring is locked" }))?.allow).toBe(false);
  });

  it("offers Retry beside Allow… where Retry can help: the keychain is locked, or a vault key waits for a failure that may pass", () => {
    const notice = credentialsNotice(status({ state: "credentials_pending", failed_step: "credentials", credentials_need_permission: 1, credentials_retry_helps: true, detail: "the keychain is locked: unlock it, then retry" }));
    expect(notice?.warning).toBe(true);
    expect(notice?.retry).toBe(true);
    expect(notice?.allow).toBe(true);
    expect(notice?.description).toContain("unlock it, then retry");
    expect(notice?.description).toContain("Retry moves what it can now");
    expect(notice?.description).toContain("1 saved item needs your permission: Allow… asks for it");
  });

  it("mentions what stays behind, without a Retry that cannot help", () => {
    const notice = credentialsNotice(status({ state: "completed", credentials_left: 2, detail: "host:web-2 (it can never be read)" }));
    expect(notice?.warning).toBe(false);
    expect(notice?.retry).toBe(false);
    expect(notice?.title).toBe("2 saved credentials stay with the earlier version");
    expect(notice?.description).toContain("host:web-2 (it can never be read)");
    expect(notice?.description).toContain("Nothing was deleted.");
    expect(notice?.description).not.toContain("Retry");
    expect(credentialsNotice(status({ state: "completed", credentials_left: 1 }))?.title).toBe("1 saved credential stays with the earlier version");
  });

  it("says nothing once nothing is left, or where nothing in this version moves them", () => {
    expect(credentialsNotice(status({ state: "credentials_pending" }))).toBeNull();
    expect(credentialsNotice(status({ state: "completed" }))).toBeNull();
    for (const state of ["not_needed", "deferred", "conflict"] as const) {
      expect(credentialsNotice(status({ state, failed_step: "credentials", credentials_left: 3, detail: "a reason" }))).toBeNull();
    }
    expect(credentialsNotice(undefined)).toBeNull();
  });
});

describe("statusCheckFailure", () => {
  it("says that a check after the app opened failed, and why", () => {
    const failure = statusCheckFailure({ isRefetchError: true, error: new Error("the backend is unavailable") });
    expect(failure?.title).toBe("Lunport could not check where its data is");
    expect(failure?.description).toContain("the backend is unavailable");
    expect(failure?.description).toContain("keeps what it found before");
  });

  it("says nothing when the check worked, or before the app opened (the gate says it then)", () => {
    expect(statusCheckFailure({ isRefetchError: false, error: null })).toBeNull();
  });
});
