import { afterEach, describe, expect, it, vi } from "vitest";
import { previewLibrarySync, enableLibrarySync, type LibrarySyncPreview } from "@/lib/records";
import { stubBackend } from "@/lib/test-ipc";
import { librarySyncError, suggestedLibraryRenames } from "./library-sync";

afterEach(() => vi.unstubAllGlobals());
const preview: LibrarySyncPreview = {
  token: "reviewed-public-snapshot",
  local_hosts: 1,
  local_groups: 1,
  conflicts: [
    { kind: "group", id: "0000000000000004", current_name: "Production", suggested_name: "Production (2)" },
    { kind: "host", id: "0000000000000003", current_name: "web", suggested_name: "web-2" },
  ],
};

describe("explicit library inclusion", () => {
  it("prepares without consent and submits the exact reviewed names and snapshot", async () => {
    const calls = stubBackend(async (cmd) => cmd === "records_library_preview" ? structuredClone(preview) : null);
    expect(await previewLibrarySync()).toEqual(preview);
    expect(calls).toHaveLength(1);
    const renames = suggestedLibraryRenames(preview);
    renames[1].name = "personal-web";
    await enableLibrarySync(true, { token: preview.token, renames });
    expect(calls[1]).toEqual(["records_library_enable", {
      upgradeConfirmed: true,
      review: { token: preview.token, renames: [
        { kind: "group", id: "0000000000000004", name: "Production (2)" },
        { kind: "host", id: "0000000000000003", name: "personal-web" },
      ] },
    }]);
    expect(preview.conflicts[1].suggested_name).toBe("web-2");
  });
  it("retains specific native causes rather than calling every failure a duplicate name", () => {
    for (const code of ["library_download", "account_check", "stale_review", "name_conflict", "identity_conflict", "upgrade_required"]) {
      expect(librarySyncError({ code, message: `${code}: records kept` })).toBe(`${code}: records kept`);
    }
  });
  it("never exposes an arbitrary relay exception, unknown structured error or empty message", () => {
    for (const error of [new Error("secret relay response"), "secret relay response", { code: "remote_body", message: "secret relay response" }, { code: "library_download", message: "" }, null]) {
      const result = librarySyncError(error);
      expect(result).toContain("Existing records have been kept");
      expect(result).not.toContain("secret relay response");
      expect(result).not.toContain("duplicate");
    }
  });
});
