import { afterEach, expect, it, vi } from "vitest";
import { stubBackend } from "./test-ipc";
import { previewRecordDeploy, confirmRecordDeploy, cancelRecordDeploy } from "./records";
import { deploymentMessage } from "./records-deploy";
afterEach(() => vi.unstubAllGlobals());
it("sends stable IDs then only the backend preview ID and explicit authorization", async () => {
  const calls = stubBackend(async () => null);
  await previewRecordDeploy("stable-host", "stable-key");
  await confirmRecordDeploy("reviewed-preview", true);
  await cancelRecordDeploy("reviewed-preview");
  expect(calls).toEqual([
    ["records_deploy_preview", { hostId: "stable-host", keyId: "stable-key" }],
    ["records_deploy_confirm", { previewId: "reviewed-preview", authorized: true }],
    ["records_deploy_cancel", { previewId: "reviewed-preview" }],
  ]);
});
it("keeps uncertain and stale outcomes distinct from installed and exposes audit failure without retry", () => {
  expect(deploymentMessage({ outcome: "added", audit_error: null })).toContain("added");
  expect(deploymentMessage({ outcome: "already_present", audit_error: null })).toContain("already");
  expect(deploymentMessage({ outcome: "unknown", audit_error: null })).toContain("could not be confirmed");
  expect(deploymentMessage({ outcome: "stale_preview", audit_error: null })).toContain("Refresh");
  expect(deploymentMessage({ outcome: "added", audit_error: "not saved" })).toContain("log could not be saved");
});
