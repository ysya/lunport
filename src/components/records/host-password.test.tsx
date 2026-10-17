import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { tauriInvoke } from "@/lib/ipc";
import { HostPasswordField, saveHostPassword } from "./HostPasswordField";
vi.mock("@/lib/ipc", () => ({ tauriInvoke: vi.fn() }));

describe("device-only host passwords", () => {
  beforeEach(() => { vi.mocked(tauriInvoke).mockReset(); });
  it("addresses the credential by stable host ID without a record/sync mutation", async () => {
    const password = " synthetic password with spaces ";
    await saveHostPassword("0000000000000001", { kind: "set", value: password });
    expect(tauriInvoke).toHaveBeenCalledExactlyOnceWith("secrets_set", { alias: "0000000000000001", password });
    vi.mocked(tauriInvoke).mockClear();
    await saveHostPassword("0000000000000001", { kind: "delete" });
    expect(tauriInvoke).toHaveBeenCalledExactlyOnceWith("secrets_delete", { alias: "0000000000000001" });
  });
  it("leaves existing credentials alone when no explicit change is requested", async () => {
    await saveHostPassword("id", null);
    expect(tauriInvoke).not.toHaveBeenCalled();
  });
  it("does not surface a native error that might contain a submitted secret", async () => {
    vi.mocked(tauriInvoke).mockRejectedValue(new Error("native error: SENTINEL_PASSWORD"));
    await expect(saveHostPassword("id", { kind: "set", value: "SENTINEL_PASSWORD" })).rejects.toThrow("Host saved. Couldn’t save the password change on this device.");
    try { await saveHostPassword("id", { kind: "delete" }); } catch (error) { expect(String(error)).not.toContain("SENTINEL_PASSWORD"); }
  });
  it("requires an explicit save action and conceals a replacement without reading the saved password", () => {
    const render = (change: Parameters<typeof HostPasswordField>[0]["change"]) => renderToStaticMarkup(<HostPasswordField hostId={null} change={change} onChange={() => {}} />);
    expect(render(null)).not.toContain("<input");
    expect(render(null)).toContain("Save password on this device");
    const html = render({ kind: "set", value: "" });
    expect(html).toContain('type="password"');
    expect(html).toContain("never sync");
    expect(tauriInvoke).not.toHaveBeenCalled();
  });
});
