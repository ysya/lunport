import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { tauriInvoke } from "@/lib/ipc";
import { HostPasswordField, saveHostPassword } from "./HostPasswordField";
vi.mock("@/lib/ipc", () => ({ tauriInvoke: vi.fn() }));
const host = { id: "0000000000000001", revision: { version: "1", updated_at_ms: "1", device_id: "d".repeat(32) } };
const overview = { generation: "4" };

describe("encrypted host passwords", () => {
  beforeEach(() => { vi.mocked(tauriInvoke).mockReset(); });
  it("saves and deletes through the native password boundary with a host revision and generation fence", async () => {
    const password = " synthetic password with spaces ";
    await saveHostPassword(host, { kind: "set", value: password }, overview);
    expect(tauriInvoke).toHaveBeenCalledExactlyOnceWith("records_password_change", { hostId: host.id, expected: host.revision, generation: overview.generation, password });
    vi.mocked(tauriInvoke).mockClear();
    await saveHostPassword(host, { kind: "delete" }, overview);
    expect(tauriInvoke).toHaveBeenCalledExactlyOnceWith("records_password_change", { hostId: host.id, expected: host.revision, generation: overview.generation, password: null });
  });
  it("leaves existing credentials alone when no explicit change is requested", async () => {
    await saveHostPassword(host, null, overview);
    expect(tauriInvoke).not.toHaveBeenCalled();
  });
  it("does not surface a native error that might contain a submitted secret", async () => {
    vi.mocked(tauriInvoke).mockRejectedValue(new Error("native error: SENTINEL_PASSWORD"));
    await expect(saveHostPassword(host, { kind: "set", value: "SENTINEL_PASSWORD" }, overview)).rejects.toThrow("Host saved. Couldn’t save the password change.");
    try { await saveHostPassword(host, { kind: "delete" }, overview); } catch (error) { expect(String(error)).not.toContain("SENTINEL_PASSWORD"); }
  });
  it("requires an explicit save action and conceals a replacement without reading the saved password", () => {
    const render = (change: Parameters<typeof HostPasswordField>[0]["change"]) => renderToStaticMarkup(<HostPasswordField hostId={null} change={change} onChange={() => {}} />);
    expect(render(null)).not.toContain("<input");
    expect(render(null)).toContain("Save password");
    const html = render({ kind: "set", value: "" });
    expect(html).toContain('type="password"');
    expect(html).toContain("Included automatically when you enable encrypted library sync");
    expect(tauriInvoke).not.toHaveBeenCalled();
  });
});
