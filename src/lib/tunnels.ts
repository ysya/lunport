import { tauriInvoke } from "./ipc";
import type { TunnelRule } from "@/bindings/TunnelRule";
import type { TunnelView } from "@/bindings/TunnelView";
import type { ForwardKind } from "@/bindings/ForwardKind";
export type { TunnelRule, TunnelView, ForwardKind };
export const tunnelsKey = ["tunnels"] as const;
export const tunnelKinds: Record<ForwardKind, string> = { local: "Local", remote: "Remote", dynamic: "SOCKS5" };
export const listTunnels = () => tauriInvoke<TunnelView[]>("tunnels_list");
export const saveTunnel = (rule: TunnelRule, expected: TunnelRule | null) => tauriInvoke<void>("tunnels_save", { rule, expected });
export const deleteTunnel = (expected: TunnelRule) => tauriInvoke<void>("tunnels_delete", { expected });
export const startTunnel = (expected: TunnelRule) => tauriInvoke<void>("tunnels_start", { expected });
export const stopTunnel = (id: string) => tauriInvoke<void>("tunnels_stop", { id });
export const tunnelBusy = (row: TunnelView) => ["connecting", "running", "stopping"].includes(row.live.phase);
export function endpoint(host: string, port: number) { return `${host.includes(":") ? `[${host}]` : host}:${port || "auto"}`; }
export function tunnelRoute(rule: TunnelRule, port = rule.forward.port) {
  const f = rule.forward;
  return `${endpoint(f.bind_address, port)} → ${f.kind === "dynamic" ? "SOCKS5" : endpoint(f.target_host, f.target_port)}`;
}
export function newTunnel(hostId = ""): TunnelRule {
  return { id: "", name: "", host_id: hostId, forward: { kind: "local", bind_address: "127.0.0.1", port: 15432, target_host: "127.0.0.1", target_port: 5432 } };
}
