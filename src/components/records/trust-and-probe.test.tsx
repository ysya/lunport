import { afterEach, describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { stubBackend } from "@/lib/test-ipc";
import { hostView } from "./fixtures";
import { TrustedHostRow } from "./KnownHostsManager";
import { probeLabel } from "./ConnectionCheck";
import { forgetRecordHostKey, probeRecordHost, setRecordGroupOrder, type ConnectionProbe } from "@/lib/records";
import { KnownHostsFilePanel } from "@/components/KnownHostsDialog";
import { queryKeys } from "@/lib/queries";
afterEach(() => vi.unstubAllGlobals());

describe("host trust and reachability", () => {
  it("renders the populated OpenSSH tab without requiring a Legacy tooltip provider", () => {
    const client = new QueryClient();
    client.setQueryData(queryKeys.knownHosts,[{line_index:0,line_hash:"a".repeat(64),hosts:"fixture.test",key_type:"ssh-ed25519",fingerprint_sha256:"SHA256:fixture",hashed:false,marker:null}]);
    const html = renderToStaticMarkup(<QueryClientProvider client={client}><KnownHostsFilePanel /></QueryClientProvider>);
    expect(html).toContain("fixture.test");
    expect(html).toContain("SHA256:fixture");
  });
  it("passes the exact displayed identity and large revision tokens when forgetting trust", async () => {
    const host=hostView();
    host.payload.host_key={algorithm:"ssh-ed25519",public_key:"public-blob",fingerprint:"SHA256:fixture",pinned_at_ms:1,pinned_by_device_id:"d".repeat(32)};
    const calls=stubBackend(async () => null);
    await forgetRecordHostKey(host);
    await probeRecordHost(host.id);
    const order={ids:["b"],revision:host.revision,blocked:false,sync_enabled:true};
    await setRecordGroupOrder(order,["a","b"]);
    expect(calls).toEqual([
      ["records_host_forget_key",{id:host.id,revision:host.revision,hostname:host.effective_payload.hostname,port:host.effective_payload.port,expectedPin:host.payload.host_key}],
      ["records_host_probe",{hostId:host.id}],
      ["records_group_order",{expectedIds:["b"],revision:host.revision,ids:["a","b"]}],
    ]);
  });
  it("identifies the saved fingerprint and its source without exposing key material", () => {
    const host=hostView();
    host.payload.host_key={algorithm:"ssh-ed25519",public_key:"public-blob",fingerprint:"SHA256:fixture",pinned_at_ms:1,pinned_by_device_id:"d".repeat(32)};
    const html=renderToStaticMarkup(<TrustedHostRow host={host} disabled={false} verifying={false} verify={()=>{}} forget={()=>{}} />);
    expect(html).toContain("SHA256:fixture");
    expect(html).toContain("Local host");
    expect(html).toContain("Forget identity");
    expect(html).not.toContain("public-blob");
  });
  it("labels a TCP result separately from SSH login or host online status", () => {
    const result:ConnectionProbe={host_id:"a",hostname:"fixture",port:22,status:"reachable",latency_ms:7,elapsed_ms:10,checked_at_ms:1};
    expect(probeLabel(result)).toBe("Port reachable · 7 ms");
    expect(probeLabel({...result,status:"timed_out"})).toBe("Connection timed out");
    expect(probeLabel({...result,status:"requires_jump"})).toBe("Uses a jump host");
    expect(probeLabel({...result,status:"settings_changed"})).toContain("check again");
  });
});
