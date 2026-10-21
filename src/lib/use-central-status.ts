import { useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { listen } from "@tauri-apps/api/event";
import { newerCentralStatus } from "./central-status";
import { centralStatus, centralStatusKey, type CentralStatus } from "./central-sync";

/** Mounted by the Records workspace, never by the legacy OpenSSH editor. */
export function useCentralStatus() {
  const client = useQueryClient();
  const query = useQuery({ queryKey: centralStatusKey, queryFn: async () => { const incoming = await centralStatus(); return newerCentralStatus(client.getQueryData<CentralStatus>(centralStatusKey), incoming); },
    retry: false, refetchOnWindowFocus: true,
    refetchInterval: (query) => query.state.data?.configured ? 5000 : false });
  useEffect(() => {
    let disposed = false;
    const pending = listen<CentralStatus>("central://status", ({ payload }) => {
      if (!disposed) client.setQueryData<CentralStatus>(centralStatusKey, (previous) => newerCentralStatus(previous, payload));
    });
    return () => { disposed = true; void pending.then((stop) => stop()).catch(() => {}); };
  }, [client]);
  return query;
}
