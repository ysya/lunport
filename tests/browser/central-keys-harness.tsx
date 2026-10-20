// Synthetic browser fixture. No native commands, account, credentials or private SSH material.
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RecordsKeysPanel } from "@/components/records/KeysPanel";
import { recordOverview, recordsStatus } from "@/components/records/fixtures";
import {
  recordKeyDestinationKey,
  recordsStatusKey,
  type RecordKeyView,
} from "@/lib/records";
import "@/index.css";
import "@/components/records/library.css";
const client = new QueryClient({
  defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
});
const root = createRoot(document.getElementById("root")!);
const pending: Array<() => void> = [];
const model = {
  central: false,
  root: "a",
  defer: false,
  status: "available" as RecordKeyView["status"],
  storage: "managed" as RecordKeyView["storage"],
  calls: [] as string[],
};
Object.assign(window, {
  __TAURI_INTERNALS__: {
    invoke(command: string) {
      model.calls.push(command);
      if (model.defer && command.startsWith("records_key_")) {
        const reply = {
          ...overview(),
          generation: "999999999999999999",
          last_error: "SYNTHETIC_OLD_REPLY",
        };
        return new Promise((resolve) => pending.push(() => resolve(reply)));
      }
      return Promise.reject("Synthetic fixture rejects all native actions");
    },
  },
});
function overview() {
  return recordOverview({
    central_mode: model.central,
    key_scope: model.central
      ? {
          generation: "1",
          profile: "1".repeat(64),
          account: "2".repeat(64),
          genesis: model.root.repeat(64),
          vault: "4".repeat(64),
          device: "5".repeat(32),
          identity_slot: null,
        }
      : undefined,
    account: {
      chain_id: "a".repeat(64),
      device_name: "Synthetic device",
    },
    keys: [
      {
        id: "b".repeat(32),
        authority: "account",
        synced: false,
        status: model.status,
        storage: model.storage,
        public: null,
      },
    ],
  });
}
function paint() {
  client.setQueryData(
    recordsStatusKey,
    recordsStatus({ overview: overview() }),
  );
  root.render(
    <QueryClientProvider client={client}>
      <main
        data-central={model.central}
        data-root={model.root}
        className="flex h-screen flex-col p-6"
      >
        <RecordsKeysPanel overview={overview()} />
      </main>
    </QueryClientProvider>,
  );
}
Object.assign(window, {
  __centralKeysTest: {
    model,
    root(value: string) {
      model.root = value;
      paint();
    },
    defer(value: boolean) {
      model.defer = value;
    },
    reply() {
      pending.splice(0).forEach((resolve) => resolve());
    },
    cachedDestination() {
      const status = client.getQueryData<{
        overview?: ReturnType<typeof overview>;
      }>(recordsStatusKey);
      return status?.overview ? recordKeyDestinationKey(status.overview) : null;
    },
    cachedError() {
      return (
        client.getQueryData<{ overview?: ReturnType<typeof overview> }>(
          recordsStatusKey,
        )?.overview?.last_error ?? null
      );
    },
    clearCalls() {
      model.calls = [];
    },
    central(value: boolean) {
      model.central = value;
      paint();
    },
    storage(value: RecordKeyView["storage"]) {
      model.storage = value;
      paint();
    },
    status(value: RecordKeyView["status"]) {
      model.status = value;
      paint();
    },
  },
});
paint();
