// Synthetic browser fixture. No native commands, account, credentials or private SSH material.
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RecordsKeysPanel } from "@/components/records/KeysPanel";
import { recordOverview } from "@/components/records/fixtures";
import type { RecordKeyView } from "@/lib/records";
import "@/index.css";
import "@/components/records/library.css";
const client = new QueryClient({
  defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
});
const root = createRoot(document.getElementById("root")!);
const model = {
  central: false,
  status: "available" as RecordKeyView["status"],
  storage: "managed" as RecordKeyView["storage"],
  calls: [] as string[],
};
Object.assign(window, {
  __TAURI_INTERNALS__: {
    invoke(command: string) {
      model.calls.push(command);
      return Promise.reject("Synthetic fixture rejects all native actions");
    },
  },
});
function paint() {
  root.render(
    <QueryClientProvider client={client}>
      <main className="flex h-screen flex-col p-6">
        <RecordsKeysPanel
          overview={recordOverview({
            central_mode: model.central,
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
          })}
        />
      </main>
    </QueryClientProvider>,
  );
}
Object.assign(window, {
  __centralKeysTest: {
    model,
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
