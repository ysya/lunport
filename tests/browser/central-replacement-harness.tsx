// Synthetic browser-only fixture. No native account, SSH key, network service or OS credential.
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { CentralReplacement } from "@/components/records/CentralReplacement";
import {
  replacementKey,
  type ReplacementProgress,
} from "@/lib/central-replacement";
import type { CentralStatus } from "@/lib/central-sync";
import "@/index.css";

const client = new QueryClient({
  defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
});
const root = createRoot(document.getElementById("root")!);
const model = {
  mounted: true,
  disabled: false,
  counter: 0,
  generation: null as string | null,
  status: {
    available: true,
    configured: true,
    phase: "enrolled",
    service: "https://sync.test",
    account_id: "a".repeat(64),
    device_id: "b".repeat(32),
    root_fingerprint: "1".repeat(64),
    membership_head: "3".repeat(64),
    authorization_epoch: "2",
    has_session: false,
    needs_recovery: true,
    replacement_pending: false,
    login_pending: false,
    can_sync: false,
    pending: 0,
    conflicts: 0,
    error: null,
  } as CentralStatus,
  progress: {
    phase: "idle",
    operation: null,
    route: null,
    verified: 0,
    total: 0,
    root_fingerprint: "1".repeat(64),
    backup_confirmed: false,
    unresolved_archives: 0,
  } as ReplacementProgress,
  calls: [] as { command: string; args: Record<string, any> }[],
};
const deferred = new Map<string, number>();
const pending = new Map<
  string,
  {
    resolve: (v: unknown) => void;
    reject: (e: unknown) => void;
    result?: unknown;
  }[]
>();
const copy = <T,>(value: T): T => structuredClone(value);
function paint() {
  root.render(
    <QueryClientProvider client={client}>
      <main className="mx-auto max-w-xl p-6">
        <p>Synthetic lifecycle test</p>
        {model.mounted && (
          <CentralReplacement
            status={model.status}
            disabled={model.disabled}
            update={(status) => {
              model.status = status;
              paint();
            }}
            onBusyChange={() => {}}
          />
        )}
      </main>
    </QueryClientProvider>,
  );
}
function apply(command: string, args: Record<string, any>): unknown {
  if (command === "central_replacement_status") return copy(model.progress);
  if (command === "central_status") return copy(model.status);
  if (command === "central_replacement_reserve") {
    const generation = (++model.counter).toString(16).padStart(32, "0");
    model.generation = generation;
    return {
      generation,
      scope: "e".repeat(64),
      route: args.route,
      operation: model.progress.operation,
    };
  }
  if (command === "central_replacement_cancel") {
    if (model.generation === args.invocation.generation) {
      model.generation = null;
      if (["reading", "recovering"].includes(model.progress.phase))
        model.progress = { ...model.progress, phase: "verification_required" };
    }
    return copy(model.progress);
  }
  if (args.invocation?.generation !== model.generation)
    throw "The invocation was superseded.";
  if (command === "central_replacement_start") {
    const route = args.invocation.route;
    model.progress = {
      ...model.progress,
      route,
      operation: model.progress.operation ?? "c".repeat(32),
      phase:
        route === "trusted_device" ? "awaiting_approval" : "backup_required",
      verified: 33,
      total: 33,
    };
    model.status = { ...model.status, replacement_pending: true };
    paint();
    return copy(model.progress);
  }
  if (command === "central_replacement_reveal_pairing")
    return { code: "PAIRING_SECRET_TEST_ONLY", expires_at_ms: "1900000000000" };
  if (command === "central_replacement_reveal_kit")
    return {
      kit: "RECOVERY_SECRET_TEST_ONLY",
      root: model.progress.root_fingerprint,
    };
  if (command === "central_replacement_confirm") {
    model.progress = {
      ...model.progress,
      phase: "reading",
      backup_confirmed: true,
      verified: 0,
      total: 33,
    };
    return copy(model.progress);
  }
  if (command === "central_replacement_continue") {
    model.progress = {
      ...model.progress,
      phase: "complete",
      verified: 33,
      total: 33,
    };
    model.status = {
      ...model.status,
      device_id: "d".repeat(32),
      replacement_pending: false,
      needs_recovery: false,
      has_session: true,
    };
    return copy(model.progress);
  }
  if (command === "central_replacement_revalidate") {
    model.progress = { ...model.progress, phase: "backup_required" };
    return copy(model.progress);
  }
  throw `Unexpected fixture command ${command}`;
}
Object.assign(window, {
  __TAURI_INTERNALS__: {
    invoke(command: string, args: Record<string, any> = {}) {
      model.calls.push({ command, args: copy(args) });
      if ((deferred.get(command) ?? 0) > 0) {
        deferred.set(command, deferred.get(command)! - 1);
        // Reservations/reveals already exist natively when their response is delayed. Other
        // commands can be held before any simulated backend mutation to test late callbacks.
        const result = /reserve|reveal/.test(command)
          ? apply(command, args)
          : undefined;
        return new Promise((resolve, reject) => {
          const list = pending.get(command) ?? [];
          list.push({ resolve, reject, result });
          pending.set(command, list);
        });
      }
      return Promise.resolve().then(() => apply(command, args));
    },
  },
});
const api = {
  model,
  defer(command: string) {
    deferred.set(command, (deferred.get(command) ?? 0) + 1);
  },
  resolve(command: string, value?: unknown) {
    const next = pending.get(command)?.shift();
    if (!next) throw new Error(`No pending ${command}`);
    next.resolve(value ?? next.result);
  },
  reject(command: string) {
    const next = pending.get(command)?.shift();
    if (!next) throw new Error(`No pending ${command}`);
    next.reject("Injected fixture failure");
  },
  mount(value: boolean) {
    model.mounted = value;
    paint();
  },
  disable(value: boolean) {
    model.disabled = value;
    paint();
  },
  hide(value: boolean) {
    Object.defineProperty(document, "hidden", { configurable: true, value });
    document.dispatchEvent(new Event("visibilitychange"));
  },
  status(value: Partial<CentralStatus>) {
    model.status = { ...model.status, ...value };
    paint();
  },
  progress(value: Partial<ReplacementProgress>) {
    model.progress = { ...model.progress, ...value };
    client.setQueryData(replacementKey(model.status), copy(model.progress));
  },
  caches() {
    return {
      queries: client
        .getQueryCache()
        .getAll()
        .map((q) => ({ key: q.queryKey, data: q.state.data })),
      mutations: client.getMutationCache().getAll().length,
    };
  },
};
Object.assign(window, { __replacementTest: api });
paint();
