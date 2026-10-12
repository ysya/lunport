import { vi } from "vitest";

/**
 * A fake Tauri event bus for tests: `listen()` registers its handler through `transformCallback` and the
 * `plugin:event|listen` command, so both are captured here and `emit` calls the handler the way the webview
 * would. Every command is recorded in `commands`, in the order it was invoked; `answer` gives the result of a
 * command other than `plugin:event|listen` (`undefined` without it). `failListen` makes the backend refuse to
 * register a listener; `failUnlisten` makes releasing one fail. It stubs `window`: the test calls
 * `vi.unstubAllGlobals()` after it. Only `*.test.ts` files import this module.
 */
export function stubEventBus({
  failListen = false,
  failUnlisten = false,
  answer,
}: { failListen?: boolean; failUnlisten?: boolean; answer?: (cmd: string) => unknown } = {}) {
  const callbacks = new Map<number, (event: unknown) => void>();
  const handlers = new Map<string, (event: unknown) => void>();
  const commands: string[] = [];
  let nextId = 1;
  vi.stubGlobal("window", {
    __TAURI_INTERNALS__: {
      transformCallback: (callback: (event: unknown) => void) => {
        const id = nextId++;
        callbacks.set(id, callback);
        return id;
      },
      invoke: async (cmd: string, args: { event?: string; handler?: number }) => {
        commands.push(cmd);
        if (cmd === "plugin:event|listen" && args.event && args.handler) {
          if (failListen) throw new Error("the event plugin refused the listener");
          handlers.set(args.event, callbacks.get(args.handler)!);
          return nextId++;
        }
        return answer?.(cmd);
      },
    },
    __TAURI_EVENT_PLUGIN_INTERNALS__: {
      unregisterListener: () => {
        if (failUnlisten) throw new Error("the listener is already gone");
      },
    },
  });
  const emit = (event: string, payload: unknown) => {
    const handler = handlers.get(event);
    if (!handler) throw new Error(`nobody listens to ${event}`);
    handler({ event, id: 0, payload });
  };
  return { emit, handlers, commands };
}
