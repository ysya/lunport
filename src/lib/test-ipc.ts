import { QueryClientProvider, type QueryClient } from "@tanstack/react-query";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { vi } from "vitest";

/*
 * Test helpers for the code that reaches the backend through TanStack Query hooks. Only `*.test.ts(x)` files import this module.
 */

/** Stub the backend: every command, the plugins' too, ends in `window.__TAURI_INTERNALS__.invoke`. */
export function stubBackend(reply: (cmd: string, args: unknown) => Promise<unknown>): Array<[string, unknown]> {
  const calls: Array<[string, unknown]> = [];
  vi.stubGlobal("window", {
    __TAURI_INTERNALS__: {
      invoke: (cmd: string, args: unknown) => {
        calls.push([cmd, args]);
        return reply(cmd, args);
      },
    },
  });
  return calls;
}

/** Run a hook the way a component does and hand back what it returned (a server render: no effects run, nothing subscribes). */
export function renderHook<T>(queryClient: QueryClient, useHook: () => T): T {
  let result!: T;
  const Probe = () => {
    result = useHook();
    return null;
  };
  renderToStaticMarkup(createElement(QueryClientProvider, { client: queryClient }, createElement(Probe)));
  return result;
}
