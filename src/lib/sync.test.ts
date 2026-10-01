import { readFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { toast } from "sonner";

import { RELAY_DEPLOY_URL, openRelayDeploy } from "./sync";

/** Stub the backend: every plugin command ends in `window.__TAURI_INTERNALS__.invoke`. */
function stubBackend(reply: (cmd: string, args: unknown) => Promise<unknown>): Array<[string, unknown]> {
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

describe("the relay deploy link", () => {
  beforeEach(() => {
    // sonner's `toast.dismiss` schedules through requestAnimationFrame, which Node lacks.
    vi.stubGlobal("requestAnimationFrame", (cb: FrameRequestCallback) => {
      cb(0);
      return 0;
    });
  });

  afterEach(() => {
    toast.dismiss();
    vi.unstubAllGlobals();
  });

  it("starts Cloudflare's deploy flow for this repository's relay folder", () => {
    const target = new URL(RELAY_DEPLOY_URL);
    expect(target.origin).toBe("https://deploy.workers.cloudflare.com");
    expect(target.searchParams.get("url")).toBe("https://github.com/ysya/sshelter/tree/main/relay");
  });

  it("is the same link as the README buttons", () => {
    for (const readme of ["README.md", "relay/README.md"]) {
      expect(readFileSync(readme, "utf8"), readme).toContain(`(${RELAY_DEPLOY_URL})`);
    }
  });

  it("opens it in the default browser", async () => {
    const calls = stubBackend(async () => undefined);
    await openRelayDeploy();
    expect(calls).toEqual([["plugin:opener|open_url", { url: RELAY_DEPLOY_URL, with: undefined }]]);
    expect(toast.getToasts()).toEqual([]);
  });

  it("says so when the browser cannot be opened", async () => {
    stubBackend(async () => {
      throw "opener refused";
    });
    await openRelayDeploy();
    expect(toast.getToasts()).toEqual([
      expect.objectContaining({ title: "Could not open your browser", description: "opener refused" }),
    ]);
  });
});
