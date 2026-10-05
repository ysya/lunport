import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { ReasonList } from "./SyncMigrationDialog";

/*
 * The list of hosts that were refused or failed, rendered on the server (no DOM in these tests): one line per
 * reason, and bounded, so a stop of the relay that lists every remaining host cannot outgrow the dialog.
 */

const limited = "the relay is rate-limiting new spaces from this network, so no more are created now; try again in about an hour";

function list(failures: { alias: string; error: string }[]): string {
  return renderToStaticMarkup(<ReasonList failures={failures} />);
}

describe("the list of hosts that could not be moved", () => {
  it("names the hosts that share a reason once, with the reason once", () => {
    const html = list([
      { alias: "a", error: "a is already in that space" },
      { alias: "b", error: limited },
      { alias: "c", error: limited },
      { alias: "d", error: limited },
    ]);
    expect(html.split(limited)).toHaveLength(2); // the reason is printed once
    expect(html).toContain("b, c, d");
    expect(html).toContain("a is already in that space");
  });

  it("scrolls instead of growing the dialog", () => {
    const many = Array.from({ length: 60 }, (_, i) => ({ alias: `host-${i}`, error: `reason ${i}` }));
    const html = list(many);
    expect(html).toMatch(/class="[^"]*\bmax-h-40\b[^"]*\boverflow-y-auto\b/);
    expect([...html.matchAll(/reason \d+/g)]).toHaveLength(60);
  });

  it("prints nothing for no hosts", () => {
    expect(list([])).not.toContain("<p");
  });
});
