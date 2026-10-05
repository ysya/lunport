import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { PendingApprovalView } from "@/bindings/PendingApprovalView";
import { NOW } from "@/lib/sync-fixtures";
import { CLICK_GUARD_MS, PendingHost, ReviewFooter } from "./SyncApprovalDialog";

/*
 * The markup of the card and the footer, rendered on the server (no DOM in these tests): what the user is told
 * on a card, which button shows the spinner, how the change list treats whitespace, and where Close sits.
 */

const view: PendingApprovalView = {
  space_id: "a".repeat(64),
  space_name: "Work",
  alias: "web",
  digest: "d1",
  text: "Host web\n  HostName 10.0.0.1\n  ProxyCommand nc %h 22\n",
  current_text: null,
  applied: { host: "", gated: [] },
  incoming: { host: "web", gated: [{ keyword: "proxycommand", value: "nc %h 22" }] },
  from_device: "MacBook-B",
  updated_at_ms: NOW,
};

function card(props: Partial<Parameters<typeof PendingHost>[0]> = {}): string {
  return renderToStaticMarkup(
    <PendingHost
      view={view}
      hosts={[]}
      spaces={undefined}
      mark={undefined}
      running={null}
      busy={false}
      locked={false}
      guarded={false}
      onApprove={() => undefined}
      onReject={() => undefined}
      {...props}
    />,
  );
}

function footer(props: Partial<Parameters<typeof ReviewFooter>[0]> = {}): string {
  return renderToStaticMarkup(
    <ReviewFooter count={3} busy={false} locked={false} guarded={false} runningAll={null} onClose={() => undefined} onRejectAll={() => undefined} onApproveAll={() => undefined} {...props} />,
  );
}

/** The inside of every button, in order. */
function buttons(html: string): string[] {
  return [...html.matchAll(/<button\b[^>]*>([\s\S]*?)<\/button>/g)].map((m) => m[1]);
}

/** The inside of the button whose label is `label` (React separates text nodes with comments). */
function button(html: string, label: string): string {
  const found = buttons(html).find((inner) => inner.replace(/<!--.*?-->/g, "").trim().endsWith(label));
  if (found === undefined) throw new Error(`no ${label} button in ${html}`);
  return found;
}

/** Whether each button is disabled, in order. */
function disabledFlags(html: string): boolean[] {
  return [...html.matchAll(/<button\b[^>]*>/g)].map((m) => m[0].includes('disabled=""'));
}

/** The labels of the buttons, in order, without markup. */
function labels(html: string): string[] {
  return buttons(html).map((inner) => inner.replace(/<!--.*?-->/g, "").replace(/<[^>]*>/g, "").trim());
}

describe("a held host's card", () => {
  it("says on the card when its version is not the one the user first saw", () => {
    expect(card({ mark: "changed" })).toContain("Changed since you opened this — review it again");
    expect(card({ mark: "new" })).toContain("New since you opened this");
    const plain = card();
    expect(plain).not.toContain("since you opened this");
  });

  it("shows the spinner on the button that runs, and on no other", () => {
    expect(button(card({ running: "approve", busy: true }), "Approve")).toContain("animate-spin");
    expect(button(card({ running: "approve", busy: true }), "Reject")).not.toContain("animate-spin");
    expect(button(card({ running: "reject", busy: true }), "Reject")).toContain("animate-spin");
    expect(button(card({ running: "reject", busy: true }), "Approve")).not.toContain("animate-spin");
    expect(card({ running: null })).not.toContain("animate-spin");
  });

  it("disables both buttons while any decision runs", () => {
    const html = card({ busy: true });
    expect([...html.matchAll(/<button\b[^>]*\bdisabled=""/g)]).toHaveLength(2);
    expect([...card().matchAll(/<button\b[^>]*\bdisabled=""/g)]).toHaveLength(0);
  });

  it("turns both buttons off while the account cannot take a decision, and keeps them on otherwise", () => {
    expect([...card({ locked: true }).matchAll(/<button\b[^>]*\bdisabled=""/g)]).toHaveLength(2);
    expect([...card({ locked: false }).matchAll(/<button\b[^>]*\bdisabled=""/g)]).toHaveLength(0);
  });

  it("turns both buttons off for a moment after the list on screen was replaced, so a click aimed at what was there lands on nothing", () => {
    expect([...card({ guarded: true }).matchAll(/<button\b[^>]*\bdisabled=""/g)]).toHaveLength(2);
    expect([...card({ guarded: false }).matchAll(/<button\b[^>]*\bdisabled=""/g)]).toHaveLength(0);
  });

  it("keeps the whitespace of the change list, so values that differ only in it look different", () => {
    const html = card({ hosts: [{ patterns: ["web"], source_file: "/home/f/.ssh/config" }] });
    const items = [...html.matchAll(/<li\b[^>]*class="([^"]*)"/g)].map((m) => m[1]);
    expect(items.length).toBe(3);
    for (const classes of items) expect(classes).toContain("whitespace-pre-wrap");
  });

  it("says which existing host approving takes over, and in which file", () => {
    const spaces = [{ id: "a".repeat(64), name: "Work", file_path: "/home/f/.ssh/sshelter/work-aaaaaaaa.config" }];
    const html = card({ hosts: [{ patterns: ["web", "prod"], source_file: "/home/f/.ssh/config" }], spaces });
    expect(html).toContain("Not in Work on this computer yet: Host web");
    expect(html).toContain("Takes over web in /home/f/.ssh/config (synced files are read first)");
    expect(card()).not.toContain("Takes over");
  });

  it("says a block of its own space file comes first yet the held block's settings still apply, and does not also say the host is not in that space", () => {
    const work = "/home/f/.ssh/sshelter/work-aaaaaaaa.config";
    const html = card({ hosts: [{ patterns: ["db", "web"], source_file: work }], spaces: [{ id: "a".repeat(64), name: "Work", file_path: work }] });
    expect(html).toContain("A new block in Work: Host web");
    expect(html).toContain(
      "web is also a name of another block in /home/f/.ssh/sshelter/work-aaaaaaaa.config: that block comes first and its values win wherever it sets one. ProxyCommand from this block still applies unless that block sets it too.",
    );
    expect(html).not.toContain("Not in Work");
    expect(html).not.toContain("Takes over");
  });

  it("highlights the Host line of a host that is not in its space yet when it names more than one host", () => {
    const wide = card({ view: { ...view, text: "Host web prod\n  ProxyCommand nc %h 22\n", incoming: { ...view.incoming, host: "web prod" } } });
    expect(wide).toMatch(/<div class="[^"]*bg-amber-500\/15[^"]*">Host web prod<\/div>/);
    expect(card()).not.toMatch(/<div class="[^"]*bg-amber-500\/15[^"]*">Host web<\/div>/);
  });

  it("shows the characters that draw nothing instead of drawing nothing", () => {
    const html = card({ view: { ...view, alias: "we\u{3164}b", from_device: "Mac\u{202E}Book" } });
    expect(html).toContain("we⟨U+3164⟩b");
    expect(html).toContain("Mac⟨U+202E⟩Book");
    expect(html).not.toContain("\u{3164}");
    expect(html).not.toContain("\u{202E}");
  });

  it("shows a mark that has nothing to sit on, wherever remote text appears on the card", () => {
    const text = "Host web\n  ProxyCommand nc %h %p;\u{301}#$(id)\n";
    const html = card({ view: { ...view, text, incoming: { host: "web", gated: [{ keyword: "proxycommand", value: "nc %h %p;\u{301}#$(id)" }] } } });
    expect(html).toContain("ProxyCommand nc %h %p;⟨U+0301⟩#$(id)"); // the block line
    expect(html).toContain("Adds ProxyCommand nc %h %p;⟨U+0301⟩#$(id)"); // the change list
    expect(html).not.toContain("\u{301}");
  });
});

describe("the footer", () => {
  it("keeps Close at the right edge: the all-hosts buttons come before it, so hosts that arrive never put one of them where Close was", () => {
    expect(labels(footer({ count: 3 }))).toEqual(["Reject all", "Approve all (3)", "Close"]);
    expect(labels(footer({ count: 2 }))).toEqual(["Reject all", "Approve all (2)", "Close"]);
    // One host has its own buttons; nothing listed (loading, an error, nothing waiting) offers nothing to act on.
    expect(labels(footer({ count: 1 }))).toEqual(["Close"]);
    expect(labels(footer({ count: 0 }))).toEqual(["Close"]);
  });

  it("turns the all-hosts buttons off while the account cannot take a decision, but never Close", () => {
    const locked = footer({ locked: true });
    expect(labels(locked)).toEqual(["Reject all", "Approve all (3)", "Close"]);
    expect(disabledFlags(locked)).toEqual([true, true, false]);
    expect(disabledFlags(footer({ locked: false }))).toEqual([false, false, false]);
  });

  it("turns the all-hosts buttons off for a moment after the list was replaced, but never Close", () => {
    expect(disabledFlags(footer({ guarded: true }))).toEqual([true, true, false]);
    expect(disabledFlags(footer({ guarded: false }))).toEqual([false, false, false]);
  });

  it("shows the spinner on the all-hosts button that runs, and disables every button meanwhile", () => {
    const approving = footer({ runningAll: "approve", busy: true });
    expect(button(approving, "Approve all (3)")).toContain("animate-spin");
    expect(button(approving, "Reject all")).not.toContain("animate-spin");
    const rejecting = footer({ runningAll: "reject", busy: true });
    expect(button(rejecting, "Reject all")).toContain("animate-spin");
    expect(button(rejecting, "Approve all (3)")).not.toContain("animate-spin");
    expect([...approving.matchAll(/<button\b[^>]*\bdisabled=""/g)]).toHaveLength(3);
    expect([...footer().matchAll(/<button\b[^>]*\bdisabled=""/g)]).toHaveLength(0);
    expect(footer()).not.toContain("animate-spin");
  });
});

describe("the click guard", () => {
  it("is short: long enough to see the list change, too short to be in the way", () => {
    expect(CLICK_GUARD_MS).toBeGreaterThanOrEqual(300);
    expect(CLICK_GUARD_MS).toBeLessThanOrEqual(1000);
  });

  // No DOM in these tests, so the wiring is pinned in the source: the guard starts in a layout effect (before the
  // browser paints the render that moved the list) whenever `listMoved` says what sits above the list changed, and
  // the paragraphs and the banner are drawn from the very object it compares.
  it("is started before the browser paints whenever what sits above the list changed", () => {
    const source = readFileSync("src/components/SyncApprovalDialog.tsx", "utf8");
    expect(source).toMatch(/useLayoutEffect\(\(\) => \{\s*if \(listMoved\(aboveBefore\.current, above\)\) guard\(\);\s*aboveBefore\.current = above;\s*\}, \[above\.lock, above\.notice, above\.newer\]\);/);
    for (const part of ["above.lock &&", "above.notice &&", "above.newer &&"]) expect(source, part).toContain(part);
  });
});
