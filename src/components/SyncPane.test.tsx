import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { SyncOverview } from "@/bindings/SyncOverview";
import { syncOverviewKey } from "@/lib/sync";
import { NOW, SPOOFED_NAME, SPOOFED_NAME_SHOWN, device, overview, space } from "@/lib/sync-fixtures";
import { SyncPane } from "./SyncPane";

/*
 * Settings → Sync rendered on the server (no DOM in these tests) from a filled query cache: what the status row,
 * the Review row, the notices and the Spaces rows say in each state. Dialogs are closed in a server render.
 */

function pane(o: SyncOverview): string {
  const queryClient = new QueryClient();
  queryClient.setQueryData(syncOverviewKey, o);
  return renderToStaticMarkup(
    <QueryClientProvider client={queryClient}>
      <SyncPane />
    </QueryClientProvider>,
  );
}

/** The text of the page without markup or the comments React puts between text nodes; HTML entities decoded for apostrophes. */
function text(html: string): string {
  return html
    .replace(/<!--.*?-->/g, "")
    .replace(/<[^>]*>/g, " ")
    .replace(/&#x27;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/\s+/g, " ");
}

/** The opening tag of the button whose label is `label`. */
function buttonTag(html: string, label: string): string {
  const found = [...html.matchAll(/<button\b[^>]*>([\s\S]*?)<\/button>/g)].find((m) => text(m[1]).trim() === label);
  if (!found) throw new Error(`no ${label} button`);
  return found[0].slice(0, found[0].indexOf(">") + 1);
}

describe("the status row", () => {
  it("names the space that stopped syncing and why, instead of 'Synced'", () => {
    const html = pane(overview({ spaces: [space({ last_error: "duplicate Host web" })] }));
    expect(text(html)).toContain("Personal: duplicate Host web");
    expect(text(html)).not.toContain("Up to date");
  });

  it("counts the spaces when several need attention", () => {
    const html = pane(overview({ spaces: [space({ last_error: "boom" }), space({ id: "b".repeat(64), name: "Work", missing: true })] }));
    expect(text(html)).toContain("2 spaces need attention — see Spaces");
  });
});

describe("hosts waiting for approval", () => {
  it("offers Review while the account can take a decision", () => {
    const html = pane(overview({ approvals_waiting: 2 }));
    expect(text(html)).toContain("2 hosts waiting for your approval");
    expect(buttonTag(html, "Review…")).not.toContain('disabled=""');
  });

  it("turns Review off and says why while the sync code was changed on another computer", () => {
    const html = pane(overview({ approvals_waiting: 2, frozen: { detected_at_ms: NOW, by_devices: ["MacBook-B"] } }));
    expect(text(html)).toContain("Nothing changes until you approve them. Enter the new sync code first.");
    expect(buttonTag(html, "Review…")).toContain('disabled=""');
  });
});

describe("the Spaces rows while the account cannot change its spaces", () => {
  it("say why instead of what the row does, on 'New space' and on 'Move hosts into a space'", () => {
    const html = pane(overview({ frozen: { detected_at_ms: NOW, by_devices: [] } }));
    expect(text(html).split("Enter the new sync code first.").length - 1).toBeGreaterThanOrEqual(2);
    expect(text(html)).not.toContain("Choose which of this computer's hosts should follow you to your other computers.");
  });

  it("say what they do when nothing is in the way", () => {
    const html = pane(overview());
    expect(text(html)).toContain("Starts empty and syncs on this computer.");
    expect(text(html)).toContain("Choose which of this computer's hosts should follow you to your other computers.");
  });
});

describe("a space's name, which another computer chose", () => {
  it("is shown with its hidden characters revealed wherever the pane prints it: the status row, the Spaces list, its labels, the notices, the devices", () => {
    const html = pane(
      overview({
        spaces: [space({ name: SPOOFED_NAME, last_error: "duplicate Host web", synced_on: ["MacBook-A"] })],
        devices: [device({ spaces: [space().id] })],
        notices: [{ kind: "space_deleted", name: SPOOFED_NAME, by_device: "MacBook-B" }],
      }),
    );
    expect(text(html)).toContain(`${SPOOFED_NAME_SHOWN}: duplicate Host web`); // the status row
    expect(text(html)).toContain(`“${SPOOFED_NAME_SHOWN}” was deleted on MacBook-B`); // the notice
    expect(html).toContain(`aria-label="Sync ${SPOOFED_NAME_SHOWN} on this computer"`);
    expect(html).toContain(`aria-label="Actions for ${SPOOFED_NAME_SHOWN}"`);
    expect(text(html)).toContain(`macOS · ${SPOOFED_NAME_SHOWN}`); // the devices list
    // Not one of the characters is left in the page.
    expect(html).not.toMatch(/[\u202E\u200B]/);
  });
});

describe("files SSHelter doesn't use", () => {
  it("speaks of one file in the singular and of several in the plural", () => {
    expect(text(pane(overview({ stray_files: ["hosts.config"] })))).toContain("hosts.config in ~/.ssh/sshelter: it is not in SSHelter's Include line.");
    expect(text(pane(overview({ stray_files: ["a.config", "b.config"] })))).toContain("they are not in SSHelter's Include line.");
  });
});

describe("a computer that is not in a sync account", () => {
  const left = { joined: false, devices: [], spaces: [] };

  it("keeps saying where its files went, and says of a notice about the account it left what it was about", () => {
    const html = pane(
      overview({
        ...left,
        notices: [
          { kind: "left_account", kept_files: ["/home/f/.ssh/sshelter-local/personal-3fa2c1d9.config"] },
          { kind: "new_sync_code" },
        ],
      }),
    );
    expect(text(html)).toContain("Your synced files are now local files");
    expect(text(html)).toContain("The sync code was changed This was about the sync account this computer has since left.");
    expect(text(html)).not.toContain("Show the new sync code, save it");
  });

  it("reads an unfinished upgrade's state from the status line, and asks before it stops", () => {
    const html = pane(overview({ ...left, upgrading: true, last_error: "keychain locked" }));
    expect(text(html)).toContain("keychain locked");
    expect(text(html)).toContain("Stop syncing");
    // The confirm is closed until the button is pressed.
    expect(text(html)).not.toContain("Stop syncing on this computer?");
    const moving = pane(overview({ ...left, upgrading: true }));
    expect(text(moving)).toContain("Moving this computer to the new sync format…");
  });
});

describe("the Devices list", () => {
  it("is drawn from the clock the pane keeps (relative times)", () => {
    const html = pane(
      overview({ devices: [device(), device({ id: "device-b", name: "MacBook-B", is_this: false, last_seen_ms: Date.now() - 3 * 3_600_000 })] }),
    );
    expect(text(html)).toContain("last seen 3h ago");
  });
});
