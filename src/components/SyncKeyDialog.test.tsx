import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { keyCandidate } from "@/lib/sync-fixtures";
import { KeySetupRow, UnsupportedList } from "./SyncKeyDialog";

/**
 * The dialog's rows rendered on the server (no DOM): what each key's row says and which buttons it offers.
 * The dialog itself opens from the UI store and the candidates query; its logic is tested in key-slots.test.ts.
 */
const row = (candidate = keyCandidate(), busy = false) =>
  renderToStaticMarkup(<KeySetupRow candidate={candidate} busy={busy} onChoose={() => {}} />);
/** The text of the markup, with the apostrophes React escapes put back. */
const text = (html: string) => html.replace(/<[^>]*>/g, " ").replace(/&#x27;/g, "'").replace(/\s+/g, " ");
/** The opening tag of the button labelled `label`, without its closing ">". */
const buttonTag = (html: string, label: string) => {
  const at = html.indexOf(`>${label}<`);
  if (at < 0) throw new Error(`no ${label} button`);
  return html.slice(html.lastIndexOf("<button", at), at);
};
// The shared Button's class names carry `disabled:` variants, so only the attribute itself says a button is off.
const DISABLED = 'disabled=""';

describe("a key's row", () => {
  it("says which hosts use the key, asks the question and shows what changes", () => {
    const t = text(row());
    expect(t).toContain("web uses id_mac.");
    expect(t).toContain("Sync this key to your other computers?");
    expect(t).toContain("No passphrase — your sync code and every joined computer can use this key once it syncs.");
    expect(t).toContain("web: IdentityFile ~/.ssh/id_mac → ~/.ssh/sshelter/keys/id_mac-…");
    for (const label of ["Sync key", "Keep on this computer", "Rename"]) expect(row()).toContain(`>${label}<`);
    expect(buttonTag(row(), "Sync key")).not.toContain(DISABLED);
  });

  it("offers only Keep for a key that can't be synced, and says why", () => {
    const html = row(keyCandidate({ unsyncable: "This key isn't in the OpenSSH format, so it can't be synced." }));
    expect(text(html)).toContain("This key isn't in the OpenSSH format, so it can't be synced.");
    expect(buttonTag(html, "Sync key")).toContain(DISABLED);
    expect(buttonTag(html, "Keep on this computer")).not.toContain(DISABLED);
  });

  it("names the hosts it leaves alone", () => {
    const html = row(
      keyCandidate({
        hosts: [
          { alias: "web", space_name: "Personal", value: "~/.ssh/id_mac", locked: null },
          { alias: "api", space_name: "Personal", value: "~/.ssh/id_mac", locked: "This host has more than one copy; SSHelter changes it once only one copy is left." },
        ],
      }),
    );
    expect(text(html)).toContain("Not changed: api — This host has more than one copy");
    expect(text(html)).not.toContain("api: IdentityFile");
  });

  it("turns every button off while a choice is being applied", () => {
    const html = row(keyCandidate(), true);
    for (const label of ["Sync key", "Keep on this computer", "Rename"]) expect(buttonTag(html, label)).toContain(DISABLED);
  });
});

describe("values that can't be set up", () => {
  it("lists each host with its value and the reason", () => {
    const html = renderToStaticMarkup(<UnsupportedList items={[{ alias: "proxy", value: "~/.ssh/%h", reason: "uses % tokens or environment variables" }]} />);
    expect(text(html)).toContain("Can't set up automatically");
    expect(text(html)).toContain("proxy: ~/.ssh/%h — uses % tokens or environment variables");
    expect(renderToStaticMarkup(<UnsupportedList items={[]} />)).toBe("");
  });
});
