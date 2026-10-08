import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";

import { rememberKeySetupAsked } from "@/lib/key-slots";
import { queryKeys } from "@/lib/queries";
import { keyCandidatesKey, syncOverviewKey } from "@/lib/sync";
import { keyCandidate, overview } from "@/lib/sync-fixtures";
import { KeySetupRow, UnsupportedList, dialogBusy, shouldAskOnUpgrade, useKeySetupOnUpgrade } from "./SyncKeyDialog";

afterEach(() => vi.unstubAllGlobals());

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

describe("a key slot kept from the previous sync account", () => {
  const FILE = "mac-3fa2c1d9";
  const kept = (synced_copy: boolean) =>
    keyCandidate({
      default_name: "mac",
      kept_slot: { id: `3fa2c1d9${"0".repeat(24)}`, file_name: FILE, synced_copy, in_vault: false, local_only: false },
      hosts: [
        { alias: "web", space_name: "Personal", value: `~/.ssh/sshelter/keys/${FILE}`, locked: null },
        { alias: "db", space_name: "Personal", value: "~/.ssh/id_mac", locked: null },
      ],
    });

  it("keeps its name, says where it came from under the question and shows only the hosts that change", () => {
    const html = row(kept(false));
    expect(html).not.toContain(">Rename<");
    expect(html).not.toContain('aria-label="Key name"');
    const t = text(html);
    expect(t).toContain("web and db use mac.");
    const question = t.indexOf("Sync this key to your other computers?");
    const note = t.indexOf(`From your previous sync account. Its hosts keep using ~/.ssh/sshelter/keys/${FILE}.`);
    expect(question).toBeGreaterThanOrEqual(0);
    expect(note).toBeGreaterThan(question);
    expect(t).toContain(`db: IdentityFile ~/.ssh/id_mac → ~/.ssh/sshelter/keys/${FILE}`);
    expect(t).not.toContain("web: IdentityFile");
    for (const label of ["Sync key", "Keep on this computer"]) expect(buttonTag(html, label)).not.toContain(DISABLED);
  });

  it("calls a synced copy this computer's copy", () => {
    const t = text(row(kept(true)));
    expect(t).toContain(`This computer's copy, synced to it in your previous sync account. Its hosts keep using ~/.ssh/sshelter/keys/${FILE}.`);
    expect(row(kept(true))).not.toContain(">Rename<");
  });

  it("leaves other keys as they were: Rename and no note", () => {
    const html = row();
    expect(html).toContain(">Rename<");
    expect(text(html)).not.toContain("previous sync account");
  });
});

describe("a key in SSHelter that a synced host uses", () => {
  const FILE = "laptop-3fa2c1d9";
  const inSshelter = (local_only: boolean) =>
    keyCandidate({
      path: `/home/f/.ssh/sshelter/keys/${FILE}`,
      default_name: "laptop",
      kept_slot: { id: `3fa2c1d9${"0".repeat(24)}`, file_name: FILE, synced_copy: false, in_vault: true, local_only },
      hosts: [{ alias: "web", space_name: "Personal", value: `~/.ssh/sshelter/keys/${FILE}`, locked: null }],
    });

  it("asks under its own name, says where the key is and offers both answers without rewriting anything", () => {
    const html = row(inSshelter(true));
    const t = text(html);
    expect(html).not.toContain(">Rename<");
    expect(t).toContain("web uses laptop.");
    expect(t).toContain(`This key is only on this computer, in SSHelter. Its hosts keep using ~/.ssh/sshelter/keys/${FILE}.`);
    expect(t).not.toContain("IdentityFile");
    for (const label of ["Sync key", "Keep on this computer"]) expect(buttonTag(html, label)).not.toContain(DISABLED);
    expect(text(row(inSshelter(false)))).toContain(`From your previous sync account, in SSHelter on this computer. Its hosts keep using ~/.ssh/sshelter/keys/${FILE}.`);
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

describe("while the keys are read again", () => {
  const LABELS = ["Sync key", "Keep on this computer", "Rename"];

  it("is busy while a choice is being applied and while the keys are read again", () => {
    expect(dialogBusy({ applying: false, rereading: false })).toBe(false);
    expect(dialogBusy({ applying: true, rereading: false })).toBe(true);
    expect(dialogBusy({ applying: false, rereading: true })).toBe(true);
  });

  // A successful answer starts reading the keys again before it is reported, so for a moment the rows on screen are the old
  // ones, the key just answered among them. The dialog's content can't be rendered here (Radix portals render nothing on the
  // server, and the rows only show once the first read is back), so the rule is pinned together with the row it turns off.
  it("turns the rows off while the keys are read again, as while a choice is applied", () => {
    for (const state of [{ applying: false, rereading: true }, { applying: true, rereading: false }]) {
      const html = row(keyCandidate(), dialogBusy(state));
      for (const label of LABELS) expect(buttonTag(html, label)).toContain(DISABLED);
    }
    const idle = row(keyCandidate(), dialogBusy({ applying: false, rereading: false }));
    for (const label of LABELS) expect(buttonTag(idle, label)).not.toContain(DISABLED);
  });
});

describe("the question after an update", () => {
  it("is decided only for a computer that syncs, once its config has loaded, and only once", () => {
    // Until the backend has the config it answers an empty list, not an error: deciding on that answer would use the question up.
    expect(shouldAskOnUpgrade({ joined: false, configLoaded: true, askedBefore: false })).toBe(false);
    expect(shouldAskOnUpgrade({ joined: true, configLoaded: false, askedBefore: false })).toBe(false);
    expect(shouldAskOnUpgrade({ joined: true, configLoaded: true, askedBefore: true })).toBe(false);
    expect(shouldAskOnUpgrade({ joined: true, configLoaded: true, askedBefore: false })).toBe(true);
  });

  /**
   * What `useKeySetupOnUpgrade` hands the candidates query as `enabled` on its first render, from a query cache that holds the
   * answers a start-up has so far. A server render runs no effects, so nothing is fetched or decided here: this is the render-time
   * decision that gates the hook's effect, which neither asks nor remembers while it is off.
   */
  function enabledFor({ joined, configLoaded }: { joined: boolean; configLoaded: boolean }) {
    const queryClient = new QueryClient();
    queryClient.setQueryData(syncOverviewKey, overview({ joined }));
    if (configLoaded) queryClient.setQueryData(queryKeys.hosts, { files: [], hosts: [] });
    const Probe = () => {
      useKeySetupOnUpgrade();
      return null;
    };
    renderToStaticMarkup(
      <QueryClientProvider client={queryClient}>
        <Probe />
      </QueryClientProvider>,
    );
    // The hook's observer built that query with the options it was given.
    const query = queryClient.getQueryCache().find({ queryKey: keyCandidatesKey });
    return (query?.options as unknown as { enabled?: boolean } | undefined)?.enabled;
  }

  it("is what the hook gives the candidates query: it stays off until the account and the config are both there", () => {
    expect(enabledFor({ joined: true, configLoaded: false })).toBe(false);
    expect(enabledFor({ joined: false, configLoaded: true })).toBe(false);
    expect(enabledFor({ joined: true, configLoaded: true })).toBe(true);
    const store = new Map<string, string>();
    vi.stubGlobal("localStorage", { getItem: (k: string) => store.get(k) ?? null, setItem: (k: string, v: string) => store.set(k, v) });
    rememberKeySetupAsked();
    expect(enabledFor({ joined: true, configLoaded: true })).toBe(false);
  });
});
