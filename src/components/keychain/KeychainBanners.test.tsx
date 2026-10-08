import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import type { ComponentProps } from "react";
import { describe, expect, it } from "vitest";

import type { SyncKeySlotView } from "@/bindings/SyncKeySlotView";
import { agentProblemKey } from "@/lib/agent";
import { launchAtLoginKey } from "@/lib/queries";
import { syncOverviewKey } from "@/lib/sync";
import { keySlot, overview } from "@/lib/sync-fixtures";
import { AgentProblemLine, KeychainBannersFor, KeychainBannersView } from "./KeychainBanners";
import { buttonTag, buttonsIn, DISABLED, text, textIn } from "./test-markup";

describe("the agent's problem", () => {
  it("shows why the agent can't be reached, with Fix for a removed Include", () => {
    const missing = renderToStaticMarkup(<AgentProblemLine problem={{ kind: "include_missing" }} busy={false} onFix={() => {}} />);
    expect(text(missing)).toContain("Hosts that use keys in SSHelter can't reach its agent.");
    expect(missing).toContain(">Fix<");
    const failed = renderToStaticMarkup(<AgentProblemLine problem={{ kind: "not_running", reason: "path too long" }} busy={false} onFix={() => {}} />);
    expect(text(failed)).toContain("SSHelter's agent isn't running: path too long");
    expect(failed).not.toContain(">Fix<");
  });

  it("turns Fix off while something is running, and presses it through onFix", () => {
    const problem = { kind: "include_missing" } as const;
    // The line has no hooks: calling it gives its element tree, whose button can be read and pressed.
    const fixButton = (busy: boolean, onFix = () => {}) => buttonsIn(AgentProblemLine({ problem, busy, onFix }))[0];
    expect(fixButton(true).props.disabled).toBe(true);
    expect(fixButton(false).props.disabled).toBe(false);
    let fixed = 0;
    const fix = fixButton(false, () => fixed++);
    expect(textIn(fix)).toBe("Fix");
    fix.props.onClick!();
    expect(fixed).toBe(1);
  });

  it("lets a long reason wrap instead of pushing Fix out of the sidebar", () => {
    const reason = `socket path is too long: /home/${"x".repeat(200)}/.ssh/sshelter/agent/sock`;
    const html = renderToStaticMarkup(<AgentProblemLine problem={{ kind: "not_running", reason }} busy={false} onFix={() => {}} />);
    const opening = html.slice(html.indexOf("<p "), html.indexOf(">", html.indexOf("<p ")));
    for (const cls of ["min-w-0", "break-words"]) expect(opening).toContain(cls);
  });
});

type ViewProps = ComponentProps<typeof KeychainBannersView>;
const view = (overrides: Partial<ViewProps> = {}) =>
  KeychainBannersView({
    problem: null,
    movable: 0,
    launchHint: false,
    gitHint: null,
    busy: false,
    onFix: () => {},
    onMove: () => {},
    onLaunch: () => {},
    onDismissLaunch: () => {},
    onCopyGit: () => {},
    ...overrides,
  });
const banners = (overrides: Partial<ViewProps> = {}) => renderToStaticMarkup(view(overrides));
const GIT = "git config --global core.sshCommand C:/Windows/System32/OpenSSH/ssh.exe";

describe("the banners above the Keychain's list", () => {
  it("show nothing when there is nothing to say", () => {
    expect(banners()).toBe("");
  });

  it("come in order: the agent's problem, Move, the launch hint, the Git hint", () => {
    const t = text(banners({ problem: { kind: "include_missing" }, movable: 2, launchHint: true, gitHint: GIT }));
    const order = [
      "can't reach its agent",
      "2 keys can move into SSHelter",
      "Keys in SSHelter work only while SSHelter is running.",
      "Git for Windows uses its own ssh, which can't reach SSHelter's agent. Run this once:",
    ].map((part) => t.indexOf(part));
    expect(order.every((at) => at >= 0)).toBe(true);
    expect([...order].sort((a, b) => a - b)).toEqual(order);
    expect(t).toContain(GIT);
  });

  it("press through to Move, launch at login, Dismiss and Copy", () => {
    const pressed: string[] = [];
    const tree = view({
      movable: 1,
      launchHint: true,
      gitHint: GIT,
      onMove: () => pressed.push("move"),
      onLaunch: () => pressed.push("launch"),
      onDismissLaunch: () => pressed.push("dismiss"),
      onCopyGit: () => pressed.push("copy"),
    });
    const buttons = buttonsIn(tree);
    expect(buttons.map(textIn)).toEqual(["Move", "Turn on launch at login", "Dismiss", "Copy"]);
    buttons.forEach((b) => b.props.onClick!());
    expect(pressed).toEqual(["move", "launch", "dismiss", "copy"]);
  });

  it("turn Move and launch at login off while something runs", () => {
    const busy = banners({ movable: 1, launchHint: true, busy: true });
    expect(buttonTag(busy, "Move")).toContain(DISABLED);
    expect(buttonTag(busy, "Turn on launch at login")).toContain(DISABLED);
    expect(buttonTag(busy, "Dismiss")).not.toContain(DISABLED);
  });
});

describe("this computer's banners", () => {
  // A server render reads a zustand store's initial state: the dismissed hint and the menu-bar setting are handed in.
  const render = (
    slots: SyncKeySlotView[],
    o: { launchAtLogin?: boolean; dismissed?: boolean; closeToTray?: boolean; joined?: boolean } = {},
  ) => {
    const queryClient = new QueryClient();
    const account = o.joined === false ? { joined: false, account_short: null, devices: [], spaces: [] } : {};
    queryClient.setQueryData(syncOverviewKey, overview({ ...account, key_slots: slots }));
    queryClient.setQueryData(agentProblemKey, { kind: "include_missing" });
    if (o.launchAtLogin !== undefined) queryClient.setQueryData(launchAtLoginKey, o.launchAtLogin);
    return text(
      renderToStaticMarkup(
        <QueryClientProvider client={queryClient}>
          <KeychainBannersFor dismissed={o.dismissed ?? false} closeToTray={o.closeToTray ?? false} onDismissLaunch={() => {}} onMoveFailures={() => {}} />
        </QueryClientProvider>,
      ),
    );
  };

  it("show the agent's problem only while a key is in SSHelter", () => {
    expect(render([keySlot({ in_vault: true })])).toContain("can't reach its agent");
    expect(render([keySlot()])).not.toContain("can't reach its agent");
  });

  it("count the keys that are files for now", () => {
    expect(render([keySlot({ file_for_now: true }), keySlot({ id: "b".repeat(32), file_for_now: true })])).toContain(
      "2 keys can move into SSHelter",
    );
  });

  it("stay without a sync account: the keys this computer keeps in SSHelter still need the agent, launch at login and Move", () => {
    const t = render([keySlot({ in_account: false, in_vault: true })], { joined: false, launchAtLogin: false });
    expect(t).toContain("can't reach its agent");
    expect(t).toContain("Keys in SSHelter work only while SSHelter is running.");
    expect(render([keySlot({ in_account: false, file_for_now: true })], { joined: false })).toContain("1 key can move into SSHelter");
  });

  it("suggest launch at login until it is on, SSHelter keeps running in the menu bar, or the hint is dismissed", () => {
    const vault = [keySlot({ in_vault: true })];
    expect(render(vault, { launchAtLogin: false })).toContain("Keys in SSHelter work only while SSHelter is running.");
    expect(render(vault, { launchAtLogin: true })).not.toContain("work only while");
    expect(render(vault, { launchAtLogin: false, closeToTray: true })).not.toContain("work only while");
    expect(render(vault, { launchAtLogin: false, dismissed: true })).not.toContain("work only while");
  });
});
