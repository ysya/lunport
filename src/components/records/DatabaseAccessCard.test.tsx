import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import type { ReactElement, ReactNode } from "react";
import { toast } from "sonner";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AlertDialog, AlertDialogAction, AlertDialogCancel } from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { DISABLED, buttonTag, elementsOf, text, textIn } from "@/components/keychain/test-markup";
import { copyText } from "@/lib/clipboard";
import { tauriInvoke } from "@/lib/ipc";
import { renderHook } from "@/lib/test-ipc";
import {
  UNKNOWN_IAM_USER,
  connectionUrl,
  databasePort,
  databasesQuery,
  hasConnectionDetails,
  iamUserFor,
  writableLeft,
  writableSecondsLeft,
  type DatabasePhase,
  type DatabaseView,
  type SavedDatabase,
} from "@/lib/databases";
import { DatabaseAccessCard, DatabaseAccessView, beginUnlock, copyPassword, rotatePassword, type DatabaseAccessViewProps } from "./DatabaseAccessCard";

vi.mock("@/lib/ipc", () => ({ tauriInvoke: vi.fn() }));
vi.mock("@/lib/clipboard", () => ({ copyText: vi.fn() }));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

/*
 * There is no DOM here, so the card is drawn two ways: as static markup (its words and the state of its controls), and as the element
 * tree of its hook-free view, whose callbacks the tests press. The card that keeps the state is read as far as a server render goes: the
 * view it draws and the actions it hands that view, which the tests run against a stubbed backend and clipboard.
 */

const SECOND = 1000;
const MINUTE = 60_000;
const AT = new Date(2027, 0, 15, 10, 0).getTime(); // 10:00 on this computer's clock
const ID = "00000000000000a1";
const ACCOUNT = "frank@example.com";
const SERVICE_ACCOUNT = "orders-sa@acme-prod-123456.iam.gserviceaccount.com";
/** What the keychain holds and what rotating it makes: synthetic, and nothing a page may draw, cache or say. */
const PASSWORD = "c3ludGhldGljLXBvcnQtcGFzc3dvcmQ";
const NEW_PASSWORD = "bmV3LXN5bnRoZXRpYy1wb3J0LXBhc3N3b3Jk";
const ORDERS_URL = "postgresql://frank%40example.com@127.0.0.1:6543/postgres";

const ORDERS: SavedDatabase = {
  id: ID,
  name: "Orders",
  engine: "postgres",
  project: "acme-prod-123456",
  region: "asia-east1",
  instance: "orders-pg",
  environment: "prod",
  network: "public",
  account: ACCOUNT,
  default_database: "postgres",
  pam: null,
  local_port: 6543,
};
const live = (phase: DatabasePhase, patch: Partial<DatabaseView["live"]> = {}): DatabaseView["live"] => ({
  phase,
  port: phase === "stopped" || phase === "error" ? null : 6543,
  connections: 0,
  writable_until_ms: null,
  error: null,
  ...patch,
});
/** A saved database as the list shows it: a prod database that runs on its saved port, with writes locked. */
function view(patch: Partial<DatabaseView> = {}, database: Partial<SavedDatabase> = {}): DatabaseView {
  return { database: { ...ORDERS, ...database }, live: live("running"), synced: true, blocked: false, removed: false, ...patch };
}
/** A running prod database whose writes lock again `left` milliseconds after 10:00. */
const writable = (left: number) => view({ live: live("running", { writable_until_ms: AT + left }) });

const invoke = vi.mocked(tauriInvoke);
const copy = vi.mocked(copyText);
const calls = () => invoke.mock.calls;
/** The backend answers each command with its reply, or fails with it when it is an error; a command it was not told about fails. */
function backend(replies: Record<string, unknown>) {
  invoke.mockImplementation(async (command: string) => {
    if (!(command in replies)) throw new Error(`unexpected command ${command}`);
    const reply = replies[command];
    if (reply instanceof Error) throw reply;
    return reply;
  });
}

beforeEach(() => {
  vi.spyOn(Date, "now").mockReturnValue(AT);
  invoke.mockReset();
  copy.mockReset();
  vi.mocked(toast.success).mockReset();
  vi.mocked(toast.error).mockReset();
});
afterEach(() => vi.restoreAllMocks());

type Shown = Partial<Omit<DatabaseAccessViewProps, "actions">>;
/** The view over `shown` with a spy for every action: its markup, and its element tree for pressing the controls. */
function card(shown: DatabaseView = view(), props: Shown = {}) {
  const actions = {
    copyUrl: vi.fn(),
    copyPassword: vi.fn(),
    ask: vi.fn(),
    rotate: vi.fn(),
    unlock: vi.fn(),
    confirmUnlock: vi.fn(),
    lock: vi.fn(),
    reconnect: vi.fn(),
  };
  const all: DatabaseAccessViewProps = { view: shown, url: ORDERS_URL, now: AT, pending: null, error: null, asking: null, actions, ...props };
  const tree = () => DatabaseAccessView(all);
  return { actions, tree, html: () => renderToStaticMarkup(tree()) };
}

/** The card's own button (a dialog's are not) that says `label`. */
function button(tree: ReactNode, label: string): ReactElement {
  const found = elementsOf(tree, Button).find((element) => textIn(element) === label);
  if (!found) throw new Error(`no ${label} button`);
  return found;
}
const press = (element: ReactElement) => (element.props as unknown as { onClick: () => void }).onClick();
/** The alert dialog whose words include `words`. */
function dialog(tree: ReactNode, words: string): ReactElement {
  const found = elementsOf(tree, AlertDialog).find((element) => textIn(element).includes(words));
  if (!found) throw new Error(`no dialog about ${words}`);
  return found;
}
const dialogProps = (element: ReactElement) => element.props as unknown as { open: boolean; onOpenChange: (open: boolean) => void };

/** The card the page keeps, as far as a server render gets: the view it draws and the actions it gave that view. */
function kept(shown: DatabaseView = view(), client = new QueryClient()) {
  const tree = renderHook(client, () => DatabaseAccessCard({ view: shown, iamUser: ACCOUNT }));
  return { client, props: tree.props as DatabaseAccessViewProps };
}

describe("the address and the time a card shows", () => {
  it("the_connection_url_encodes_the_iam_user", () => {
    expect(connectionUrl(ORDERS, ACCOUNT)).toBe(ORDERS_URL);
    // A service account's user keeps its dots, and what a URL would read otherwise is encoded in the user and in the database.
    expect(connectionUrl(ORDERS, "orders-sa@acme-prod-123456.iam")).toBe("postgresql://orders-sa%40acme-prod-123456.iam@127.0.0.1:6543/postgres");
    expect(connectionUrl({ ...ORDERS, default_database: "orders db/2" }, "ops@example.com")).toBe("postgresql://ops%40example.com@127.0.0.1:6543/orders%20db%2F2");
    // A name's invisible characters never reach the address as themselves.
    expect(connectionUrl({ ...ORDERS, default_database: "orders\u202e" }, ACCOUNT)).toBe("postgresql://frank%40example.com@127.0.0.1:6543/orders%E2%80%AE");
    // It carries no password: the address is safe to paste anywhere.
    const parsed = new globalThis.URL(connectionUrl(ORDERS, ACCOUNT));
    expect([parsed.username, parsed.password, parsed.host, parsed.pathname]).toEqual(["frank%40example.com", "", "127.0.0.1:6543", "/postgres"]);
  });

  it("writable_time_left_is_shown_as_minutes_and_seconds", () => {
    const until = AT + 15 * MINUTE;
    expect(writableLeft(until, AT)).toBe("15:00");
    expect(writableLeft(until, AT + SECOND)).toBe("14:59");
    expect(writableLeft(AT + 61 * SECOND, AT)).toBe("01:01");
    expect(writableLeft(AT + 59 * SECOND, AT)).toBe("00:59");
    expect(writableLeft(AT + 5 * SECOND, AT)).toBe("00:05");
    // A part of a second still counts as the second: the last one reads 00:01, never 00:00 while writes are on.
    expect(writableLeft(AT + 1, AT)).toBe("00:01");
    expect(writableLeft(AT + 59 * SECOND + 1, AT)).toBe("01:00");
    expect(writableSecondsLeft(AT + 42 * SECOND, AT)).toBe(42);
    expect(writableSecondsLeft(AT + 41 * SECOND + 1, AT)).toBe(42);
  });

  it("a_window_that_never_opened_or_has_ended_has_no_time_left", () => {
    expect(writableLeft(null, AT)).toBeNull();
    expect(writableLeft(AT, AT)).toBeNull();
    expect(writableLeft(AT - 1, AT)).toBeNull();
    expect(writableLeft(AT - 5 * MINUTE, AT)).toBeNull();
    expect(writableLeft(Number.NaN, AT)).toBeNull();
    expect(writableSecondsLeft(null, AT)).toBeNull();
    expect(writableSecondsLeft(AT, AT)).toBeNull();
  });

  it("names_the_database_user_as_the_backend_does", () => {
    // The database's own account, else the one gcloud is signed in as.
    expect(iamUserFor(ACCOUNT, "ops@example.com")).toBe(ACCOUNT);
    expect(iamUserFor(null, "ops@example.com")).toBe("ops@example.com");
    // A service account signs in without `.gserviceaccount.com`, and only that suffix at the very end goes.
    expect(iamUserFor(SERVICE_ACCOUNT, null)).toBe("orders-sa@acme-prod-123456.iam");
    expect(iamUserFor(null, SERVICE_ACCOUNT)).toBe("orders-sa@acme-prod-123456.iam");
    expect(iamUserFor("a.gserviceaccount.com@example.com", null)).toBe("a.gserviceaccount.com@example.com");
    // Neither known: a placeholder that reads as one, and the address still holds together.
    expect(iamUserFor(null, null)).toBe(UNKNOWN_IAM_USER);
    expect(UNKNOWN_IAM_USER).toBe("your-google-account");
    expect(connectionUrl(ORDERS, UNKNOWN_IAM_USER)).toBe("postgresql://your-google-account@127.0.0.1:6543/postgres");
  });

  it("offers_details_for_the_port_that_runs_else_the_one_saved_and_never_for_a_removed_record", () => {
    expect(databasePort(view())).toBe(6543);
    // The port that runs is the one apps reach, whatever the record holds now; a port that failed falls back to the saved one.
    expect(databasePort(view({ live: live("running", { port: 6544 }) }))).toBe(6544);
    expect(databasePort(view({ live: live("error", { error: "Port 6543 is already in use on this computer." }) }))).toBe(6543);
    expect(databasePort(view({ live: live("stopped") }, { local_port: null }))).toBeNull();
    expect(hasConnectionDetails(view({ live: live("stopped") }))).toBe(true);
    expect(hasConnectionDetails(view({ live: live("stopped") }, { local_port: null }))).toBe(false);
    // A database that runs although another device cleared its port still has the port that runs.
    expect(hasConnectionDetails(view({ live: live("running") }, { local_port: null }))).toBe(true);
    // A record that is gone is listed only to be stopped.
    expect(hasConnectionDetails(view({ removed: true, blocked: true }))).toBe(false);
  });
});

describe("the card", () => {
  it("shows_the_address_and_the_password_actions_without_the_password", () => {
    const html = card().html();
    const shown = text(html);
    expect(html).toContain('aria-label="Connection details for Orders"');
    expect(shown).toContain(ORDERS_URL);
    for (const label of ["Copy URL", "Copy password", "Rotate password"]) expect(buttonTag(html, label), label).not.toContain(DISABLED);
    // The password is never drawn; the card only says where it is kept.
    expect(shown).toContain("It stays in the keychain and is never shown.");
    expect(html).not.toContain("<input");
    expect(html).not.toContain(PASSWORD);
  });

  it("presses_copy_url_copy_password_and_rotate_through_the_actions", () => {
    const { actions, tree } = card();
    press(button(tree(), "Copy URL"));
    expect(actions.copyUrl).toHaveBeenCalledTimes(1);
    press(button(tree(), "Copy password"));
    expect(actions.copyPassword).toHaveBeenCalledTimes(1);
    // Rotating asks first: the button opens the question, it does not rotate.
    press(button(tree(), "Rotate password"));
    expect(actions.ask).toHaveBeenCalledExactlyOnceWith("rotate");
    expect(actions.rotate).not.toHaveBeenCalled();
  });

  it("a_dev_database_has_no_lock_button", () => {
    for (const environment of ["dev", "staging"] as const) {
      // Only prod is locked, so no lock, no time and no reconnect are drawn, whatever the list says of a window.
      const html = card(view({ live: live("running", { writable_until_ms: AT + MINUTE }) }, { environment })).html();
      expect(text(html), environment).not.toMatch(/Locked|Writes on|Reconnect now|Writes lock again/);
      expect(html, environment).not.toMatch(/lucide-lock/);
      // The rest of the card is there.
      expect(text(html), environment).toContain(ORDERS_URL);
      expect(buttonTag(html, "Copy password"), environment).not.toContain(DISABLED);
    }
    expect(text(card().html())).toContain("Locked");
  });

  it("a_prod_database_that_runs_offers_to_unlock_writes", () => {
    const { actions, html, tree } = card();
    const markup = html();
    expect(buttonTag(markup, "Locked")).not.toContain(DISABLED);
    expect(markup).toMatch(/lucide-lock(?![-\w])/);
    expect(markup).not.toMatch(/lucide-lock-open/);
    expect(text(markup)).not.toMatch(/Reconnect now|Writes on|Writes lock again|Start the database before you unlock writes\./);
    press(button(tree(), "Locked"));
    expect(actions.unlock).toHaveBeenCalledTimes(1);
    expect(actions.lock).not.toHaveBeenCalled();
  });

  it("a_prod_database_that_does_not_run_cannot_be_unlocked_and_says_why", () => {
    for (const phase of ["stopped", "starting", "stopping", "error"] as const) {
      const html = card(view({ live: live(phase) })).html();
      expect(buttonTag(html, "Locked"), phase).toContain(DISABLED);
      expect(text(html), phase).toContain("Start the database before you unlock writes.");
    }
  });

  it("writes_on_shows_the_time_left_in_the_destructive_style_with_lock_and_reconnect", () => {
    const { actions, html, tree } = card(writable(15 * MINUTE - SECOND));
    const markup = html();
    expect(buttonTag(markup, "Writes on · 14:59")).toContain('data-variant="destructive"');
    expect(buttonTag(markup, "Writes on · 14:59")).not.toContain(DISABLED);
    expect(markup).toMatch(/lucide-lock-open/);
    expect(markup).not.toMatch(/lucide-lock(?![-\w])/);
    expect(text(markup)).not.toContain("Locked");
    expect(buttonTag(markup, "Reconnect now")).not.toContain(DISABLED);
    // Over a minute there is nothing more to warn of.
    expect(text(markup)).not.toContain("Writes lock again");
    press(button(tree(), "Writes on · 14:59"));
    expect(actions.lock).toHaveBeenCalledTimes(1);
    press(button(tree(), "Reconnect now"));
    expect(actions.reconnect).toHaveBeenCalledTimes(1);
    expect(actions.unlock).not.toHaveBeenCalled();
  });

  it("says_when_writes_lock_again_once_less_than_a_minute_is_left", () => {
    expect(text(card(writable(59 * SECOND)).html())).toContain("Writes on · 00:59");
    expect(text(card(writable(59 * SECOND)).html())).toContain("Writes lock again in 59 s.");
    expect(text(card(writable(SECOND)).html())).toContain("Writes lock again in 1 s.");
    // A minute exactly, and a part of a second over 59, still read as a minute.
    expect(text(card(writable(MINUTE)).html())).not.toContain("Writes lock again");
    expect(text(card(writable(59 * SECOND + 1)).html())).toContain("Writes on · 01:00");
    expect(text(card(writable(59 * SECOND + 1)).html())).not.toContain("Writes lock again");
  });

  it("reads_a_window_that_has_ended_as_locked_before_the_list_is_read_again", () => {
    // The list is read every 1.5 seconds, so it may still hold a window that is over; the card goes by the clock.
    const html = card(writable(-SECOND)).html();
    expect(buttonTag(html, "Locked")).not.toContain(DISABLED);
    expect(text(html)).not.toMatch(/Writes on|Reconnect now|Writes lock again/);
    expect(card(writable(0)).html()).toContain(">Locked<");
  });

  it("counts_down_with_the_clock_of_the_card_that_keeps_state", () => {
    const html = (shown: DatabaseView) => renderToStaticMarkup(<QueryClientProvider client={new QueryClient()}><DatabaseAccessCard view={shown} iamUser={ACCOUNT} /></QueryClientProvider>);
    expect(text(html(writable(15 * MINUTE - SECOND)))).toContain("Writes on · 14:59");
    expect(text(html(writable(30 * SECOND)))).toContain("Writes lock again in 30 s.");
    expect(text(html(view()))).toContain(ORDERS_URL);
    // A database that runs on another port than the record holds is reached on the port that runs.
    expect(text(html(view({ live: live("running", { port: 6544 }) })))).toContain("postgresql://frank%40example.com@127.0.0.1:6544/postgres");
  });

  it("holds_every_control_while_a_change_is_under_way", () => {
    for (const pending of ["url", "password", "rotate", "unlock", "lock", "reconnect"] as const) {
      const html = card(writable(10 * MINUTE), { pending }).html();
      for (const label of ["Copy URL", "Copy password", "Rotate password", "Writes on · 10:00", "Reconnect now"]) expect(buttonTag(html, label), `${pending}: ${label}`).toContain(DISABLED);
    }
    // The control that waits shows it: the unlock may wait for Touch ID.
    expect(card(view(), { pending: "unlock" }).html()).toContain("animate-spin");
    expect(buttonTag(card(view(), { pending: "unlock" }).html(), "Locked")).toContain(DISABLED);
    expect(card(view(), { pending: null }).html()).not.toContain("animate-spin");
  });

  it("shows_the_sentence_a_change_failed_with", () => {
    const sentence = "Writes stay locked.";
    const html = card(view(), { error: sentence }).html();
    expect(html).toMatch(/<p role="alert"[^>]*>Writes stay locked\.<\/p>/);
    expect(card().html()).not.toContain('role="alert"');
  });

  it("shows_a_names_hidden_characters_as_codes", () => {
    const html = card(view({}, { name: "Ord\u202eers" }), { asking: "rotate" }).html();
    expect(html).toContain('aria-label="Connection details for Ord⟨U+202E⟩ers"');
    expect(html).not.toContain("\u202e");
    expect(textIn(dialog(card(view({}, { name: "Ord\u202eers" })).tree(), "Rotate"))).toContain("Rotate the password of Ord⟨U+202E⟩ers?");
  });
});

describe("the questions the card asks first", () => {
  it("rotating_the_password_asks_with_the_words_that_say_what_it_means", () => {
    const { actions, tree } = card(view(), { asking: "rotate" });
    const rotate = dialog(tree(), "Rotate");
    expect(dialogProps(rotate).open).toBe(true);
    expect(textIn(rotate)).toContain("Rotate the password of Orders?");
    expect(textIn(rotate)).toContain("New connections need the new password. Open connections keep running.");
    // The other question stays shut.
    expect(dialogProps(dialog(tree(), "Unlock writes on")).open).toBe(false);
    // Confirming rotates; cancelling or dismissing only closes the question.
    press(elementsOf(rotate, AlertDialogAction)[0]);
    expect(actions.rotate).toHaveBeenCalledTimes(1);
    expect(textIn(elementsOf(rotate, AlertDialogAction)[0])).toBe("Rotate password");
    expect(textIn(elementsOf(rotate, AlertDialogCancel)[0])).toBe("Cancel");
    dialogProps(rotate).onOpenChange(false);
    expect(actions.ask).toHaveBeenCalledExactlyOnceWith(null);
  });

  it("unlocking_in_the_page_asks_with_the_words_that_say_how_long", () => {
    const { actions, tree } = card(view(), { asking: "unlock" });
    const unlock = dialog(tree(), "Unlock writes on");
    expect(dialogProps(unlock).open).toBe(true);
    expect(textIn(unlock)).toContain("Unlock writes on Orders?");
    expect(textIn(unlock)).toContain("Writes stay on for 15 minutes or until you lock again.");
    expect(dialogProps(dialog(tree(), "Rotate")).open).toBe(false);
    press(elementsOf(unlock, AlertDialogAction)[0]);
    expect(actions.confirmUnlock).toHaveBeenCalledTimes(1);
    expect(actions.unlock).not.toHaveBeenCalled();
    dialogProps(unlock).onOpenChange(false);
    expect(actions.ask).toHaveBeenCalledExactlyOnceWith(null);
  });

  it("neither_question_is_open_until_it_is_asked", () => {
    const { tree } = card();
    expect(dialogProps(dialog(tree(), "Rotate")).open).toBe(false);
    expect(dialogProps(dialog(tree(), "Unlock writes on")).open).toBe(false);
  });
});

describe("what the controls do", () => {
  it("copy_password_puts_the_password_on_the_clipboard_and_keeps_it_nowhere_else", async () => {
    backend({ databases_port_password: PASSWORD });
    const { client, props } = kept();
    await props.actions.copyPassword();
    expect(copy).toHaveBeenCalledExactlyOnceWith(PASSWORD);
    expect(calls()).toEqual([["databases_port_password", { id: ID }]]);
    expect(vi.mocked(toast.success)).toHaveBeenCalledExactlyOnceWith("Password copied.");
    // Not in the query cache, not in a mutation (both keep their results), not in the card, and not in anything it said.
    expect(JSON.stringify(client.getQueryCache().getAll().map((query) => query.state.data))).not.toContain(PASSWORD);
    expect(client.getMutationCache().getAll()).toHaveLength(0);
    const html = renderToStaticMarkup(<QueryClientProvider client={client}><DatabaseAccessCard view={view()} iamUser={ACCOUNT} /></QueryClientProvider>);
    expect(html).not.toContain(PASSWORD);
    expect(JSON.stringify(vi.mocked(toast.success).mock.calls)).not.toContain(PASSWORD);
  });

  it("runs_one_change_at_a_time", async () => {
    // The keychain takes its time; a second press meanwhile is not queued, and does not reach the backend or the clipboard.
    let release!: () => void;
    invoke.mockImplementation(async (command: string) => {
      if (command !== "databases_port_password") throw new Error(`unexpected command ${command}`);
      await new Promise<void>((resolve) => { release = resolve; });
      return PASSWORD;
    });
    const { props } = kept();
    const first = props.actions.copyPassword();
    await props.actions.copyUrl();
    await props.actions.copyPassword();
    await props.actions.lock();
    expect(calls()).toEqual([["databases_port_password", { id: ID }]]);
    expect(copy).not.toHaveBeenCalled();
    release();
    await first;
    expect(copy).toHaveBeenCalledExactlyOnceWith(PASSWORD);
    // Once it is done the next press goes through.
    await props.actions.copyUrl();
    expect(copy).toHaveBeenLastCalledWith(ORDERS_URL);
  });

  it("asks_for_no_password_until_a_button_is_pressed", () => {
    backend({});
    kept();
    renderToStaticMarkup(card().tree());
    expect(calls()).toEqual([]);
    expect(copy).not.toHaveBeenCalled();
  });

  it("a_password_that_cannot_be_read_or_copied_fails_with_a_sentence_that_leaves_it_out", async () => {
    const keychain = "The keychain did not answer. Unlock it and try again.";
    backend({ databases_port_password: new Error(keychain) });
    await expect(copyPassword(ID)).rejects.toThrow(keychain);
    expect(copy).not.toHaveBeenCalled();
    backend({ databases_port_password: PASSWORD });
    // The clipboard's own words may hold anything; the card's are fixed.
    copy.mockRejectedValueOnce(new Error(`plugin failed on ${PASSWORD}`));
    const failure = await copyPassword(ID).catch((error: unknown) => error);
    expect((failure as Error).message).toBe("Could not copy to the clipboard.");
    expect(vi.mocked(toast.success)).not.toHaveBeenCalled();
  });

  it("copy_url_puts_the_address_on_the_clipboard", async () => {
    backend({});
    const { props } = kept();
    await props.actions.copyUrl();
    expect(copy).toHaveBeenCalledExactlyOnceWith(ORDERS_URL);
    expect(vi.mocked(toast.success)).toHaveBeenCalledExactlyOnceWith("URL copied.");
    expect(calls()).toEqual([]);
    // An address with no account known still copies.
    const unknown = renderHook(new QueryClient(), () => DatabaseAccessCard({ view: view(), iamUser: UNKNOWN_IAM_USER })).props as DatabaseAccessViewProps;
    expect(unknown.url).toBe("postgresql://your-google-account@127.0.0.1:6543/postgres");
    await unknown.actions.copyUrl();
    expect(copy).toHaveBeenLastCalledWith("postgresql://your-google-account@127.0.0.1:6543/postgres");
  });

  it("rotating_copies_the_new_password_and_says_so", async () => {
    backend({ databases_rotate_port_password: NEW_PASSWORD });
    const { client, props } = kept();
    await props.actions.rotate();
    expect(calls()).toEqual([["databases_rotate_port_password", { id: ID }]]);
    expect(copy).toHaveBeenCalledExactlyOnceWith(NEW_PASSWORD);
    expect(vi.mocked(toast.success)).toHaveBeenCalledExactlyOnceWith("New password copied.");
    expect(JSON.stringify(client.getQueryCache().getAll().map((query) => query.state.data))).not.toContain(NEW_PASSWORD);
    expect(client.getMutationCache().getAll()).toHaveLength(0);
    expect(JSON.stringify(vi.mocked(toast.success).mock.calls)).not.toContain(NEW_PASSWORD);
  });

  it("a_rotated_password_that_cannot_be_copied_says_to_copy_it_again", async () => {
    backend({ databases_rotate_port_password: NEW_PASSWORD });
    copy.mockRejectedValueOnce(new Error(`plugin failed on ${NEW_PASSWORD}`));
    const failure = (await rotatePassword(ID).catch((error: unknown) => error)) as Error;
    expect(failure.message).toBe("The password was rotated, but it could not be copied. Use Copy password.");
    expect(failure.message).not.toContain(NEW_PASSWORD);
    // The card does not claim the copy when it failed.
    copy.mockRejectedValueOnce(new Error("clipboard unavailable"));
    await kept().props.actions.rotate();
    expect(vi.mocked(toast.success)).not.toHaveBeenCalled();
    // A rotation the backend refused copies nothing.
    backend({ databases_rotate_port_password: new Error("The keychain did not answer. Unlock it and try again.") });
    copy.mockClear();
    await expect(rotatePassword(ID)).rejects.toThrow("The keychain did not answer. Unlock it and try again.");
    expect(copy).not.toHaveBeenCalled();
  });

  it("the_system_method_unlocks_without_an_in_app_dialog", async () => {
    backend({ os_unlock_method: "system", databases_unlock_writes: AT + 15 * MINUTE });
    const askInApp = vi.fn();
    await beginUnlock(ID, askInApp);
    // The system asks for Touch ID or the Mac's password itself: the page's own yes is not given, and not asked for.
    expect(askInApp).not.toHaveBeenCalled();
    expect(calls()).toEqual([["os_unlock_method"], ["databases_unlock_writes", { id: ID, confirmedInApp: false }]]);
    // The same through the card.
    invoke.mockClear();
    await kept().props.actions.unlock();
    expect(calls()).toEqual([["os_unlock_method"], ["databases_unlock_writes", { id: ID, confirmedInApp: false }]]);
  });

  it("the_dialog_method_asks_in_the_page_first_and_unlocks_only_once_confirmed", async () => {
    backend({ os_unlock_method: "dialog", databases_unlock_writes: AT + 15 * MINUTE });
    const askInApp = vi.fn();
    await beginUnlock(ID, askInApp);
    expect(askInApp).toHaveBeenCalledTimes(1);
    // Nothing is unlocked by asking.
    expect(calls()).toEqual([["os_unlock_method"]]);
    invoke.mockClear();
    const { props } = kept();
    await props.actions.unlock();
    expect(calls()).toEqual([["os_unlock_method"]]);
    // Its confirmation unlocks, with the page's yes.
    invoke.mockClear();
    await props.actions.confirmUnlock();
    expect(calls()).toEqual([["databases_unlock_writes", { id: ID, confirmedInApp: true }]]);
  });

  it("a_refused_unlock_keeps_the_backends_sentence", async () => {
    backend({ os_unlock_method: "system", databases_unlock_writes: new Error("Writes stay locked.") });
    await expect(beginUnlock(ID, vi.fn())).rejects.toThrow("Writes stay locked.");
    backend({ os_unlock_method: new Error("Lunport could not tell how to confirm.") });
    await expect(beginUnlock(ID, vi.fn())).rejects.toThrow("Lunport could not tell how to confirm.");
  });

  it("locks_again_and_reads_the_list_again_so_the_card_follows_at_once", async () => {
    backend({ databases_lock_writes: null, databases_list: [writable(10 * MINUTE)] });
    const client = new QueryClient();
    await client.fetchQuery(databasesQuery);
    invoke.mockClear();
    await kept(writable(10 * MINUTE), client).props.actions.lock();
    expect(calls()).toEqual([["databases_lock_writes", { id: ID }], ["databases_list"]]);
  });

  it("reconnect_now_says_how_many_idle_connections_it_closed", async () => {
    const say = vi.mocked(toast.success);
    backend({ databases_reconnect_locked: 2 });
    await kept(writable(10 * MINUTE)).props.actions.reconnect();
    expect(calls()).toEqual([["databases_reconnect_locked", { id: ID }]]);
    expect(say).toHaveBeenLastCalledWith("Closed 2 idle read-only connections.");
    backend({ databases_reconnect_locked: 1 });
    await kept(writable(10 * MINUTE)).props.actions.reconnect();
    expect(say).toHaveBeenLastCalledWith("Closed 1 idle read-only connection.");
    backend({ databases_reconnect_locked: 0 });
    await kept(writable(10 * MINUTE)).props.actions.reconnect();
    expect(say).toHaveBeenLastCalledWith("No idle read-only connections to close.");
  });
});
