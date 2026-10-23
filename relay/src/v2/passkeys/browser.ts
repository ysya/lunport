import {
  startRegistration,
  startAuthentication,
} from "@simplewebauthn/browser";
const flow = new URLSearchParams(location.search).get("flow") ?? "";
const key = new URLSearchParams(location.hash.slice(1)).get("key") ?? "";
history.replaceState(null, "", location.pathname + location.search);
const message = document.querySelector<HTMLElement>("#message")!;
const buttons = Array.from(
  document.querySelectorAll<HTMLButtonElement>("button[data-kind]"),
);
const list = document.querySelector<HTMLElement>("#credentials")!;
const signIn = document.querySelector<HTMLElement>("#sign-in")!;
const signup = document.querySelector<HTMLFormElement>("#signup")!;
const email = document.querySelector<HTMLInputElement>("#email")!;
const switcher = document.querySelector<HTMLElement>("#switcher")!;
const newAccount = document.querySelector<HTMLButtonElement>('[data-view="signup"]')!;
const pageHeading = document.querySelector<HTMLElement>("h1")!;
let busy = true;
let managing = false;
let managementKey = "";
async function call(path: string, body: object): Promise<any> {
  const response = await fetch("/v1/auth/passkey/" + path, {
    method: "POST",
    credentials: "omit",
    cache: "no-store",
    redirect: "error",
    referrerPolicy: "no-referrer",
    headers: {
      "content-type": "application/json",
      "x-lunport-flow": key,
      ...(managementKey ? { "x-lunport-management": managementKey } : {}),
    },
    body: JSON.stringify({ flow, ...body }),
  });
  if (!response.ok) {
    if (response.status === 409) {
      const result = await response.json().catch(() => null);
      if (result?.error === "account_exists") throw new Error("This email already names an account on this server. Sign in with its passkey or use another email.");
    }
    throw new Error(response.status === 429 ? "Too many requests. Wait a minute, then try again." : "Passkey request failed.");
  }
  return response.json();
}
function setBusy(value: boolean) {
  busy = value;
  document.querySelectorAll<HTMLButtonElement>("button").forEach((b) => {
    b.disabled = value || b.dataset.current === "true";
  });
}
function redirect(value: string) {
  const callback = new URL(value);
  const query = Array.from(callback.searchParams.entries());
  if (
    callback.protocol !== "http:" ||
    callback.hostname !== "127.0.0.1" ||
    !callback.port ||
    callback.pathname !== "/passkey/callback" ||
    callback.username ||
    callback.password ||
    callback.hash ||
    query.length !== 2 ||
    !/^lpkc1\.[0-9a-f]{32}\.[0-9a-f]{64}$/.test(
      callback.searchParams.get("code") ?? "",
    ) ||
    !/^[A-Za-z0-9_-]{32,128}$/.test(callback.searchParams.get("state") ?? "")
  )
    throw new Error("Invalid app callback.");
  message.textContent = "Signed in. Returning to Lunport…";
  location.replace(callback.href);
}
function showManagement(result: any) {
  if (result.management_key !== undefined) {
    if (!/^[0-9a-f]{64}$/.test(result.management_key))
      throw new Error("Invalid management capability.");
    managementKey = result.management_key;
  }
  if (!managementKey) throw new Error("Missing management capability.");
  managing = true;
  signIn.hidden = true; signup.hidden = true; switcher.hidden = true;
  pageHeading.textContent = "Your passkeys";
  buttons.forEach((b) => {
    b.hidden = !["add", "complete"].includes(b.dataset.kind!);
  });
  list.replaceChildren();
  const heading = document.createElement("p");
  heading.textContent = `Account ${result.account} · ${result.credentials.length} passkey(s)`;
  list.append(heading);
  result.credentials.forEach(
    (
      credential: { id: string; current: boolean; backed_up: boolean },
      index: number,
    ) => {
      const row = document.createElement("div");
      const label = document.createElement("p");
      label.textContent = `Passkey ${index + 1} · ${credential.id.slice(0, 12)}${credential.current ? " · used for this sign-in" : ""}${credential.backed_up ? " · backed up by its provider" : ""}`;
      const remove = document.createElement("button");
      remove.textContent = "Remove this passkey";
      remove.dataset.current = String(credential.current);
      remove.disabled = credential.current;
      remove.addEventListener(
        "click",
        () =>
          void run(async () =>
            showManagement(await call("remove", { credential: credential.id })),
          ),
      );
      row.append(label, remove);
      list.append(row);
    },
  );
  message.textContent =
    "Add a backup passkey on another device or security key. Removing a passkey signs out existing account-login sessions. To remove the passkey used here, first sign in with another one.";
}
async function run(action: () => Promise<void>) {
  if (busy) return;
  setBusy(true);
  try {
    await action();
  } catch (error) {
    message.textContent = error instanceof Error && (error.message.startsWith("This email") || error.message.startsWith("Too many")) ? error.message : managing
      ? "The passkey change could not be completed. Try again, or return to Lunport and start a new sign-in."
      : "Sign-in failed or was cancelled. Try again, or return to Lunport to start a new sign-in.";
  } finally {
    setBusy(false);
  }
}
buttons.forEach((button) =>
  button.addEventListener(
    "click",
    () =>
      void run(async () => {
        const kind = button.dataset.kind!;
        if (kind === "complete") {
          redirect((await call("complete", {})).redirect);
          return;
        }
        if (kind === "register" && !signup.reportValidity()) return;
        message.textContent = "Waiting for your passkey…";
        const { options } = await call("options", { kind, ...(kind === "register" ? { email: email.value.trim() } : {}) });
        const response =
          kind === "register" || kind === "add"
            ? await startRegistration({ optionsJSON: options })
            : await startAuthentication({ optionsJSON: options });
        const result = await call("finish", { response });
        if (result.managing) showManagement(result);
        else redirect(result.redirect);
      }),
  ),
);
document.querySelectorAll<HTMLButtonElement>("button[data-view]").forEach((button) => button.addEventListener("click", () => {
  if (busy) return;
  const creating = button.dataset.view === "signup";
  signIn.hidden = creating; signup.hidden = !creating;
  pageHeading.textContent = creating ? "Create your account" : "Sign in to Lunport";
  newAccount.hidden = creating;
  document.querySelector<HTMLButtonElement>('[data-view="login"]')!.hidden = !creating;
  message.textContent = creating ? "Use an email as your account name, then create a passkey." : "Sign in with the passkey for your account.";
  if (creating) email.focus();
}));
signup.addEventListener("submit", (event) => { event.preventDefault(); document.querySelector<HTMLButtonElement>('[data-kind="register"]')!.click(); });
setBusy(true);
if (!/^[0-9a-f]{32}$/.test(flow) || !/^[0-9a-f]{64}$/.test(key))
  message.textContent = "Open sign-in from the Lunport app.";
else
  call("context", {})
    .then((context) => {
      if (context.existing_only) newAccount.hidden = true;
      if (context.account_name) document.querySelector<HTMLElement>("#account-name")!.textContent = context.account_name;
      setBusy(false);
    })
    .catch(() => {
      message.textContent = "This sign-in expired. Return to Lunport.";
    });
