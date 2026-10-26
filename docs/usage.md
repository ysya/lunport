# Using Lunport

Lunport is your SSH workspace for hosts, keys and Groups, formerly named SSHelter. Download the current Stable from [Releases](https://github.com/ysya/lunport/releases/latest). Existing SSHelter installations retain their data, credentials and command-line integrations through the rename.

## Your host library

A new installation opens a Records workspace without requiring an SSH config or an existing data directory. The first save creates the local library. Add a host with its hostname, username and port, or use **Import** to review entries from OpenSSH files. Import copies the selected data and preserves the sources.

Groups provide shared connection defaults and can contain other Groups. Host overrides remain explicit. The full-height sidebar is reserved for Library navigation; use tags, Recent and Needs attention to find connections, or open the command palette with **⌘K / Ctrl+K**. Use the **⋯** menu beside **New host** for **Import hosts** or **New group**. **Settings** opens from the upper-right toolbar or **⌘, / Ctrl+,** and provides search across the preferences available in your workspace.

Host and key details open over the right side of the workspace, keeping the catalog width and scroll position unchanged. Drag the detail divider to resize it on wide windows. **Escape** or **Close details** returns to the selected item; narrow windows show details across the workspace without rebuilding the collection.

Drag a Group row within its current level to reorder it. Its **⋯** menu also offers **Move up / Move down**; with the Group focused, use **Alt+↑ / Alt+↓** (Option on macOS). **Groups → ⋯ → Sort groups by name** restores name sorting. Sorting preserves nesting and connection defaults, and newly added Groups follow manually ordered peers. With an account, order syncs to your computers; concurrent offline reorders converge through the existing sync rules. Older 1.2.0 clients continue using name sorting while retaining the additional encrypted metadata.

## Appearance and color themes

Open **Settings → Appearance → Color theme** to choose Lunport, Nord, Dracula, Catppuccin, Tokyo Night or Solarized. The miniature previews follow the selected **System / Light / Dark** mode. Selections apply immediately and are remembered on this installation; the original Lunport palette remains the default. Settings search also finds themes by name.

Each preset covers the workspace, sidebar, cards, dialogs and status colors. Dracula uses Alucard in light mode; Catppuccin uses Latte/Mocha, and Tokyo Night uses Day/Night. Surface roles and status colors are adapted for interface text contrast. **Theme credits** includes palette sources and licenses. External terminals such as iTerm2 and Terminal keep their own color preferences.

## Server identities and connection checks

Open **Settings → Connections → Known hosts**, or choose **Manage identity…** in a host's connection details. **Lunport identities** shows the saved address, key type, fingerprint, verification time and originating device. You can copy a fingerprint, verify it again, or forget it after reviewing the confirmation. Forgetting a shared host's identity syncs to your other computers; its host settings and login keys remain saved. The next connection requires a new trust decision.

The **OpenSSH known_hosts** tab manages this computer's `~/.ssh/known_hosts`. Search by host, fingerprint or key type; hashed names remain hidden. Removing an entry first saves a backup and checks that the complete displayed line is still current. Changes in this tab apply to OpenSSH's local file. Lunport's SSH client uses the separate identities shown in the first tab.

In a host's connection details, **Check port** performs a manual TCP reachability check with a three-second limit and displays the result, connection time and check time. A reachable port confirms TCP connectivity; server identity and login are verified separately. Timeout, refused connection and name-resolution errors describe that check rather than declaring a host offline. For jump-host routes, use **Verify fingerprint** to check through the configured route; that flow may request jump-host credentials. A host that connects through Google Cloud IAP has **Check through IAP** in its place, described under [Google Cloud IAP and OS Login](#google-cloud-iap-and-os-login).

## SSH tunnels

Open **Tunnels** in the Records workspace and choose **New tunnel**. Select a saved SSH host and a forwarding type:

- **Local:** listen on this computer and reach a destination from the SSH host, such as `127.0.0.1:15432 → db.internal:5432`.
- **Remote:** listen on the SSH host and reach a destination from this computer. The SSH server must allow remote forwarding; its `GatewayPorts` policy controls non-loopback exposure.
- **SOCKS5:** point a browser or tool at the local listening address. TCP CONNECT is supported, including destination name resolution through the SSH host. UDP and SOCKS authentication are not supported.

Listening addresses are IPv4 or IPv6 addresses. The default `127.0.0.1` is loopback; choose port **0** to allocate an available listening port. The actual port appears after starting. Each tunnel uses the host's existing keys, passwords, server fingerprint checks and jump hosts, without opening a shell.

Rules sync as encrypted account metadata. **Running state stays on each device:** receiving a rule never starts it, and changes elsewhere do not reconfigure an existing connection. Stop and start to apply an updated rule. A rule deleted elsewhere stays visible until its local connection is stopped. On leaving sync, rules for preserved hosts become local rules.

Tunnels keep running while switching pages, closing terminal tabs or closing the window. Quitting Lunport, reloading it or installing an update ends them. Reconnection is manual. Up to 16 tunnels can run on one device, each with up to 64 simultaneous TCP connections; up to 256 definitions can be saved.

## Connect in Lunport or an external terminal

The in-app terminal is available first on the **Beta** update channel in **Settings → Updates**.

Choose **Lunport (in app)** in **Settings → Connections** for integrated SSH tabs, or select an external terminal. The app terminal is the default for everyone: an external terminal chosen in an older version is set back to it once, and a choice made since then is kept. The Records connection menu changes the same saved preference. Legacy hosts can override it individually. Lunport's built-in SSH engine handles authentication and server identity in either destination. New or changed server fingerprints require a decision in Lunport; compare them against a trusted source before accepting them.

Double-click a ready host or use Quick connect. Each connection opens a separate session tab. In the Records workspace, Library and session tabs share the title bar. Switching to Library, Settings or another tab keeps SSH connected. Tab icons distinguish connecting, failed and ended sessions; the bottom bar shows the active connection's address and status. Closing a running tab asks for confirmation; a completed tab closes immediately. **Terminal options** at the bottom right contains connection details, text-size controls, Copy selection, Reconnect and Disconnect. Closing the app window keeps active sessions running, while quitting, reloading the workspace or installing an update ends them.

An established connection that drops unexpectedly reconnects automatically in the same tab, retaining earlier output. Retries wait 2, 5, 10, 20 and 30 seconds, then pause; an operating-system network-restored event can resume them. Choose **Retry now** or press Enter with terminal input focused to reconnect immediately, or choose **Stop retrying**. The **Automatically reconnect** toggle in Terminal options applies to that tab. Normal shell exits and manual disconnects stay ended. A first failed connection, rejected server identity, cancelled login or authentication failure waits for manual action.

Use **Reconnect** in Terminal options or the bottom bar to replace a live connection; Lunport asks before ending it. Ended sessions show a visible Reconnect button and also accept Enter. Reconnecting opens a new shell and keeps earlier output available for search; queued keystrokes are discarded. Credentials and server identities still use the normal authentication and verification flow. Use a remote tool such as tmux when commands must survive disconnection.

In **Settings → Connections → In-app terminal**, choose the terminal text size and cursor preference. App color themes apply to the terminal; dark presets include their ANSI colors. Text size and theme changes apply to open sessions without reconnecting. **⌘F / Ctrl+F** searches retained output in a floating panel without resizing the remote terminal; Enter / Shift+Enter selects the next / previous match, and Escape closes Find and returns to terminal input. **Ctrl+Tab / Ctrl+Shift+Tab** switches workspace tabs. When a tab has keyboard focus, Left / Right and Home / End move between tab labels; Enter or Space activates one. **⌘ / Ctrl +**, **−** and **0** adjust or reset terminal text size. Quick connect is **⌘K** on macOS; inside a terminal on other platforms use **Ctrl+Shift+K** so Ctrl+K remains available to the shell. Use normal copy/paste shortcuts or **Terminal options → Copy selection**. Remote clipboard writes are disabled.

Up to eight session tabs can be open. Retained history and queued data are bounded; if the terminal cannot consume output, it reports the interruption rather than retrying keystrokes.

Use a key from the local vault, a saved password or an interactive authentication prompt. Passwords, key passphrases and two-factor codes appear in Lunport’s **SSH authentication** window, with the requesting host and username. Answers apply to the current connection; cancelling or closing the terminal abandons its questions. Shell input continues in your preferred terminal.

In the Records host editor, choose **Authentication → Password**. Leave the password unset to enter it in Lunport when connecting, or choose **Save password**, enter it and save the host. Saved SSH passwords use protected local credential storage and join end-to-end encrypted library sync when enabled. The editor shows saved status without reading or revealing the saved password; **Replace password** and **Remove saved password** take effect when you save changes. If credential storage fails after creating the host, retry **Save changes** without creating another host.

The SSH engine supports `ProxyJump`; `ProxyCommand` connections are not supported. It signs with keys kept in Lunport, so an external `IdentityFile` must be imported or moved into the vault before this engine can use it. A host relying on an implicit `~/.ssh/id_*` key must select its key explicitly.

### Google Cloud IAP and OS Login

A host on a Compute Engine instance can be reached through Identity-Aware Proxy TCP forwarding instead of a public address, without `gcloud` running. In the host editor, choose **Google Cloud IAP** under **Connect via** in place of **Address**, then enter the **Instance**, the **Project** and the **Zone**; the instance takes the address's place beside the port. **Google Cloud options**, folded until you open it, holds the Google account, **OS Login**, the Privileged Access Manager grant check and the network interface (`nic0` for the first). The host is then reached through the tunnel instead of at its address, and saving it with **Address** again removes the route. **New IAP host** on the **Google Cloud** page in the Library sidebar (or **⌘N / Ctrl+N** there) opens a new host with Google Cloud IAP already chosen. A host with a route says **IAP** on its card, and its details show the instance and project in place of the address. The tunnel goes to the host's port on the instance, so the instance's firewall must allow Google's IAP range `35.235.240.0/20` on that port, and the Google account needs `roles/iap.tunnelResourceAccessor` on the instance. Jump hosts still work: an IAP host can be the first hop of a chain, but not a later one.

A route is saved with its host. In a library that uses central sync it syncs wherever the host does (the editor says "Saved with the host, so it syncs wherever the host does."), so the same host connects through IAP on your other computers as soon as their gcloud is signed in. Without central sync, that is with no account or an older account that has not moved to central sync, a route stays on the computer where you saved it, and the editor says "Saved on this computer only." Routes already saved on a computer, by an earlier release or before it used central sync, move into the library once it uses central sync, for the hosts the library has. A route the library has no room for stays on that computer, and the **Google Cloud** page says so; a new save that would not fit is refused with a sentence that says what to remove. Deleting a host deletes its route. Devices running Lunport 1.12 or earlier stop syncing a library once it holds a route, until they are updated. On the same computer, Lunport 1.12 cannot open a library that holds a synced route or the memory of a grant requested from Lunport, and releases before 1.12 cannot open a library that holds any route.

Credentials come from `gcloud auth login` on each computer: Lunport reads the files gcloud keeps under `~/.config/gcloud` (`%APPDATA%\gcloud` on Windows, or `CLOUDSDK_CONFIG`) and refreshes access tokens itself. Sign-ins are per computer and are not synced. **Google account** chooses which signed-in account the route uses, from the accounts gcloud has on the computer; leave it on gcloud's active account to use whichever account is active on each computer. When a sign-in has expired, the connection says so and `gcloud auth login <account>` fixes it.

**OS Login** registers the host's vault key with OS Login when it is not there yet and checks that the host is saved with OS Login's username for the account. While the route uses OS Login, **Use OS Login username** under **Username** fills in that username for the route's account and project; it is saved with the host when you save, and the project must have OS Login enabled. The **Require a Privileged Access Manager grant** switch reveals the **Entitlements** (for example `prod-operate, prod-admin`), their **Location** and a **Default grant** length. One of the entitlements must hold an in-flight grant before Lunport opens the tunnel. The default length (30 minutes at first) is what a request starts from until you have asked for another on this computer; it is saved with the route, so it syncs, unlike the last length you used. When none is in flight, a connection you start asks you for one in Lunport's **Request a grant** window: the justification and the duration in minutes, prefilled with what you last asked for on this computer for that host (the route's default length when you never did); **Request** (or Enter) requests the grant on the first entitlement as you, waits until it is active and goes on connecting, while the terminal reads `Waiting for you to request a Privileged Access Manager grant in Lunport.` **Cancel**, an empty justification or no answer within five minutes fails the connection with the sentence that quotes the `gcloud pam grants create` command, as before. Several connections that need the same grant at once (every tab reconnecting after a network drop, a tunnel starting with a tab) ask once. IAP can take about 1½ minutes to see a fresh grant: for two minutes after a grant became active, a refused tunnel is tried again every ten seconds and the terminal says so once; a refusal after that explains the delay. AI requests through MCP and Lunport's own server-identity check never request a grant; they get the refusal.

The details of a host whose route requires a grant show an **Access grant** section: which entitlement holds an active grant and until when (or that one is activating, or that none is), refreshed every minute, and **Request grant…**, which opens the same form and is off while a grant is active. The justification and the length you last used are remembered on this computer only, so requesting a grant never edits the route that syncs.

For a host with a route, **Check through IAP** takes the place of **Check port** in its details. It opens a tunnel to the instance's port with the route's Google account and closes it at once, and gives up after 20 seconds; it says whether the port was reached through IAP and how long that took. When IAP refuses the account the check says so, and for a route that requires a grant it adds that you can request one; an expired sign-in is named with the command that fixes it. Anything else that stops the tunnel, such as a firewall that does not allow IAP's range to the port, is reported with its reason. The check never requests a grant or asks you to sign in, and it tries no SSH, so login and server identity are verified separately.

The **Google Cloud** page answers whether this computer can use your routes; it edits none, since routes are edited with their hosts. **Google sign-in** lists each account gcloud has credentials for on this computer with whether its sign-in works (signed in, expired, or could not be checked), a **gcloud active** badge and how many routes use it; an expired sign-in shows `gcloud auth login <account>`, and an account a route names that this computer has no sign-in for appears as **Not signed in on this computer**. **Access grants**, shown when a route requires a grant, has a row for each entitlement the routes name, with its project and location, whether a grant is active until a time, activating or missing, the hosts that require it and **Request grant**, which is off while a grant is active; a grant ends on its own, and Lunport never revokes one. **Hosts through IAP** lists each host with a route, with its project, instance, zone and account; choosing a host opens its editor. A route the library has no room for is marked **Saved on this computer only: the library has no room for this route**.

A dropped network connection is reconnected inside the tunnel for up to 15 minutes; the SSH session survives it as long as its keepalive allows (with the host's defaults, 30 s × 3 missed, about a minute and a half), and when the tunnel ends the connection says why.

The command-line entry point remains `sshelter connect <host>` through the rename. Windows terminals use `sshelter-cli.exe`, installed beside `sshelter.exe`. Saved MCP commands keep working with these executable names.

## Import and manage keys

Open **Keys → Import private key → From a file** to choose a supported OpenSSH private key with the system picker. You can also paste it. Lunport copies the key into its encrypted local vault and preserves the original file. Passphrase-protected keys retain their protection.

To change a key's name, select it in **Keys**, choose **Rename**, and save the new name. The key ID, fingerprint, private material and host references stay the same. Account key names sync to your other devices; a conflicting or deleted key must be resolved before renaming.

Central library sync includes managed SSH private keys by default after you sign in and unlock sync. There are no per-key sync switches or private-key download steps. The Keys page offers **Set up automatic sync** until this library has completed account setup and migration. Generating or importing a key then includes it in that encrypted library. Hardware and external-agent keys keep their private material on their original device. Saved SSH passwords sync with their hosts; separately stored key passphrases stay on each device.

Lunport's SSH agent provides vault keys to compatible local SSH clients while the app is running and asks before a program uses a key. Keep the app running, or enable launch at login when you need that integration. Exporting a private key creates an ordinary key file outside the vault; other programs can then use that copy independently.

## Local use without an account

New installations open a local library immediately. Add and edit hosts, manage keys, import SSH configuration and connect to your servers without signing in. These actions do not enroll the device or upload your library to the sync service. SSH connections still need access to their destination servers.

Sync is optional. Open **Sync** when you want to connect your devices; choose **Sign in and sync with Passkey**, then set or enter your sync unlock password. Library sync starts automatically after successful unlock. Until then, locally managed SSH private keys remain in the encrypted local vault. Once library sync is enabled, managed keys join the encrypted library by default.

An existing synced library retains its device approval, recovery and migration checks. Local use does not bypass a revoked device or an unfinished safety review.

## Sync your library

Passkey account sync is available on macOS, Windows and Linux.

Open **Sync** in the upper-right toolbar, or **Settings → Local data → Open sync**. The account-service URL starts blank: deploy your own Cloudflare or Docker service, enter its HTTPS URL and choose **Sign in and sync with Passkey**. Local use needs no account. Passkey needs no external identity provider; OIDC remains optional.

On the first device, create and confirm a **sync unlock password** of at least 12 characters. Lunport prepares and syncs your encrypted library automatically. Hosts, Groups, tunnel rules, Google Cloud IAP routes, saved SSH passwords and managed SSH private keys are included. The server stores encrypted library content.

On another device, sign in to the same account on the same server, then enter the same sync unlock password once. Lunport securely connects the device, downloads your library and merges local records automatically. Imported host references, tunnel rules and Google Cloud IAP routes are remapped together. No pairing code is required. Passkey signs you into the account; the sync password unlocks encrypted data inside the app.

The former sync-code controls are removed. To change an already selected service, edit its URL and choose **Change server and restart**. This opens a separate empty local library and closes terminal sessions. Reimport your SSH config explicitly; old account, Vault and backup contents are not silently uploaded to the new service. First-time sign-in from a local library keeps that library.

New and imported records then sync with the library. You can edit cached records offline; changes queue until the next connection. Managed SSH private keys and saved SSH passwords are included automatically. The relay receives ciphertext. Changing or removing a saved SSH password also syncs. Passwords remain bound to the host identity, address, port and username; changing those connection settings requires saving the password again. Previously saved passwords without that binding must be saved again once. Each device still confirms server fingerprints before using credentials.

Use the account device controls to revoke a lost device. Revocation blocks subsequent authenticated sync; it does not erase content already decrypted on that device. Save your sync unlock password in a password manager. It is not sent to the server and cannot be recovered through Passkey sign-in.

The relay can run on Cloudflare Workers or your own server with Docker Compose. See [server configuration and deployment guides](central-server-configuration.md). Relay URLs require HTTPS; localhost HTTP is allowed for development.

## AI access through MCP

Open **Settings → AI access**, enable access and choose the hosts or Groups a client may use. An explicitly allowed Group includes subgroups and current or future members, including synced hosts. Moving a host out removes that Group permission; individual grants remain until removed separately. Group permissions are local to this device and library, use stable IDs, and are independent of the display name. Renaming retains permission; another Group with the same name receives none. Under **Connect an AI tool**, select Codex, Claude Code, Claude Desktop, Cursor or VS Code and choose **Add**. Codex and Claude settings are backed up before the app saves its entry; Cursor and VS Code open their own installation review. Existing unrelated servers and settings are preserved. Adding a tool does not grant host permissions or change command review.

**Allowed hosts** shows the effective host count and separate **Groups** and **Hosts** tabs. Search or filter by access status; select a Group’s host count to review its members. Each row shows **Allowed**, **Not allowed**, or **Partial** for a Group covered only by member grants, with its access source and member count. **Manage access** opens the inherited grant or adds a separate grant that survives its removal. **Remove grant** removes only that direct grant; other Group or individual grants continue to apply. Raw record IDs are omitted from normal rows but still work in search.

**Configured** means the settings were saved, not that the client is connected. Start a new Codex or Claude Code session, or quit and reopen Claude Desktop, to load the server. Cursor and VS Code finish installation in their own UI. **Refresh status** checks the local settings again; **Repair setup** can update an existing Lunport entry. A conflicting server name, malformed settings or a managed settings symlink is left untouched, with manual setup available.

For another agent, open **Manual setup & other agents**. Copy or export the JSON `mcpServers` configuration, Codex TOML or VS Code JSON. The same area provides the executable path and `--mcp` argument separately, plus optional Codex/Claude Code terminal commands. These configurations connect a local stdio MCP client on this computer. New configurations register the server as `lunport` and export as `lunport-mcp.json`, `lunport-mcp.toml` or `lunport-vscode-mcp.json`. Existing `sshelter` registrations remain supported and keep their alias and client permissions when repaired. The installed executable path can still end in `sshelter` or `sshelter.exe`; use the actual path shown by the app.

The Records adapter uses an OS-authenticated local session broker. It can start Lunport in the background; approvals and server trust decisions appear in the app when needed.

| Tool | Behavior |
| --- | --- |
| `list_hosts` | List hosts allowed individually or through a Group. |
| `get_host` | Read sanitized public settings for a permitted host, including its Google Cloud IAP route when it has one. |
| `ssh_exec` | Execute a bounded command under Ask or explicitly acknowledged Auto-log. |
| `create_host` | Propose public connection settings for your review. Saving does not grant AI access or trust a server key. |
| `verify_host_key` | Verify a permitted host's fingerprint, with an in-app trust decision for a new or changed key. |
| `update_host` | Propose changes to a permitted host's public connection settings; Lunport shows each change as old → new and asks before saving. Changing the address clears the pinned server key, as the editor does. |
| `set_transport` | Propose a permitted host's Google Cloud IAP route, or changes to it (a field given replaces that field only; `pam` sets or removes the grant check); Lunport asks before saving. |
| `remove_transport` | Propose removing a permitted host's route, so it is reached at its saved address again; Lunport asks before saving. |

For example, a client can propose `create_host` with `{"alias":"web","hostname":"server.example.com","user":"deploy","port":22}`. Review the settings in Lunport, then allow that host in AI access, or save it in an already allowed Group, before inspection, fingerprint verification or command execution. The native creation review shows whether existing Group permission applies. Creation fields cannot supply passwords, private keys, host-key pins or AI permission grants.

To change a host the client may use, it proposes `update_host` with `{"alias":"jumpbox-prod","hostname":"10.20.0.8"}`, and to reach it through IAP, `set_transport` with `{"alias":"jumpbox-prod","project":"knowknow-prod","zone":"asia-east1-b","instance":"jumpbox","pam":{"entitlements":["prod-operate"]}}`; each opens Lunport's approval window with the fields that would change, and nothing is saved without your click, in Auto-log mode too. Moving a host between Groups, its server key, passwords and private keys stay out of reach of these tools.

`verify_host_key` accepts a host ID or exact alias; the client cannot supply a trust decision. You can also use **Edit host → Server identity → Verify server fingerprint**. Verification stops before destination login or remote commands. Jump hosts may need their own credentials. A matching saved fingerprint does not prompt again; a changed destination, route, permission or pin requires verification again.

Ask reviews the exact command and can request credentials through Lunport. Auto-log execution never prompts for credentials or silently trusts a new key; complete fingerprint verification first. Authentication answers and command output are not retained in the public audit log. This permission gate covers Lunport MCP requests; other local programs still have their own operating-system access.

**Recent activity** shows the latest 10 public audit entries, retained across app restarts. **Requested** and **Completed** show the date and time, including seconds and this device's local time zone. Older entries show only the timestamps that were recorded; entries without a usable timestamp show **Time unavailable**.

## Existing Legacy workspaces

Legacy mode keeps your OpenSSH configuration as the source of truth. It preserves comments, blank lines, ordering and unknown directives, changing only the edited lines. Included files remain part of the workspace. Every write is backed up; restoring also backs up the current file first.

Legacy tools include effective configuration, key hygiene, jump-chain inspection, lint, discovery from `known_hosts` or Tailscale, and host-key cleanup. Settings uses **Files & backups** and **Discovery & checks** for the corresponding controls. Use the explicit migration review to copy selected hosts and keys into Records.

### Historical sync files

The old chain sync service is retired. Existing files under `~/.ssh/sshelter/` remain local OpenSSH sources; this release does not delete them or retrieve old chain data from the server. If an alias appears in more than one source, OpenSSH combines matching blocks and takes the first value for most settings; repeatable options may accumulate. Lunport blocks ambiguous edits and identifies the sources to review.

Use **Import** to copy host settings from an old local `sync-state.json` into Records, then enable encrypted library sync with a central account. Keep a backup of the original files until you have reviewed the imported hosts and keys. Key material, saved SSH passwords and trust approvals need separate review.

### Legacy MCP

The Legacy adapter uses an authenticated localhost bridge and exposes `list_hosts`, `get_effective_config` and `run`. Each remote `run` waits for an in-app **Allow once** decision. It uses non-interactive OpenSSH authentication (`BatchMode=yes`), so key or agent authentication must already work without prompts. Passwords and passphrases are not forwarded to the AI process.

## Windows integrations

Connections use Lunport's engine and bundled console helper. Vault keys do not require Windows' ssh-agent service. For external key files that you want Windows OpenSSH to keep loaded, enable the **OpenSSH Authentication Agent** service once from an administrator PowerShell:

```powershell
Set-Service ssh-agent -StartupType Automatic
Start-Service ssh-agent
```

In-app key deployment uses Windows OpenSSH; Windows does not include `ssh-copy-id`. The app's deployment check identifies unsupported older OpenSSH builds and explains the next step.

Git for Windows has its own SSH executable, which cannot use Lunport's Windows agent pipe. To use Windows OpenSSH with Git, run:

```bash
git config --global core.sshCommand C:/Windows/System32/OpenSSH/ssh.exe
```

## Updates and help

**Settings → Updates** shows the installed version, release notes, download progress and Stable/Beta channel. Switching from Beta to Stable keeps the installed version until a newer stable version is available. Installing an update restarts the app and ends active sessions.

On macOS, an old `SSHelter.app` installation is renamed to `Lunport.app` when the updated app starts. The old path remains a compatibility link, so existing absolute MCP and CLI commands keep working. An enabled launch-at-login entry is updated to the new path; a disabled entry stays disabled. Credentials and library data retain their existing identity. macOS may request installation permission once. A cancelled or incomplete rename can be retried in **Settings → About → Finish the Lunport rename**, without reinstalling. A conflicting app at the destination is never overwritten.

**Settings → About** contains the Lunport identity, installed version, project, releases, issues and license links. On macOS, **Lunport → About Lunport** also opens the native panel. Local diagnostic logs are available in **Settings → Diagnostics** in Records, or **Discovery & checks** in Legacy.

### Recover host settings from an old local workspace

In **Import**, choose the old Lunport `sync-state.json`, review the hosts, then confirm. On macOS, the original file is `~/Library/Application Support/org.homelab.sshelter/sync-state.json`; switching servers preserves it while the new workspace lives in a separate `server-workspace-*` folder. Choose the original file on any device that still has the host cache. The old relay does not need to be available.

This restores host aliases, addresses, users, ports, jumps, timeouts, tags and notes. Groups retain their hierarchy, defaults and host membership. The import uses new local host and Group identities and preserves the source file. Assign new SSH keys in the host editor and confirm server fingerprints when connecting; old account state, key material and trust approvals are excluded. After reviewing the local hosts, finish encrypted library setup to sync them to the new account.

### Move hosts and Groups between devices

Open **All hosts → More library actions → Export hosts and Groups…** to save `lunport-hosts.json`. If a server change left the old library in the original workspace, choose **Export previous workspace hosts and Groups…** instead. Export works offline without signing in and reads cached host settings; it does not contact the retired relay or open the key Vault.

On the destination device choose **Import hosts**, select the exported JSON, review the hosts, then confirm. Group names, hierarchy, defaults and host membership are retained, including empty Groups. Jump-host relationships, tags and notes are also retained. Older host-only exports still import, but require a new export from the source workspace to recover Groups. SSH private keys, old key bindings, server fingerprint approvals, imported commands and account credentials are excluded. Assign SSH keys and verify server fingerprints before connecting. Saved SSH passwords are also excluded. Source workspaces remain in place. Host exports contain server addresses and notes, so keep them private.
