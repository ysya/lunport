# Final review fix list — plan 1a (9c6b8ed..62662b0)

One fix wave, one implementer, in the order below (severity first; within a severity, engine code before tests, docs and CI).
Base: `62662b0` on `next/own-ssh`. Every Global Constraint of the plan still holds: `--offline --locked`, no change to
`src-tauri/Cargo.toml` / `Cargo.lock` (`git diff --stat -- src-tauri/Cargo.toml src-tauri/Cargo.lock` prints nothing at the end),
`vault/` untouched, russh named only in `ssh/russh_engine.rs`, no new compiler warning (the old `set_host_enabled` one stays the only
one), conventional commits staged by path, nothing pushed. Commands run from `src-tauri/` with
`PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH`, exactly one `--`, and `SSHELTER_REQUIRE_OPENSSH=1` for `ssh::`.
After every run that starts sshd, the leftover check of `global-constraints.md` (listeners / `sshd-session` / `sshelter-sshd-*` dirs all 0).

Line numbers are those of `62662b0`; they move as the wave edits a file, so find each place by the quoted text.

---

## F1 — Important — `exec` leaves the command's stdin open, so a command that reads it waits for the whole timeout

- **Where:** `src-tauri/src/ssh/russh_engine.rs:965-974` (`exec_on`, right after the `exec` request is handed over); doc
  `russh_engine.rs:952-959`; contract `src-tauri/src/ssh/traits.rs:32-39`.
- **What is wrong:** the engine sends the `exec` request and never sends `CHANNEL_EOF`, and `Session::exec` has no stdin parameter, so
  nobody can. Any command that reads stdin (`cat`, `read`, `sudo -S`, `apt-get install` without `-y`, `python3` with no script, a tool
  that prompts) blocks until the caller's timeout and comes back `Ended::TimedOut` (MCP: up to 300 s) instead of seeing end-of-file at
  once. Today's MCP `run` (`src-tauri/src/mcp.rs:847`, `.stdin(Stdio::null())`) gives the command EOF immediately, so phase 2's
  `ssh_exec` over this engine would regress. The ledger deferred "exec never sends EOF" to 1b as "design for 1b"; that ruling is wrong on
  the merits: the 1a interface has no stdin at all (spec §6.1, §7.1 `exec{host, command, timeout_secs}`, §8.2), so the only possible
  semantics is "empty stdin", it can only be set inside the engine, and 1b would have to patch `russh_engine.rs` anyway.
- **Change:** after the `match sent(channel.exec(true, command)).await { … }` block, add
  ```rust
  // The command's standard input is empty, as with `ssh host command < /dev/null`: one that reads it sees the end at once instead of
  // waiting for the timeout. On a connection that does not take the request in time the command reads on, and the timeout ends it.
  let _ = sent(channel.eof()).await;
  ```
  (ignore the result: the command is already running, and an `Err` here must not orphan it without a close).
  Doc `exec_on` (:954-956): "…and the requests that start the command, end its input and close the channel are given `SEND_LIMIT` each."
  Doc `Session::exec` (traits.rs:32-34), see F6 for the full replacement text (it says the command's stdin is empty).
- **Test (red on 62662b0, green after):** `engine_tests/exec.rs`, new
  ```rust
  /// The command's standard input is empty, as `ssh host command < /dev/null` gives it: a command that reads it sees the end at once
  /// instead of waiting until the timeout.
  #[test]
  fn a_command_that_reads_its_input_sees_the_end_at_once() {
      let Some(tools) = tools() else { return };
      let server = Server::start(&tools, &[]);
      let session = open_session(&engine(), &server);
      let started = Instant::now();
      let result = session.exec("cat; read line; echo after:$?", Duration::from_secs(20), MIB).unwrap();
      assert_eq!((result.ended, result.exit_code, result.stdout.as_slice()), (Ended::Exited, Some(0), b"after:1\n".as_slice()));
      assert!(started.elapsed() < Duration::from_secs(5), "the command waited for input: {:?}", started.elapsed());
  }
  ```
  Before the fix it ends `TimedOut` after 20 s. No existing test reads stdin (checked), and the toy server's `exec_request` ignores EOF.

---

## F2 — Minor — "Authentication failed for u@a (tried: )." when nothing could be tried, and a skipped password leaves no reason

- **Where:** `src-tauri/src/ssh/error.rs:55-62` (Display of `AuthFailed`) and its doc `error.rs:23-24`;
  `src-tauri/src/ssh/russh_engine.rs:715` (`let Some(password) = password else { break 'password Step::Skipped };`);
  `src-tauri/src/ssh/fake.rs:229-230` (fake mirror).
- **What is wrong:** `tried` is empty when the key is not in the vault (`a_key_that_is_not_in_the_vault_is_skipped_and_the_failure_says_so`
  pins `tried.is_empty()`), when `AuthSource::password` returns `None` for a password-first hop (the user cancelled the dialog — 1b's
  planned flow), or both. The sentence then reads `(tried: )`, and for the cancelled-password case it is
  `Authentication failed for deploy@web (tried: ).` with no reason at all. Spec §11: `Display` is the sentence the user sees.
- **Change:**
  - error.rs Display: when `tried.is_empty()` write `Authentication failed for {user}@{alias} (no login method could be tried).`,
    otherwise the current `(tried: …)` sentence; the `reason` suffix logic is unchanged. Doc of the variant: "`tried` lists the methods
    that were attempted, possibly none (a key that is not in the vault, no password to give)".
  - russh_engine.rs:715: `let Some(password) = password else { reasons.push("No password was given.".to_string()); break 'password Step::Skipped };`
  - fake.rs:230: `None => Err(ConnectError::AuthFailed { hop: reference.clone(), tried: vec![], reason: "No password was given.".to_string() }),`
    (the `refused` closure keeps an empty reason for the other arms).
- **Tests:** error.rs `an_auth_failure_reason_follows_the_sentence`: add the case `tried: vec![]`, reason
  `"The key k1 is not available on this computer."` → `"Authentication failed for deploy@web (no login method could be tried). The key k1 is not available on this computer."`.
  engine_tests/connect.rs, new `a_password_first_hop_with_no_password_says_that_nothing_could_be_tried`: scratch sshd (key only), hop
  `server.hop_with("web", server.sshd.port, AuthMethod::Password)`, `VaultAuth::new()` (no password) → assert
  `AuthFailed { tried, reason, .. }` with `tried.is_empty() && reason == "No password was given."` and
  `error.to_string() == format!("Authentication failed for {}@web (no login method could be tried). No password was given.", server.sshd.user)`.
  The fake test `a_password_login_asks_the_auth_source_and_checks_the_answer` (`tried.is_empty()`) keeps passing.

## F3 — Minor — absurd durations from a host record panic inside `connect`

- **Where:** `russh_engine.rs:70-72` (`prompt_wait_for`: `connect_timeout * 4`) and `russh_engine.rs:744`
  (`std::time::Instant::now() + prompt_wait`).
- **What is wrong:** `Duration * 4` and `Instant + Duration` panic on overflow; `connect_timeout` comes from a user-editable host record
  (1c's importer reads `ConnectTimeout` from ssh_config). Every other wait already saturates (`LONGEST_TIMEOUT`, tokio's `timeout`).
  A panic here kills the broker thread that called `connect`.
- **Change:** `self.prompt_wait.unwrap_or_else(|| connect_timeout.saturating_mul(4).max(Duration::from_secs(60)))` and
  `let deadline = std::time::Instant::now() + prompt_wait.min(LONGEST_TIMEOUT);`
- **Tests:** in `a_keyboard_interactive_answer_gets_four_connect_timeouts_and_at_least_a_minute` add
  `assert_eq!(options.prompt_wait_for(Duration::MAX), Duration::MAX, "an absurd connect timeout saturates instead of panicking");`.
  engine_tests/login_methods.rs (toy only, outside the macro), new `a_hop_with_an_absurd_connect_timeout_still_logs_in`:
  `toy()`, hop `AuthMethod::Interactive` with `connect_timeout = Duration::MAX`, `VaultAuth::new().with_answers(&[&subject.password])`,
  `engine().connect(…)` succeeds and `ok_output` passes (panics on 62662b0).

## F4 — Minor — Windows I/O errors keep their trailing period: "(…actively refused it.)."

- **Where:** `russh_engine.rs:217-226` (`describe_io`).
- **What is wrong:** Windows' messages end with a period before ` (os error N)`; the composed sentence becomes
  `Could not reach 127.0.0.1:22 (no connection could be made because the target machine actively refused it.).`
- **Change:** `let text = text.split(" (os error").next().unwrap_or(&text).trim_end_matches('.');` (rest unchanged).
- **Test:** in `io_errors_are_described_without_the_os_number_or_a_leading_capital` add the case
  `"No connection could be made because the target machine actively refused it. (os error 10061)"` →
  `"no connection could be made because the target machine actively refused it"`.

## F5 — Minor — the "empty refusal" decision is written out three times

- **Where:** `russh_engine.rs:702-706` (key arm), `:721-725` (password arm), `:768-772` (`none` after a skipped method).
- **What is wrong:** three copies of the same `classify_empty_answer` match (one slightly different in shape); a future change (a new
  `EmptyAnswer` variant, a different lost text) has to find all three. Behaviour is pinned by `a_server_that_offers_no_login_method_is_an_authentication_failure`,
  `a_connection_that_is_cut_while_the_login_waits_for_the_server_is_lost_and_not_refused` and
  `a_link_cut_while_the_login_waits_for_the_verdict_on_a_password_is_lost_and_not_refused`.
- **Change:** add next to `no_login_method`:
  ```rust
  /// Settles a refusal that names no method to go on with (see `classify_empty_answer`): the (empty) list for a plain refusal; the
  /// failure when the server offers no login method (`tried` and `reasons` go into it) or the connection was lost while we waited.
  async fn after_empty_refusal(shared: &HopShared, handle: &Handle<EngineHandler>, hop: &HopRef, tried: &mut Vec<AuthMethod>, reasons: &mut Vec<String>, remaining: MethodSet) -> Result<MethodSet, ConnectError> {
      match classify_empty_answer(shared, || handle.is_closed(), LOGIN_END_WAIT).await {
          EmptyAnswer::NoLoginMethod => Err(no_login_method(hop, std::mem::take(tried), std::mem::take(reasons))),
          EmptyAnswer::Lost => Err(ConnectError::Unreachable { hop: hop.clone(), reason: "the connection was lost during login".to_string() }),
          EmptyAnswer::Refusal => Ok(remaining),
      }
  }
  ```
  and use it in the three places: key and password arms
  `… if remaining_methods.is_empty() => Step::Refused(after_empty_refusal(shared, handle, &reference, &mut tried, &mut reasons, remaining_methods).await?),`
  and the `none` branch `… if remaining_methods.is_empty() => offered = Some(after_empty_refusal(…, remaining_methods).await?),`.
  No behaviour change; the three tests above stay green.

## F6 — Minor — doc comments that are no longer true, and the thread rules 1b needs

Text changes only (no code). Wrap at about 150 columns.

1. `traits.rs:4-6` — "Two additions to the spec's block" is stale (spec §6.1 now has both, and `Ended::Truncated`). Replace with:
   "Two members of the spec's block are there because russh needs them: `ShellChannel` is `Send + Sync` (a shell is read on one thread
   while another writes, which needs a shared reference), and `AuthSource::public_key` exists (russh's public-key login announces the
   public key before it asks for a signature, and neither `Hop` nor `sign` carries it)."
2. `traits.rs:15-16` (`SshEngine::connect`) — replace "every wait inside is bounded." with: "Every wait of the engine's own is bounded;
   a call into `auth` lasts as long as the source takes (`AuthSource::password` gets no deadline, `AuthSource::interactive` gets one).
   `host_keys` and `auth` are called on the thread that called `connect`, while it is blocked in it: do not hold a lock across `connect`
   that the policy or the auth source takes."
3. `traits.rs:23` — "Dropping it closes it." → "Dropping it closes it; on a plain thread the drop waits up to about 3 s for the disconnects to go out."
4. `traits.rs:32-34` (`Session::exec`, also fixes the 166-column line) — replace the second and third sentences with: "Output beyond
   `output_cap` bytes (stdout and stderr together) is not read: the engine asks for the channel to be closed, sets `truncated` and ends the
   result as `Ended::Truncated`. The command's standard input is empty: it reads end-of-file at once, as with `ssh host command < /dev/null`.
   A timeout, the cap and a command that ends without a status are results, not errors. After a timeout or the cap the connection is still
   usable; a command that ends without a status (`Ended::Disconnected`) normally means that the connection was lost, which `is_alive` tells."
5. `traits.rs:45` (`disconnect_reason`) — append: "The first call after the end may wait up to 0.3 s for the hop that ended to write down why."
6. `traits.rs:48` (`close`) — append: "On a link that has stopped answering it gives each hop up to about 2.5 s."
7. `traits.rs:55-57` (`ShellChannel::write`) — append: "A `Timeout` can follow a partial write: part of `data` may have reached the
   shell, so sending all of it again can repeat input."
8. `traits.rs:80` (`HostKeyPolicy::check`) — "Called on the thread that called `SshEngine::connect`, while the handshake is in progress, so
   it must be fast and must not block: a lookup, never a dialog."
9. `traits.rs:84` (`AuthSource` doc) — append: "Every method is called on the thread that called `SshEngine::connect`."
10. `types.rs:217-219` (`Ended::Disconnected`) — "The channel ended without an exit status or a signal: normally because the connection was
    lost (`Session::is_alive` tells), rarely because the server closed the channel without reporting one. Never read this as exit code 0."
11. `types.rs:261` (`DisconnectKind::KeepaliveTimeout`) — "The server stayed silent for (`keepalive_max_missed` + 1) keepalive intervals:
    `keepalive_max_missed` keepalives went unanswered, and the next silent interval ended the connection." (russh `client/mod.rs:1426-1434`
    counts first and gives up when the count exceeds the maximum; measured 3027 ms for 1 s / 2.)
12. `error.rs:1` — append: "A failure behind a jump host is reported on the hop where it happened (`Unreachable`'s `reason` names the jump
    host when the jump host could not reach the next one); spec §11's `Could not connect through {jump alias}: {reason}` is the broker's
    wording of it, as are the sentences that need the keepalive seconds or "while the command was running"." (plan 1a line 509 already decided this.)
13. `russh_engine.rs:55-57` (`EngineOptions::prompt_wait`) — "How long the person may take to answer one keyboard-interactive round and,
    separately, how long the server may then take over its verdict on the answers (one round can take up to twice this). `None` = 4 × the
    hop's connect timeout, at least 60 s (spec §6.2 step 4)."
14. `russh_engine.rs:254-255` (`stall_limit`) — replace "Not covered: the TCP connect (the timer does not exist yet), and the waits for a
    person, which keep their own limits (a host key question or a signature parks russh's loop, and the loop re-arms the timer when it
    moves on)." with "Not covered: the TCP connect (the timer does not exist yet) and the waits for a person (see the module rules). The host
    key question and the signature are answered inside this limit, which is one more reason both must be quick; while they are asked,
    russh's loop is parked, and it re-arms the timer when it moves on."
15. `russh_engine.rs:839-841` (`Drop for RusshSession`) — the first sentence's reason ("a task spawned now would die with it") stopped
    being true when the task took ownership of the runtime (1fe8142). Replace the doc with: "Sends the disconnects. On a plain thread it
    waits for them (up to 3 s) before it returns, so that the server reads a disconnect message and not a dropped socket. Inside any tokio
    runtime context (a thread of the engine's runtime or of another one) blocking is not allowed, so a task does it, and the task owns the
    engine's runtime until it is done."
16. `fake.rs:81-82` (`FakeEngine`) — append: "Closing a session ends every shell opened on it with `Exit::Disconnected`, as a lost
    connection does; `with_shell_exit` is how a shell ends when it is closed itself (`ShellChannel::close`) or ends at once."
17. `testing/harness.rs:5` — the path `spike/russh/src/harness.rs` no longer exists: "Ported from the phase-0 spike's harness (the
    `spike/` crate that plan 1a deleted), checked on macOS with OpenSSH 10.3p1: …".
18. `testing/harness.rs:15` and `:243` — `rm -r "$TMPDIR"/sshelter-sshd-*` → `rm -r "${TMPDIR:-/tmp}"/sshelter-sshd-*`.
19. `testing/harness.rs:18-19` and the test doc `:830-832` — "each of them starts a session of its own" is not exact (the post-login
    process stays in the per-connection process's group). Say instead: "none of them stays in the listener's process group (the
    per-connection process starts a session of its own, and a shell another one), so killing the listener's group does not reach them".

## F7 — Minor — test tightening (parked by the task reviews)

1. `channel.rs:272-288` `chunks_come_out_in_the_order_they_went_in_and_a_small_buffer_gets_part_of_a_chunk`: wrap the body in
   `bounded(|| { … })` (a `read_until` that ignored its deadline would hang the suite).
2. `channel.rs:374` (`a_waiting_reader_wakes_when_a_chunk_arrives_and_when_the_queue_closes`): before `queue.close();` add
   `std::thread::sleep(Duration::from_millis(100)); // the reader is back in its wait: only close()'s notify can wake it now`
   (the close-without-notify mutant escaped 2 of 150 runs without it).
3. `testing/mod.rs:16-25` (`eventually`): after the loop and before the `panic!`, add `if condition() { return; }` (a condition that
   became true during the last sleep is not a timeout).
4. `types.rs` tests, new `a_secret_does_not_show_its_value_in_debug_output`:
   `let secret: Secret = Zeroizing::new("hunter2".to_string()); assert!(!format!("{secret:?}").contains("hunter2"));`
   (zeroize ≥ 1.9 redacts; 1.8.2 derived `Debug` and printed it; `Cargo.toml` says `zeroize = "1"`, the lock pins 1.9.1 through
   ssh-key 0.7.0-rc.11's `^1.9`).
5. `fake.rs` `a_password_login_asks_the_auth_source_and_checks_the_answer`: add the success case of a password-first hop with the
   trusting policy: `connect(&engine, &by_password, &asked_once)` is `Ok` and `asked_once.asked == ["password pw"]` ("asked once,
   before the host key, and not again during the login"; a re-ask at fake.rs:229 survives today). In `closing_is_recorded_once`, before
   the racing part: `drop(session);` then assert exactly one `FakeEvent::Closed` in `engine.events()`.

## F8 — Minor — the loser of two concurrent sweeps prints an error

- **Where:** `testing/harness.rs:421-424`.
- **Change:** `Err(error) if error.kind() == std::io::ErrorKind::NotFound => "directory already removed".to_string(),` before the
  generic `Err` arm.

## F9 — Minor — CI files (parked by the Task 12 and 13 reviews; first runs are the user's)

1. `.github/workflows/test-engine.yml`, `linux` job:
   - `runs-on: ubuntu-24.04` (the PAM image is `ubuntu:24.04`, and the package names were checked against 24.04); update the header
     comment's "gcc on ubuntu-latest" accordingly.
   - Move the step "Start OpenSSH with PAM in a container" to just after "OpenSSH on the runner" (before the scratch-sshd cargo step), and
     give "Password and keyboard-interactive tests against the container" `if: ${{ !cancelled() }}`, so a first-run failure of the
     scratch-sshd step does not hide whether the image builds and PAM logins work.
   - Top level: `concurrency:` with `group: ${{ github.workflow }}-${{ github.head_ref || github.ref_name }}` and
     `cancel-in-progress: true` (a push to `next/own-ssh` with an open PR runs twice otherwise).
2. `src-tauri/tests/pam-sshd/Dockerfile:25`: append `\` + ` && grep -q 'session optional pam_loginuid.so' /etc/pam.d/sshd` so a sed that
   matched nothing fails the build instead of producing an image whose logins end at once.
3. `.github/workflows/test-windows.yml`:
   - `:50-53` comment: add the SSH engine to the list ("and the SSH engine (`ssh::`: the tests that need no sshd of their own; the
     scratch-sshd ones print "skipped" on Windows)").
   - `:60`: "The library and the binary in a debug build, with russh in the dependency graph (the release workflow builds the same graph)."
   - `:116-120`: add `SSHELTER_REQUIRE_TEST_SSH: "1"` to the step's `env`.
4. `engine_tests/environment.rs:15-22`: when the three variables are not all set, first
   `assert!(!std::env::var("SSHELTER_REQUIRE_TEST_SSH").is_ok_and(|value| value == "1"), "SSHELTER_TEST_SSH_PORT, SSHELTER_TEST_SSH_USER and SSHELTER_TEST_SSH_KEY are required (SSHELTER_REQUIRE_TEST_SSH=1)");`
   (the same rule as `SSHELTER_REQUIRE_PAM`; today a lost `GITHUB_ENV` line turns the Windows leg into a silent pass); mention the variable
   in the module doc. `:36`: the message prints `String::from_utf8_lossy(&hello.stdout)` instead of the byte vector.
5. Check both workflows with `actionlint` (binary or the local `rhysd/actionlint:1.7.12` image with `--network none`), as Tasks 12/13 did.

## F10 — Minor — no test of a chain longer than two hops

- **Where:** `engine_tests/jump.rs` (new test). Spec decision 4: "ProxyJump 多層". A third hop is the one path not exercised: a
  `direct-tcpip` open on a session whose own transport is a channel stream, and a three-hop `disconnect_all`.
- **Test:** `a_three_hop_chain_runs_a_command_on_the_last_host_and_closing_disconnects_every_hop`: three `Server::start(&tools, &[LOG_LOGINS])`
  (`a`, `b`, `c`), one `VaultAuth` with `ka`/`kb`/`kc`, target `[a.hop_with("a", a.sshd.port, key("ka")), b.hop_with("b", …), c.hop_with("c", …)]`,
  `TestPolicy::trusting()`; `exec("echo $SSH_CONNECTION")` → `server_port_in(stdout) == Some(c.sshd.port)`; `policy.seen()` aliases
  `["a", "b", "c"]`; `session.close()`; then `eventually` each of `c`, `b`, `a` logs "Received disconnect" (5 s each). The exec settles
  the destination, as `settle` does in `closing_the_session_disconnects_every_hop`.

## F11 — Minor — keyboard-interactive with several rounds and an empty round is untested

- **Where:** `russh_engine.rs` `toy_server` (`ToyLogin`, `Toy`, `auth_keyboard_interactive`) and `engine_tests/login_methods.rs`.
  The engine's KI loop (`russh_engine.rs:735-760`) handles any number of rounds and answers a zero-prompt round without asking the
  person; that is the usual 2FA shape (PAM: password, then a code; Duo-style "wait" rounds with no prompt) and nothing exercises it
  (the toy and the PAM container ask one question).
- **Change (toy server, test-only):** add `pub rounds: Option<Vec<Vec<(String, String)>>>` to `ToyLogin` (each round a list of
  `(prompt, expected answer)`; an empty list is an info request with zero prompts); `None` keeps today's single password round
  (`toy()`/`slow_toy()` set `rounds: None`). `Toy` gets a `round: usize` (per client); on `response == None` it starts at round 0; on
  `Some(response)` it compares the answers with the current round (any mismatch → `Auth::reject()`), then answers `Auth::Partial` with the
  next round's prompts, or `Auth::Accept` after the last one.
- **Test:** `a_keyboard_interactive_login_with_several_rounds_and_an_empty_one_succeeds` (toy only): rounds
  `[[], [("Password: ", <password>)], [("Verification code: ", "123456")]]`; a local `AuthSource` that answers by prompt text and
  records the prompt texts of each call; the login succeeds, `ok_output` passes, and the recorded calls are exactly
  `[["Password: "], ["Verification code: "]]` (the empty round never reaches the auth source).

---

## Verification for the wave

- Red first where the item says so (F1, F2, F3 fail on 62662b0), then green.
- `SSHELTER_REQUIRE_OPENSSH=1 … cargo test --offline --locked --lib -- ssh::` → 162 + 6 new tests (F1, F2, F3, F7.4, F10, F11) = **168**
  if done as written (folded assertions add no tests).
- Whole suite with `--skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain` →
  1579 + 6 = **1585**, 2 filtered.
- Mutations to show the new tests can fail (restore byte-identically, `git diff --stat` empty): remove the `eof` line (F1 test red);
  remove the empty-`tried` branch (F2 Display test red); `connect_timeout * 4` back (F3 test panics).
- Leftover check after every sshd run; `git diff --stat -- src-tauri/Cargo.toml src-tauri/Cargo.lock` empty; only the old warning.

---

## Not for this wave

Belongs to plan 1b/1c/1d or to the user; each with the reason it is not in this wave.

1. **[1b, interface] `AuthFailed` cannot say "the server offers password and the source had none".** The ruling for 1b (ledger: the
   broker's `AuthSource::password` answers from the keychain only, then "AuthFailed{tried} → the broker asks the person and reconnects
   password-first") needs that signal; `tried` excludes skipped methods and the reason is prose (F2 only fixes the prose). Options:
   an `offered`/`skipped: Vec<AuthMethod>` field on `AuthFailed`, or a dedicated variant. A spec §6.1 change, so the 1b plan decides.
2. **[1b, security UX] A pinned host whose server no longer offers the pinned key type fails as `NoCommonHostKeyAlgorithm`, not as a
   changed key.** The narrowing (spec §6.2 step 3) means the engine never sees the new key, so the user gets an algorithm error instead of
   the mismatch warning of §14. Suggested broker rule: on `NoCommonHostKeyAlgorithm` for a hop with `pinned`, reconnect with
   `pinned: None` and a policy that answers `Mismatch` → `HostKeyMismatch { key, pinned }` → the normal warning flow.
3. **[1b] FakeEngine vs real engine, where 1b's broker tests will lean on it.** (a) `ShellChannel::close` → fake: scripted exit
   (default `Code(0)`), real: `Exit::Disconnected` (ruled to 1b); (b) `write`/`window_change` after the session closed → fake `Ok`,
   real `Err(Closed)`; (c) no mid-session disconnect hook (ruled to 1b); (d) `failing_with` returns before the password prefetch, the real
   engine asks a password-first hop before TCP; (e) KI deadline fixed at now + 60 s (real: max(4 × connect_timeout, 60 s)) and late
   answers not rejected; (f) a missing password ends the fake login, the real engine goes on to keyboard-interactive when offered; (g) the
   fake never yields `SessionError::Timeout`/`Channel`. Recommendation: a small parity suite that runs the same scenarios against the
   fake and against the real engine on the toy server.
4. **[1b] `ByteQueue` counts payload only** (deferred by ruling): 1-byte chunks cost about 40× the capacity (~170 MB for a 4 MiB queue).
   Besides a slow program, a malicious server can do this on purpose (threat model §3, "russh 的漏洞" row). Fix when 1b sizes the queue,
   before any beta: merge a pushed chunk into the back chunk while that stays under 16 KiB (`append` in channel.rs; `front_read` stays
   valid because only the end grows) and adjust `chunks_come_out_in_the_order…` (it pins chunk boundaries).
5. **[1b] Gap notice timing** (deferred by ruling): dropped output is announced at the next kept chunk or at close; a stream that goes
   quiet after a gap shows nothing until then.
6. **[1b/1d] A refused PTY or shell request ends the shell as `Exit::Disconnected` with no reason** (`read_shell`, russh_engine.rs:1092-1096).
   OpenSSH says "PTY allocation request failed" (and continues without a PTY). The `Exit` enum has no way to say "refused"; decide in 1b
   whether to add one or a reason.
7. **[1b] Public surface.** `pub mod ssh` exports the channel plumbing and `russh_engine::{RusshEngine::connect_chain, Connection,
   Established}` only because nothing in the app uses the module yet (dead-code); `connect_chain` attaches no watcher. Narrow to
   `pub(crate)` when the broker consumes the module (watch for dead-code warnings on test-only methods such as `Connection::hop_count`).
8. **[1b] Thread and lifetime rules for the broker** (now documented by F6, to be designed in): callbacks run on the connect thread;
   `close`/drop from a plain thread or `spawn_blocking`, never a UI thread (drop waits ≤ 3 s, close ≈ 2.5 s per hop on a dead link);
   `disconnect_reason` may wait 0.3 s; `SessionError::Timeout` is not a dead connection; the first contact asks a password twice (keep
   the typed one across the pin-and-reconnect); a cancelled password dialog is followed by keyboard-interactive when offered (remember the
   cancel); `AuthSource::password` gets no deadline (pick one, spec §7.1 `deadline_ms`); `AuthError` texts go into user sentences, so no
   secret in them; the broker learns about a dead idle session only by polling `is_alive` (no callback).
9. **[1b/1d] Closing a shell before its prompt can strand a PTY-holding process on a macOS sshd** (Task 8 re-review design note):
   defer the real channel close until the first byte or ~3 s; connection-level teardown stays a documented limit.
10. **[1b] Server banners (`USERAUTH_BANNER`) are dropped** (russh's default `auth_banner`). OpenSSH prints them, and some sites require
    it; the interface has no place for them. A reasonable-person expectation for `sshelter connect`; decide in 1b/1d.
11. **[1b] A server's DISCONNECT message during the handshake is lost**: `handshake_error` (russh_engine.rs:490-502) maps `HUP`/`Disconnect`
    to a fixed text without reading `HopShared::ended`. Rare with OpenSSH (it mostly just closes); low value now.
12. **[1c] Host-record validation**: refuse absurd `connect_timeout_secs`/`keepalive_secs`, warn on `keepalive_max_missed = 0` (never
    gives up), and handle an empty `key_id` ("需要金鑰") before connecting. The `AuthFailed` reason names the vault key id
    (`The key {key_id} is not available…`), which 1b/1d should show as the key's name.
13. **[user] `--locked` in test-engine.yml/test-windows.yml vs release-please** (Task 13 ruling): fix in main's release machinery or
    refresh the lock after each release.
14. **[user] russh's pre-login keepalive spin** (KI verdict slower than the interval; a password asked while connected): upstream PR
    (do not arm the timer before `Authenticated`), `[patch.crates-io]`, or the engine's own keepalive. Until then a core burns during a
    slow push approval (bounded by sshd's LoginGraceTime).
15. **[user] Decisions already listed by the plan:** `cargo audit` in CI (decision 8); deleting `spike/russh/target/` (5.7 GB, decision
    12); the vault's ECDSA parser (the cloud session) — when it merges, adjust `a_key_the_vaults_parser_cannot_read_is_told_apart…`.
16. **[first CI runs — watch, do not pre-fix]** the four tests whose stall limit is the 1 s floor (1 s keepalive) on slow runners;
    the wedged-peer test's buffer assumption on Linux (`requests_to_a_peer_that_stopped_reading…` fails loudly if it cannot wedge);
    `ps -ax -o pid=,ppid=` on procps-ng (`descendants_of` degrades to killing the listener only); the PAM image build and real PAM;
    the Windows app build with russh/aws-lc-sys; the `russh_spins_*` canary.
17. **[later] Tests that cannot be made cheaply here:** a jump host that never answers the `direct-tcpip` open (needs a black-holed TCP
    target, i.e. a real network); a watcher-termination test (tokio's alive-task count); a host certificate end to end
    (`Preferred::DEFAULT.host_key_certificates` is empty, so only the handler unit test can reach it).
