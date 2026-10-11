//! Logging in with a password and with keyboard-interactive, and what happens to a prompt that is cancelled, late or slow (spec §6.2
//! step 4). A scratch OpenSSH has no PAM and cannot do either, so the same test bodies run against two servers:
//! - `toy`: a small SSH server in process (`russh_engine::toy_server`), everywhere, always;
//! - `pam`: a real OpenSSH with PAM in a container (`src-tauri/tests/pam-sshd`), when `SSHELTER_PAM_PORT`, `SSHELTER_PAM_USER` and
//!   `SSHELTER_PAM_PASSWORD` say where it is. Without them the `pam` tests print "skipped" and pass, unless `SSHELTER_REQUIRE_PAM=1`
//!   (the Linux job of the CI) turns that into a failure.

use std::time::{Duration, Instant};

use super::{engine, open_session_to};
use crate::ssh::russh_engine::toy_server::{ToyLogin, ToyServer};
use crate::ssh::russh_engine::{EngineOptions, RusshEngine};
use crate::ssh::testing::doubles::{TestPolicy, VaultAuth};
use crate::ssh::testing::harness::{generate_key, tools, KeyKind};
use crate::ssh::testing::proxy::Proxy;
use crate::ssh::testing::{eventually, fact};
use crate::ssh::{AuthMethod, ConnectError, Ended, Hop, SessionError, SshEngine, Target};

const MIB: usize = 1024 * 1024;

/// A server to log in to.
struct Subject {
    port: u16,
    user: String,
    password: String,
    /// Keeps an in-process server running for as long as the subject lives.
    _toy: Option<ToyServer>,
}

impl Subject {
    fn hop_on(&self, port: u16, auth: AuthMethod) -> Hop {
        Hop::new("host-login", "login", "127.0.0.1", port, &self.user, auth)
    }

    fn target_on(&self, port: u16, auth: AuthMethod) -> Target {
        Target { hops: vec![self.hop_on(port, auth)] }
    }
}

fn toy() -> Option<Subject> {
    let login = ToyLogin { user: "tester".to_string(), password: "correct horse battery staple".to_string(), prompt: "Password: ".to_string() };
    let server = ToyServer::start(login.clone());
    Some(Subject { port: server.port, user: login.user, password: login.password, _toy: Some(server) })
}

fn pam() -> Option<Subject> {
    let variable = |name: &str| std::env::var(name).ok().filter(|value| !value.is_empty());
    let (Some(port), Some(user), Some(password)) = (variable("SSHELTER_PAM_PORT"), variable("SSHELTER_PAM_USER"), variable("SSHELTER_PAM_PASSWORD")) else {
        let required = std::env::var("SSHELTER_REQUIRE_PAM").is_ok_and(|value| value == "1");
        assert!(!required, "SSHELTER_PAM_PORT, SSHELTER_PAM_USER and SSHELTER_PAM_PASSWORD are required (SSHELTER_REQUIRE_PAM=1)");
        eprintln!("skipped: SSHELTER_PAM_PORT, SSHELTER_PAM_USER and SSHELTER_PAM_PASSWORD are not all set");
        return None;
    };
    Some(Subject { port: port.parse().expect("SSHELTER_PAM_PORT is a port number"), user, password, _toy: None })
}

fn engine_with_prompt_wait(wait: Duration) -> RusshEngine {
    RusshEngine::with_options(EngineOptions { prompt_wait: Some(wait), worker_threads: 2, ..EngineOptions::default() })
}

fn ok_output(session: &dyn crate::ssh::Session) {
    let result = session.exec("echo ok", Duration::from_secs(20), MIB).expect("the session runs a command");
    assert_eq!((result.stdout.as_slice(), result.ended, result.exit_code), (b"ok\n".as_slice(), Ended::Exited, Some(0)));
}

// ---------------------------------------------------------------------------------------------------------------------------------
// The test bodies, run by `toy` and by `pam` below.

fn password_login_succeeds(subject: &Subject) {
    let auth = VaultAuth::new().with_password(&subject.password);
    let session = open_session_to(&engine(), &subject.target_on(subject.port, AuthMethod::Password), &auth);
    ok_output(session.as_ref());
    assert_eq!(auth.password_asked_for().len(), 1);
    assert!(auth.prompts_seen().is_empty(), "keyboard-interactive was not needed");
}

/// A refused password is not the end: the sequence goes on to keyboard-interactive, which the server offers too.
fn a_wrong_password_is_refused_and_keyboard_interactive_is_tried_next(subject: &Subject) {
    let auth = VaultAuth::new().with_password("not the password").with_answers(&["not the password"]);
    let error = engine().connect(&subject.target_on(subject.port, AuthMethod::Password), &*TestPolicy::trusting(), &auth).err().expect("wrong credentials");
    assert!(matches!(&error, ConnectError::AuthFailed { tried, .. } if *tried == [AuthMethod::Password, AuthMethod::Interactive]), "{error:?}");
    assert_eq!((auth.password_asked_for().len(), auth.prompts_seen().len()), (1, 1));
}

fn keyboard_interactive_login_succeeds(subject: &Subject) {
    let auth = VaultAuth::new().with_answers(&[&subject.password]);
    let session = open_session_to(&engine(), &subject.target_on(subject.port, AuthMethod::Interactive), &auth);
    ok_output(session.as_ref());
    let prompts = auth.prompts_seen();
    assert_eq!(prompts.len(), 1, "one round of questions: {prompts:?}");
    assert!(prompts[0][0].text.contains("assword") && !prompts[0][0].echo, "{:?}", prompts[0][0]);
}

/// The host's key is not accepted by the server: the key method is refused without a signature, and the sequence falls back to the password.
fn a_refused_key_falls_back_to_the_password(subject: &Subject) {
    let Some(tools) = tools() else { return };
    let keys = tempfile::tempdir().unwrap();
    let stranger = generate_key(&tools, keys.path(), "stranger", KeyKind::Ed25519);
    let auth = VaultAuth::new().with_key("k1", &stranger.private_text).with_password(&subject.password);
    let session = open_session_to(&engine(), &subject.target_on(subject.port, AuthMethod::Key { key_id: "k1".into() }), &auth);
    ok_output(session.as_ref());
    assert_eq!(auth.password_asked_for().len(), 1, "the password was asked for after the key was refused");
}

/// Review focus: the user cancels the prompt. The login is abandoned with a clear error and the connection is dropped, not left waiting.
fn a_cancelled_prompt_abandons_the_login_and_drops_the_connection(subject: &Subject) {
    let proxy = Proxy::start(subject.port);
    let auth = VaultAuth::new();
    let started = Instant::now();
    let error = engine().connect(&subject.target_on(proxy.port, AuthMethod::Interactive), &*TestPolicy::trusting(), &auth).err().expect("nobody answered");
    assert!(matches!(&error, ConnectError::AuthAbandoned { hop, .. } if hop.alias == "login"), "{error:?}");
    assert!(started.elapsed() < Duration::from_secs(10), "no waiting: {:?}", started.elapsed());
    eventually("the proxy to see the connection dropped", 5, || proxy.open_connections() == 0);
}

/// Review focus: the prompt takes longer than the engine will wait (here 1 s instead of the minute it is by default). A source that
/// behaves, like the broker, gives up at the deadline; one that answers late anyway is not believed either.
fn a_prompt_that_runs_out_of_time_abandons_the_login_and_drops_the_connection(subject: &Subject) {
    let engine = engine_with_prompt_wait(Duration::from_secs(1));
    for (label, auth) in [
        ("gives up at the deadline", VaultAuth::new().with_answers(&[&subject.password]).with_answer_delay(Duration::from_secs(5))),
        ("answers after the deadline", VaultAuth::new().with_answers(&[&subject.password]).with_answer_delay(Duration::from_millis(2500)).overrunning_the_deadline()),
    ] {
        let proxy = Proxy::start(subject.port);
        let started = Instant::now();
        let error = engine.connect(&subject.target_on(proxy.port, AuthMethod::Interactive), &*TestPolicy::trusting(), &auth).err().expect("the prompt ran out of time");
        let waited = started.elapsed();
        fact(&format!("prompt_timeout.{}.waited_ms", label.replace(' ', "_")), waited.as_millis());
        assert!(matches!(error, ConnectError::AuthAbandoned { .. }), "{label}: {error:?}");
        assert!(waited >= Duration::from_millis(900) && waited < Duration::from_secs(8), "{label}: waited {waited:?}");
        eventually("the proxy to see the connection dropped", 5, || proxy.open_connections() == 0);
    }
}

/// Review focus: a person is thinking about a prompt. russh's session is blocked inside the login while the engine waits, so the keepalive
/// timer does not turn into a busy loop. Measured in a child process, because the CPU time of a process is only meaningful when nothing else runs.
#[cfg(unix)]
fn waiting_for_a_prompt_costs_no_cpu(subject: &Subject, test: &str) {
    use crate::ssh::testing::{cpu_time_ms, fact_in, is_child, rerun_alone};

    if !is_child() {
        let output = rerun_alone(test);
        let used: u128 = fact_in(&output, "prompt_wait.cpu_ms").expect("the child measured").parse().expect("a number");
        assert!(used < 500, "2 s of waiting for a prompt used {used} ms of CPU");
        return;
    }
    let mut hop = subject.hop_on(subject.port, AuthMethod::Interactive);
    hop.keepalive_every = Duration::from_secs(1);
    let auth = VaultAuth::new().with_answers(&[&subject.password]).with_answer_delay(Duration::from_millis(3500));
    std::thread::scope(|scope| {
        let login = scope.spawn(|| engine().connect(&Target { hops: vec![hop] }, &*TestPolicy::trusting(), &auth).map(|session| session.is_alive()));
        std::thread::sleep(Duration::from_millis(1000));
        let before = cpu_time_ms();
        std::thread::sleep(Duration::from_millis(2000));
        fact("prompt_wait.cpu_ms", cpu_time_ms() - before);
        assert!(login.join().unwrap().expect("the login succeeded in the end"));
    });
}

// ---------------------------------------------------------------------------------------------------------------------------------

macro_rules! login_tests {
    ($server:ident) => {
        mod $server {
            use super::*;

            #[test]
            fn a_password_login_succeeds() {
                let Some(subject) = $server() else { return };
                password_login_succeeds(&subject);
            }

            #[test]
            fn a_wrong_password_is_refused_and_keyboard_interactive_is_tried_next() {
                let Some(subject) = $server() else { return };
                super::a_wrong_password_is_refused_and_keyboard_interactive_is_tried_next(&subject);
            }

            #[test]
            fn a_keyboard_interactive_login_succeeds() {
                let Some(subject) = $server() else { return };
                keyboard_interactive_login_succeeds(&subject);
            }

            #[test]
            fn a_refused_key_falls_back_to_the_password() {
                let Some(subject) = $server() else { return };
                super::a_refused_key_falls_back_to_the_password(&subject);
            }

            #[test]
            fn a_cancelled_prompt_abandons_the_login_and_drops_the_connection() {
                let Some(subject) = $server() else { return };
                super::a_cancelled_prompt_abandons_the_login_and_drops_the_connection(&subject);
            }

            #[test]
            fn a_prompt_that_runs_out_of_time_abandons_the_login_and_drops_the_connection() {
                let Some(subject) = $server() else { return };
                super::a_prompt_that_runs_out_of_time_abandons_the_login_and_drops_the_connection(&subject);
            }

            #[cfg(unix)]
            #[test]
            fn waiting_for_a_prompt_costs_no_cpu() {
                let Some(subject) = $server() else { return };
                super::waiting_for_a_prompt_costs_no_cpu(&subject, concat!("ssh::engine_tests::login_methods::", stringify!($server), "::waiting_for_a_prompt_costs_no_cpu"));
            }
        }
    };
}

login_tests!(toy);
login_tests!(pam);

#[test]
fn a_closed_session_after_a_login_says_so() {
    let Some(subject) = toy() else { return };
    let auth = VaultAuth::new().with_password(&subject.password);
    let session = open_session_to(&engine(), &subject.target_on(subject.port, AuthMethod::Password), &auth);
    session.close();
    assert_eq!(session.exec("echo no", Duration::from_secs(5), MIB), Err(SessionError::Closed));
}
