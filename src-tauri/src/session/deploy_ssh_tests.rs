//! Production POSIX installer over the own engine's no-PTY exec to a disposable OpenSSH server.
//! This fixture supports macOS/Linux servers, not remote Windows or Windows-to-POSIX runtime coverage.

use super::{classify, script, Outcome};
use crate::ssh::russh_engine::{EngineOptions, RusshEngine};
use crate::ssh::testing::doubles::TestPolicy;
use crate::ssh::testing::fixture::{Server, SH_SHELL};
use crate::ssh::testing::harness::tools;
use crate::ssh::{Ended, ExecResult, Session, SshEngine};
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    time::Duration,
};

fn install(session: &dyn Session, home: &tempfile::TempDir, public: &str) -> ExecResult {
    // Server isolates sshd's authorized_keys, but NOT the login shell's HOME. Always override
    // HOME in the remote command, with POSIX quoting, before invoking the actual generator.
    let home = home.path().to_str().expect("UTF-8 scratch HOME");
    let command = format!(
        "HOME='{}'; export HOME; [ ! -t 0 ] && [ ! -t 1 ] && [ ! -t 2 ] || exit 71; {}",
        home.replace('\'', "'\\''"),
        script(public).expect("the fixture public key generates an installer")
    );
    let result = session
        .exec(&command, Duration::from_secs(60), 8192)
        .expect("the production installer executes through the own engine");
    assert_eq!(result.ended, Ended::Exited, "{result:?}");
    assert_eq!(result.signal, None);
    assert!(!result.truncated);
    result
}

#[test]
fn real_ssh_installer_preserves_bytes_is_idempotent_and_refuses_symlinks() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[SH_SHELL]);
    let engine = RusshEngine::with_options(EngineOptions {
        worker_threads: 2,
        ..EngineOptions::default()
    });
    let session = engine
        .connect(
            &server.target("k1"),
            &*TestPolicy::trusting(),
            &server.vault("k1"),
        )
        .expect("connect using only the disposable fixture key");

    // Exercise both spaces and single quotes in the explicit remote HOME assignment.
    let home = tempfile::Builder::new()
        .prefix("sshelter deploy's HOME ")
        .tempdir()
        .unwrap();
    let ssh = home.path().join(".ssh");
    let authorized = ssh.join("authorized_keys");
    fs::create_dir(&ssh).unwrap();
    let original = b"# original sentinel\r\n# unterminated sentinel";
    fs::write(&authorized, original).unwrap();
    fs::set_permissions(&ssh, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(&authorized, fs::Permissions::from_mode(0o644)).unwrap();
    // ssh-keygen in the shared fixture supplies this fixed comment. Expect the public identity
    // independently of deploy::canonical, so retaining the comment is an observable failure.
    let public = server
        .key
        .public_line
        .strip_suffix(" sshelter-test")
        .unwrap();
    let expected = [original.as_slice(), b"\n", public.as_bytes(), b"\n"].concat();

    let first = install(&*session, &home, &server.key.public_line);
    assert_eq!(first.exit_code, Some(0));
    assert_eq!(first.stdout, b"SSHELTER_ADDED\n");
    assert!(first.stderr.is_empty());
    assert_eq!(classify(&first), Outcome::Added);
    assert_eq!(fs::read(&authorized).unwrap(), expected);
    assert_eq!(
        fs::metadata(&ssh).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(&authorized).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let second = install(&*session, &home, &server.key.public_line);
    assert_eq!(second.exit_code, Some(0));
    assert_eq!(second.stdout, b"SSHELTER_PRESENT\n");
    assert!(second.stderr.is_empty());
    assert_eq!(classify(&second), Outcome::AlreadyPresent);
    let bytes = fs::read(&authorized).unwrap();
    assert_eq!(bytes, expected, "the repeat must preserve every byte");
    assert_eq!(
        String::from_utf8(bytes)
            .unwrap()
            .lines()
            .filter(|line| *line == public)
            .count(),
        1
    );
    assert_eq!(
        fs::metadata(&ssh).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(&authorized).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let refused_home = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let target = outside.path().join("target");
    let target_bytes = b"# untouched symlink target without newline";
    fs::write(&target, target_bytes).unwrap();
    fs::create_dir(refused_home.path().join(".ssh")).unwrap();
    let linked = refused_home.path().join(".ssh/authorized_keys");
    symlink(&target, &linked).unwrap();
    let refused = install(&*session, &refused_home, &server.key.public_line);
    assert_eq!(refused.exit_code, Some(70));
    assert!(refused.stdout.is_empty());
    assert_eq!(classify(&refused), Outcome::RemoteFailed);
    assert_eq!(fs::read(&target).unwrap(), target_bytes);
    assert!(fs::symlink_metadata(linked)
        .unwrap()
        .file_type()
        .is_symlink());
    session.close();
}
