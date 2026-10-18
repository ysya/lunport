#!/usr/bin/env python3
"""Disposable, loopback-only OpenSSH target for the embedded-terminal preview.

Uses throwaway keys and an empty temporary HOME, never ~/.ssh or real passwords.
Keep this process running while trying the preview. Ctrl-C stops its SSH sessions
and removes the fixture. Requires a local OpenSSH sshd and ssh-keygen (macOS/Linux).
"""
import getpass
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import tempfile


def descendants(pid):
    rows = subprocess.check_output(["ps", "-axo", "pid=,ppid="], text=True)
    children = {}
    for row in rows.splitlines():
        child, parent = map(int, row.split())
        children.setdefault(parent, []).append(child)
    result, pending = [], [pid]
    while pending:
        found = children.get(pending.pop(), [])
        result.extend(found)
        pending.extend(found)
    return result


def main():
    sshd = shutil.which("sshd") or next((p for p in ["/usr/sbin/sshd", "/opt/homebrew/sbin/sshd"] if Path(p).exists()), None)
    if not sshd or not shutil.which("ssh-keygen"):
        raise SystemExit("Install OpenSSH sshd and ssh-keygen first.")
    with tempfile.TemporaryDirectory(prefix="lunport-terminal-preview-") as temporary:
        root = Path(temporary)
        os.chmod(root, 0o700)
        for name in ["host", "preview_key"]:
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "lunport-disposable-preview", "-f", str(root / name)], check=True)
        (root / "authorized_keys").write_text((root / "preview_key.pub").read_text())
        os.chmod(root / "authorized_keys", 0o600)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        (root / "ssh_config").write_text(f"Host terminal-preview\n  HostName 127.0.0.1\n  User {getpass.getuser()}\n  Port {port}\n  IdentityFile {root / 'preview_key'}\n")
        config = root / "sshd_config"
        config.write_text(f'''ListenAddress 127.0.0.1
Port {port}
HostKey "{root / 'host'}"
AuthorizedKeysFile "{root / 'authorized_keys'}"
PidFile none
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
StrictModes no
PermitUserRC no
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitTunnel no
LogLevel ERROR
ForceCommand /usr/bin/env -i HOME="{root}" USER={getpass.getuser()} LOGNAME={getpass.getuser()} PATH=/usr/bin:/bin TERM=xterm-256color LANG=en_US.UTF-8 PS1='preview $ ' /bin/sh -i
''')
        subprocess.run([sshd, "-t", "-f", str(config)], check=True)
        server = subprocess.Popen([sshd, "-D", "-e", "-f", str(config)], start_new_session=True)
        print(f"REAL SSH preview: {getpass.getuser()}@127.0.0.1:{port}", flush=True)
        print(f"Import config: {root / 'ssh_config'}", flush=True)
        print(f"Or import key: {root / 'preview_key'}", flush=True)
        subprocess.run(["ssh-keygen", "-lf", str(root / "host.pub")], check=True)
        print("Keep this process running. Ctrl-C stops the server and all its sessions.", flush=True)
        try:
            server.wait()
        except KeyboardInterrupt:
            pass
        finally:
            if server.poll() is None:
                os.kill(server.pid, signal.SIGSTOP)
                family = descendants(server.pid)
                for pid in reversed(family + [server.pid]):
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                server.wait()


if __name__ == "__main__":
    main()
