"""Exercise package replacement on an ephemeral Linux CI runner, without a GUI."""
from pathlib import Path
import hashlib
import json
import os
import subprocess

if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_OS") != "Linux":
    raise SystemExit("This package upgrade check runs only on a disposable Linux CI runner.")


def run(*args, capture=False):
    return subprocess.run(args, check=True, text=True, capture_output=capture)


scratch = Path(os.environ["RUNNER_TEMP"]) / "lunport-upgrade"
scratch.mkdir()
release = json.loads(run("gh", "api", f"repos/{os.environ['GITHUB_REPOSITORY']}/releases/tags/v1.0.0", capture=True).stdout)
for name in ["SSHelter_1.0.0_amd64.deb", "SSHelter-1.0.0-1.x86_64.rpm"]:
    run("gh", "release", "download", "v1.0.0", "--repo", os.environ["GITHUB_REPOSITORY"], "--pattern", name, "--dir", str(scratch))
    asset = next(a for a in release["assets"] if a["name"] == name)
    assert asset["digest"] == "sha256:" + hashlib.sha256((scratch / name).read_bytes()).hexdigest()

debs = list(Path("src-tauri/target/release/bundle/deb").glob("*.deb"))
rpms = list(Path("src-tauri/target/release/bundle/rpm").glob("*.rpm"))
assert len(debs) == len(rpms) == 1
old_name = run("dpkg-deb", "-f", str(scratch / "SSHelter_1.0.0_amd64.deb"), "Package", capture=True).stdout.strip()
assert old_name == "ss-helter"
assert run("dpkg-deb", "-f", str(debs[0]), "Package", capture=True).stdout.strip() == "lunport"
for field in ["Provides", "Conflicts", "Replaces"]:
    assert old_name in run("dpkg-deb", "-f", str(debs[0]), field, capture=True).stdout.strip().split(", ")

sentinel = Path.home() / ".local/share/org.homelab.sshelter/rebrand-sentinel.txt"
sentinel.parent.mkdir(parents=True, exist_ok=True)
sentinel.write_text("disposable nonsecret upgrade fixture")
before = sentinel.read_bytes()
run("sudo", "apt-get", "install", "-y", str(scratch / "SSHelter_1.0.0_amd64.deb"))
run("sudo", "apt-get", "install", "-y", str(debs[0].resolve()))
dpkg_status = "$" + "{Status}"
status = subprocess.run(["dpkg-query", "-W", "-f", dpkg_status, old_name], text=True, capture_output=True)
assert status.stdout.strip() != "install ok installed"
assert run("dpkg-query", "-W", "-f", dpkg_status, "lunport", capture=True).stdout.strip() == "install ok installed"
assert sentinel.read_bytes() == before
client = subprocess.run(["/usr/bin/sshelter", "connect"], text=True, capture_output=True)
assert client.returncode == 2 and "usage: sshelter connect <alias>" in client.stderr
desktop_files = run("dpkg-query", "-L", "lunport", capture=True).stdout.splitlines()
desktop = next(Path(p) for p in desktop_files if p.endswith(".desktop"))
assert "Name=Lunport" in desktop.read_text()

# RPM replacement checks package ownership without claiming runtime coverage for
# an RPM distribution. No dependency scripts are run by these Tauri packages.
rpm_root = scratch / "rpm-root"
rpm_root.mkdir()
run("sudo", "rpm", "--root", str(rpm_root), "--initdb")
run("sudo", "rpm", "--root", str(rpm_root), "-i", "--nodeps", str(scratch / "SSHelter-1.0.0-1.x86_64.rpm"))
run("sudo", "rpm", "--root", str(rpm_root), "-U", "--nodeps", str(rpms[0].resolve()))
assert subprocess.run(["sudo", "rpm", "--root", str(rpm_root), "-q", old_name]).returncode != 0
run("sudo", "rpm", "--root", str(rpm_root), "-q", "lunport")
assert (rpm_root / "usr/bin/sshelter").is_file()
assert sentinel.read_bytes() == before
print("DEB and RPM replace ss-helter with lunport; existing data and CLI paths survive.")
