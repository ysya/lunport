"""Upgrade the published 1.14.4 DEB and RPM to this build's packages on an ephemeral Linux CI runner, without a GUI.

The current names come from scripts/identity.mjs (the Tauri configuration), the names 1.14.4 used from scripts/legacy-identity.json.
The DEB is installed for real and then started once through the command line, which moves the application data; the RPM transaction
runs in a scratch root.
"""
from pathlib import Path
import hashlib
import json
import os
import subprocess

if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_OS") != "Linux":
    raise SystemExit("This package upgrade check runs only on a disposable Linux CI runner.")

repository = Path(__file__).resolve().parent.parent


def run(*args, capture=False):
    return subprocess.run(args, check=True, text=True, capture_output=capture)


current = json.loads(run("node", str(repository / "scripts/identity.mjs"), capture=True).stdout)["production"]
legacy = json.loads((repository / "scripts/legacy-identity.json").read_text())["production"]
linux = json.loads((repository / "src-tauri/tauri.conf.json").read_text())["bundle"]["linux"]

baseline = "v1.14.4"
scratch = Path(os.environ["RUNNER_TEMP"]) / "lunport-upgrade"
scratch.mkdir()
baseline_deb, baseline_rpm = scratch / "Lunport_1.14.4_amd64.deb", scratch / "Lunport-1.14.4-1.x86_64.rpm"
release = json.loads(run("gh", "api", f"repos/{os.environ['GITHUB_REPOSITORY']}/releases/tags/{baseline}", capture=True).stdout)
for path in [baseline_deb, baseline_rpm]:
    run("gh", "release", "download", baseline, "--repo", os.environ["GITHUB_REPOSITORY"], "--pattern", path.name, "--dir", str(scratch))
    asset = next(a for a in release["assets"] if a["name"] == path.name)
    assert asset["digest"] == "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(), f"{path.name} differs from the release"

bundles = repository / "src-tauri/target/release/bundle"
debs = list((bundles / "deb").glob("*.deb"))
rpms = list((bundles / "rpm").glob("*.rpm"))
assert len(debs) == len(rpms) == 1
candidate_deb, candidate_rpm = debs[0].resolve(), rpms[0].resolve()


def deb_field(package_file, name):
    return run("dpkg-deb", "-f", str(package_file), name, capture=True).stdout.strip()


# The candidate takes the place of the 1.14.4 package under the same name. Its relations to the package names from before 1.1 are the
# ones the Tauri configuration declares.
package = deb_field(candidate_deb, "Package")
assert package == deb_field(baseline_deb, "Package"), f"{package} does not replace the 1.14.4 package in place"
for relation in ["provides", "conflicts", "replaces"]:
    declared = deb_field(candidate_deb, relation.capitalize()).split(", ")
    for name in linux["deb"].get(relation, []):
        assert name in declared, f"the package does not declare {relation.capitalize()}: {name}"

data_home = Path(os.environ["XDG_DATA_HOME"]) if os.environ.get("XDG_DATA_HOME", "").startswith("/") else Path.home() / ".local/share"
old_data, new_data = data_home / legacy["appId"], data_home / current["appId"]
old_sentinel, new_sentinel = old_data / "upgrade-sentinel.txt", new_data / "upgrade-sentinel.txt"
old_data.mkdir(parents=True, exist_ok=True)
old_sentinel.write_text("disposable nonsecret upgrade fixture")
before = old_sentinel.read_bytes()
binaries = Path("/usr/bin")

run("sudo", "apt-get", "install", "-y", str(baseline_deb))
assert (binaries / legacy["mainBinary"]).is_file(), "1.14.4 installs its executable under its own name"
# dpkg rather than apt: until the release PR raises it, the candidate carries the version of the baseline, which apt would skip as
# installed. dpkg unpacks it over the installed package either way and removes the files the candidate no longer has.
run("sudo", "dpkg", "-i", str(candidate_deb))
status = run("dpkg-query", "-W", "-f", "${Status} ${Version}", package, capture=True).stdout.strip()
assert status == f"install ok installed {deb_field(candidate_deb, 'Version')}", status
assert (binaries / current["mainBinary"]).is_file(), f"no {binaries / current['mainBinary']}"
assert not (binaries / legacy["mainBinary"]).exists(), "the executable of 1.14.4 is still installed"
assert old_sentinel.read_bytes() == before and not new_data.exists(), "installing the package changed application data"

desktop_file = next(Path(p) for p in run("dpkg-query", "-L", package, capture=True).stdout.splitlines() if p.endswith(".desktop"))
desktop = {}
for line in desktop_file.read_text().splitlines():
    if "=" in line and not line.startswith("#"):
        key, value = line.split("=", 1)
        desktop.setdefault(key, value)
assert desktop["Name"] == current["productName"], desktop
assert Path(desktop["Exec"].split()[0]).name == current["mainBinary"], desktop

# The first start, through the command line: `connect` without an alias moves what 1.14.4 left to the current identity before anything
# else, then prints its usage.
client = subprocess.run([str(binaries / current["mainBinary"]), "connect"], text=True, capture_output=True)
assert client.returncode == 2 and f"usage: {current['mainBinary']} connect <alias>" in client.stderr, client
assert new_sentinel.read_bytes() == before, "the first start did not move the application data"
assert not old_sentinel.exists(), "the first start left the application data in the folder of 1.14.4"

# RPM replacement checks package ownership without claiming runtime coverage for an RPM distribution. No dependency scripts are run by
# these Tauri packages.
rpm_root = scratch / "rpm-root"
rpm_root.mkdir()


def rpm(*args, capture=False):
    return run("sudo", "rpm", "--root", str(rpm_root), *args, capture=capture)


def rpm_tags(package_file, tags):
    return rpm("-qp", "--qf", tags, str(package_file), capture=True).stdout


rpm("--initdb")
rpm_name = rpm_tags(candidate_rpm, "%{NAME}")
assert rpm_name == rpm_tags(baseline_rpm, "%{NAME}"), f"{rpm_name} does not replace the 1.14.4 package in place"
for relation in ["provides", "conflicts", "obsoletes"]:
    listed = rpm("-qp", f"--{relation}", str(candidate_rpm), capture=True).stdout.splitlines()
    declared = [line.split()[0] for line in listed if line.strip()]
    for name in linux["rpm"].get(relation, []):
        assert name in declared, f"the package does not declare {relation}: {name}"
rpm("-i", "--nodeps", str(baseline_rpm))
assert (rpm_root / "usr/bin" / legacy["mainBinary"]).is_file()
evr = "%{EPOCH}:%{VERSION}-%{RELEASE}"
candidate_evr = rpm_tags(candidate_rpm, evr)
# At the installed version, -U refuses the candidate as already installed (same name, version and release); --reinstall replaces it.
rpm("--reinstall" if candidate_evr == rpm_tags(baseline_rpm, evr) else "-U", "--nodeps", str(candidate_rpm))
assert rpm("-q", "--qf", evr + "\\n", rpm_name, capture=True).stdout.split() == [candidate_evr]
assert (rpm_root / "usr/bin" / current["mainBinary"]).is_file()
assert not (rpm_root / "usr/bin" / legacy["mainBinary"]).exists()
print(f"The published 1.14.4 DEB and RPM upgrade to this build's {package} in place; its first start moved the application data.")
