#!/usr/bin/env python3
"""Verify frozen source, bytes, both architectures and the public project pin.

Usage: verify-macos-credential-helper.py [--version v1|v2] [--directory DIR]
Without arguments it checks the committed helper v1 in src-tauri/signing/legacy. Helper v2 is
committed in src-tauri/signing once it is frozen.
"""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import re
import subprocess
import tempfile

repo = Path(__file__).resolve().parent.parent
signing = repo / "src-tauri/signing"
parser = argparse.ArgumentParser(description="Verify a frozen macOS credential helper and its manifest.")
parser.add_argument("--version", choices=["v1", "v2"], default="v1", help="helper version (default: v1)")
parser.add_argument("--directory", type=Path,
                    help="directory with the .bin, .c and .json files (default: where that version is committed, "
                         "src-tauri/signing/legacy for v1 and src-tauri/signing for v2)")
arguments = parser.parse_args()

def require(condition, message):
    if not condition:
        raise SystemExit(message)

def run(*args):
    try:
        return subprocess.check_output(args, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as failure:
        raise SystemExit(failure.output.decode(errors="replace")) from None

def current_identity():
    """The current identity values, as scripts/identity.mjs prints them from the files the build reads."""
    try:
        result = subprocess.run(["node", str(repo / "scripts/identity.mjs")], capture_output=True, text=True)
    except FileNotFoundError:
        raise SystemExit("Node.js is needed to read scripts/identity.mjs") from None
    require(result.returncode == 0, result.stderr.strip() or "scripts/identity.mjs failed")
    return json.loads(result.stdout)

# What each version must be, never read from the manifest under test: the checkout's source,
# protocol, signing identifier, certificate leaf SHA-1 and the public certificate kept in the
# repository.
if arguments.version == "v1":
    # Frozen, signed with the identifier and the project certificate of the releases before 2.0.0.
    # frozen-identity: helper v1 is frozen, and its identifier is part of its signature
    identifier, leaf_sha1 = "org.homelab.sshelter.credential-helper.v1", "a346b47b8dccb4faeac8aec1ea997535809aeec9"
    committed, protocol, public_certificate = signing / "legacy", 1, signing / "legacy/macos-project.pem"
else:
    # The identifier the app pins helper v2 to (src-tauri/src/identity.rs, which a committed manifest must match).
    identifier, leaf_sha1 = current_identity()["helperV2"]["identifier"], "66f062921154fb6fe72e7ee0dfe99d7d804efb03"
    committed, protocol, public_certificate = signing, 2, signing / "macos-project.pem"

certificate = run("/usr/bin/openssl", "x509", "-in", str(public_certificate), "-outform", "DER")
pin = hashlib.sha256(certificate).hexdigest()
require(hashlib.sha1(certificate).hexdigest() == leaf_sha1,
        f"{public_certificate.relative_to(repo)} is not the certificate helper {arguments.version} must be signed with")
name = "credential-helper-" + arguments.version
checkout_source = committed / (name + ".c")
directory = arguments.directory or committed
binary, source, manifest_file = (directory / (name + suffix) for suffix in (".bin", ".c", ".json"))
missing = [path.name for path in (binary, source, manifest_file) if not path.is_file()]
require(not missing, f"{directory} lacks {', '.join(missing)}")
manifest = json.loads(manifest_file.read_text())

require(manifest["protocol"] == protocol and manifest["identifier"] == identifier, "Unexpected helper protocol/identifier")
require(hashlib.sha256(binary.read_bytes()).hexdigest() == manifest["artifact_sha256"], "Frozen helper artifact changed")
require(hashlib.sha256(source.read_bytes()).hexdigest() == manifest["source_sha256"], "Frozen helper source changed; use a deliberate new helper version")
require(source.read_bytes() == checkout_source.read_bytes(), "Candidate source differs from this checkout")
required = f'identifier "{identifier}" and certificate leaf = H"{leaf_sha1}"'
run("codesign", "--verify", "--strict", "--all-architectures", "--test-requirement", "=" + required, str(binary))
with tempfile.TemporaryDirectory(prefix="lunport-helper-verification-") as temporary:
    for arch in ["arm64", "x86_64"]:
        run("lipo", str(binary), "-verify_arch", arch)
        prefix = str(Path(temporary) / (arch + "-"))
        run("codesign", "--display", "--arch", arch, "--extract-certificates=" + prefix, str(binary))
        require(hashlib.sha256(Path(prefix + "0").read_bytes()).hexdigest() == pin, "Helper certificate differs from the project pin")
        details = run("codesign", "--display", "--verbose=4", "--arch", arch, str(binary)).decode()
        flags = re.search(r"flags=0x([a-fA-F0-9]+)", details)
        require(flags and int(flags[1], 16) & 0x10000, "Helper lacks hardened runtime")
        cdhash = next(line.removeprefix("CDHash=") for line in details.splitlines() if line.startswith("CDHash="))
        require(cdhash == manifest["cdhashes"][arch], "Helper code hash differs from manifest")
        entitlements = subprocess.run(["codesign", "--display", "--arch", arch, "--entitlements", "-", "--xml", str(binary)],
                                      capture_output=True, check=True).stdout
        require(not (plistlib.loads(entitlements) if entitlements.strip() else {}), "Helper must carry no entitlements")
print("Frozen universal credential helper verified: " + manifest["artifact_sha256"])
