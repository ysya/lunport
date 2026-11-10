#!/usr/bin/env python3
"""Verify the frozen credential bridge: source, bytes, both architectures, hardened runtime, no
entitlements, and the previous project certificate that helper v1 requires of its parent.

Usage: verify-credential-bridge.py [directory]  (this directory, the committed bridge, by default)
"""
import hashlib
import json
from pathlib import Path
import plistlib
import re
import subprocess
import sys
import tempfile

here = Path(__file__).resolve().parent
directory = Path(sys.argv[1]) if len(sys.argv) > 1 else here
binary = directory / "credential-bridge.bin"
source = directory / "credential-bridge.c"
manifest = json.loads((directory / "credential-bridge.json").read_text())
# The app identifier and certificate leaf of the releases before 2.0.0: helper v1 accepts only a
# parent with both, and the app requires both of the bridge (with its code hashes).
IDENTIFIER = "org.homelab.sshelter"
LEAF_SHA1 = "a346b47b8dccb4faeac8aec1ea997535809aeec9"

def run(*args):
    try:
        return subprocess.check_output(args, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as failure:
        raise SystemExit(failure.output.decode(errors="replace")) from None

def require(condition, message):
    if not condition:
        raise SystemExit(message)

require(manifest["protocol"] == 1 and manifest["identifier"] == IDENTIFIER, "Unexpected bridge protocol/identifier")
require(hashlib.sha256(binary.read_bytes()).hexdigest() == manifest["artifact_sha256"], "Frozen bridge artifact changed")
require(hashlib.sha256(source.read_bytes()).hexdigest() == manifest["source_sha256"], "Frozen bridge source changed; a new bridge needs the previous certificate again")
require(source.read_bytes() == (here / "credential-bridge.c").read_bytes(), "Candidate source differs from this checkout")
certificate = run("/usr/bin/openssl", "x509", "-in", str(here / "macos-project.pem"), "-outform", "DER")
pin = hashlib.sha256(certificate).hexdigest()
require(hashlib.sha1(certificate).hexdigest() == LEAF_SHA1, "The previous project certificate kept here is not the one the app pins")
required = f'identifier "{IDENTIFIER}" and certificate leaf = H"{LEAF_SHA1}"'
run("codesign", "--verify", "--strict", "--all-architectures", "--test-requirement", "=" + required, str(binary))
with tempfile.TemporaryDirectory(prefix="lunport-bridge-verification-") as temporary:
    for arch in ["arm64", "x86_64"]:
        run("lipo", str(binary), "-verify_arch", arch)
        prefix = str(Path(temporary) / (arch + "-"))
        run("codesign", "--display", "--arch", arch, "--extract-certificates=" + prefix, str(binary))
        require(hashlib.sha256(Path(prefix + "0").read_bytes()).hexdigest() == pin, "Bridge certificate differs from the previous project pin")
        details = run("codesign", "--display", "--verbose=4", "--arch", arch, str(binary)).decode()
        flags = re.search(r"flags=0x([a-fA-F0-9]+)", details)
        require(flags and int(flags[1], 16) & 0x10000, "Bridge lacks hardened runtime")
        cdhash = next(line.removeprefix("CDHash=") for line in details.splitlines() if line.startswith("CDHash="))
        require(cdhash == manifest["cdhashes"][arch], "Bridge code hash differs from manifest")
        entitlements = subprocess.run(["codesign", "--display", "--arch", arch, "--entitlements", "-", "--xml", str(binary)],
                                      capture_output=True, check=True).stdout
        require(not (plistlib.loads(entitlements) if entitlements.strip() else {}), "Bridge must carry no entitlements")
print("Frozen universal credential bridge verified: " + manifest["artifact_sha256"])
