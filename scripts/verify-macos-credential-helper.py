#!/usr/bin/env python3
"""Verify frozen source, bytes, both architectures and the public project pin."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

repo = Path(__file__).resolve().parent.parent
directory = Path(sys.argv[1]) if len(sys.argv) > 1 else repo / "src-tauri/signing"
binary = directory / "credential-helper-v1.bin"
source = directory / "credential-helper-v1.c"
manifest = json.loads((directory / "credential-helper-v1.json").read_text())

def run(*args):
    try:
        return subprocess.check_output(args, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as failure:
        raise SystemExit(failure.output.decode(errors="replace")) from None

def require(condition, message):
    if not condition:
        raise SystemExit(message)

require(manifest["protocol"] == 1 and manifest["identifier"] == "org.homelab.sshelter.credential-helper.v1", "Unexpected helper protocol/identifier")
require(hashlib.sha256(binary.read_bytes()).hexdigest() == manifest["artifact_sha256"], "Frozen helper artifact changed")
require(hashlib.sha256(source.read_bytes()).hexdigest() == manifest["source_sha256"], "Frozen helper source changed; use a deliberate new helper version")
require(source.read_bytes() == (repo / "src-tauri/signing/credential-helper-v1.c").read_bytes(), "Candidate source differs from this checkout")
certificate = run("/usr/bin/openssl", "x509", "-in", str(repo / "src-tauri/signing/macos-project.pem"), "-outform", "DER")
pin = hashlib.sha256(certificate).hexdigest()
sha1 = hashlib.sha1(certificate).hexdigest()
required = f'identifier "{manifest["identifier"]}" and certificate leaf = H"{sha1}"'
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
print("Frozen universal credential helper verified: " + manifest["artifact_sha256"])
