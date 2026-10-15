#!/usr/bin/env python3
"""Exercise the built Development helper without changing system audio or app data."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("executable", type=Path, help="Built Development sshelter executable")
args = parser.parse_args()
exe = str(args.executable.resolve(strict=True))
env = os.environ.copy()
env.pop("SSHELTER_ASKPASS", None)
env.pop("SSHELTER_TEST_COREAUDIO_FILE", None)


def check(expected):
    began = time.monotonic()
    result = subprocess.run([exe, "--check-window-health"], env=env,
                            capture_output=True, text=True, timeout=6)
    elapsed = time.monotonic() - began
    assert "Profile: Development" in result.stdout, "Use an isolated Development build"
    assert result.returncode == expected, (result.stdout, result.stderr)
    print(f"{elapsed:.3f}s {result.stdout.strip()}")
    return elapsed, result.stdout


check(0)  # Real, bounded CoreAudio query; proves a response, not GPU rendering.
with tempfile.TemporaryDirectory(prefix="sshelter-guard-") as directory:
    fault = Path(directory) / "fault.txt"
    env["SSHELTER_TEST_COREAUDIO_FILE"] = str(fault)
    for mode, expected in [("success", 0), ("error", 1), ("timeout", 1), ("success", 0)]:
        fault.write_text(mode + "\n")
        elapsed, output = check(expected)
        if mode == "timeout":
            assert 2 <= elapsed < 4, (elapsed, output)
            assert "Timeout" in output

    # GUI health must not run in CLI Connect or ASKPASS helper modes.
    fault.write_text("timeout\n")
    result = subprocess.run([exe, "connect", "--help"], env=env,
                            capture_output=True, text=True, timeout=2)
    assert result.returncode in (0, 2) and "window-health" not in result.stderr
    assert "connect" in result.stdout + result.stderr
    askpass_env = dict(env, SSHELTER_ASKPASS="1", SSHELTER_ASKPASS_SECRET="DUMMY_HEALTH_TEST")
    result = subprocess.run([exe, "probe@localhost's password: "], env=askpass_env,
                            capture_output=True, text=True, timeout=2)
    assert result.returncode == 0 and result.stdout == "DUMMY_HEALTH_TEST\n"
    assert "window-health" not in result.stderr
    for challenge in ("--coreaudio-probe", "--check-window-health"):
        result = subprocess.run([exe, challenge], env=askpass_env,
                                capture_output=True, text=True, timeout=2)
        assert result.returncode == 1 and result.stdout == "", challenge
    result = subprocess.run([exe, "--coreaudio-probe"], env=env,
                            capture_output=True, timeout=4)
    assert result.returncode == -14, "The orphan-helper watchdog must terminate a stuck query"
    print("CLI Connect help and ASKPASS bypassed the GUI health gate.")

print("Helper scenarios passed. Native alerts, visible pixels, background broker, and real sleep/wake require the separate device checklist.")
