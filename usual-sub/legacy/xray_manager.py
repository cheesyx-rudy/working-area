"""Xray binary discovery and process lifecycle helpers; no URI-to-config logic."""
from __future__ import annotations
import os, shutil, subprocess
from pathlib import Path

def resolve_binary(explicit=None):
    candidate = explicit or os.environ.get("XRAY_BINARY") or shutil.which("xray")
    if not candidate: raise RuntimeError("Xray binary not found; set XRAY_BINARY or --xray-binary")
    path = Path(candidate)
    if not path.exists() or not path.is_file(): raise RuntimeError(f"Xray binary does not exist: {candidate}")
    return str(path)

def version(binary=None):
    binary = resolve_binary(binary)
    result = subprocess.run([binary, "version"], capture_output=True, text=True, timeout=5)
    if result.returncode: raise RuntimeError(result.stderr.strip() or "Xray version command failed")
    return result.stdout.strip()

def test_config(binary, config_path, timeout=5):
    return subprocess.run([resolve_binary(binary), "run", "-test", "-config", str(config_path)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout)
