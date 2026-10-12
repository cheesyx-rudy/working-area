"""Small stage plugin registry: modules are discovered automatically by filename."""
from __future__ import annotations
import importlib, pkgutil
from pathlib import Path

def discover(package_name="modules"):
    package = importlib.import_module(package_name)
    stages = {}
    for item in pkgutil.iter_modules(package.__path__):
        if item.name.startswith("_") or item.name == "registry":
            continue
        module = importlib.import_module(f"{package_name}.{item.name}")
        name = getattr(module, "STAGE_NAME", None)
        runner = getattr(module, "run_stage", None)
        if name and callable(runner):
            if name in stages: raise RuntimeError(f"Duplicate plugin stage: {name}")
            stages[name] = runner
    return stages
