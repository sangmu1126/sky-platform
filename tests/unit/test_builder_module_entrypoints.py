"""The isolated workflow must resolve its trusted helper modules from checkout."""

import os
import re
import subprocess
import sys
from pathlib import Path


def test_workflow_helper_imports_work_in_a_clean_process():
    root = Path(__file__).resolve().parents[2]
    workflow = (root / "ops/remote-builder/build.yml").read_text()
    assert "python scripts/" not in workflow
    modules = sorted(set(re.findall(r"python -m (scripts\.[a-z_]+)", workflow)))
    assert "scripts.fetch_build_materials" in modules
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": str(root / "src"),
        "AWS_EC2_METADATA_DISABLED": "true",
    }
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import importlib,sys; [importlib.import_module(m) for m in sys.argv[1:]]",
            *modules,
        ],
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
