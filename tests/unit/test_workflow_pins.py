"""Executable third-party workflow dependencies must be immutable references."""

import re
from pathlib import Path


def test_all_checked_in_actions_and_reusable_workflows_use_full_commit_ids():
    for path in Path(".github/workflows").glob("*.yml"):
        for ref in re.findall(r"\buses:\s*([^\s#]+)", path.read_text()):
            if ref.startswith("./"):
                continue
            assert re.fullmatch(r"[A-Za-z0-9_./-]+@[0-9a-f]{40}", ref), (path.name, ref)
