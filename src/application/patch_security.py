"""Conservative deployment-patch gates, not a semantic malware/authentication proof."""

import json
import re
from pathlib import PurePosixPath


def check_patch_security(path, before, after):
    name = PurePosixPath(path).name
    if PurePosixPath(path).suffix == ".py":
        from application.patch_invariants import check_python_patch

        check_python_patch(before, after)
    if name == "package.json":
        original, candidate = json.loads(before or "{}"), json.loads(after)
        for value in (original, candidate):
            if not isinstance(value, dict) or not isinstance(value.get("scripts", {}), dict):
                raise ValueError("Package script configuration must be an object")
        hooks = {"preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishOnly",
                 "prepack", "postpack", "publish", "postpublish"}
        for hook in hooks:
            if candidate.get("scripts", {}).get(hook) != original.get("scripts", {}).get(hook):
                raise ValueError("Security policy rejects automatic install/publish hook changes")
    if name == "Dockerfile":
        users = lambda text: re.findall(r"(?im)^\s*USER\s+([^\s#]+)", text)
        old_users, new_users = users(before), users(after)
        if (old_users and old_users[-1] not in {"root", "0", "0:0"}
                and (not new_users or new_users[-1] in {"root", "0", "0:0"})):
            raise ValueError("Security policy rejects removing the non-root runtime user")
        remote_add = r"(?im)^\s*ADD\s+[^\n]*(?:https?://|git@|git://)"
        if re.search(remote_add, after) and not re.search(remote_add, before):
            raise ValueError("Security policy rejects introducing remote Docker ADD")
    patterns = (
        r"NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*['\"]?0",
        r"rejectUnauthorized\s*:\s*false",
        r"\bverify\s*=\s*False\b",
        r"sslmode\s*[:=]\s*['\"]?(?:disable|allow|prefer)\b",
    )
    for pattern in patterns:
        if len(re.findall(pattern, after)) > len(re.findall(pattern, before)):
            raise ValueError("Security policy rejects introducing disabled TLS verification")
