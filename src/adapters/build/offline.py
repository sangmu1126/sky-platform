"""Operator-pinned cached bases and network-free RUN instructions.

This profile needs a disposable dedicated Docker daemon/VM. It does not isolate
the daemon from its host or restrict the daemon's own registry traffic. Dependencies
must already be in the approved base or source. Do not silently retry online.
"""

import re
import json


def validate_offline_dockerfile(dockerfile, bases, command):
    if (not isinstance(bases, dict) or not 1 <= len(bases) <= 16
            or any(not isinstance(name, str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_./:@-]{0,255}", name)
                   or not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
                   for name, digest in bases.items())):
        raise ValueError("Explicit cached offline base identities required")
    if re.search(r"(?im)^\s*#\s*(?:syntax|escape)\s*=", dockerfile):
        raise ValueError("Offline build cannot use an external or altered Dockerfile frontend")
    # Join Docker continuation lines before inspecting instructions.
    logical = re.sub(r"\\\s*\n", " ", dockerfile)
    if "<<" in logical:
        raise ValueError("Offline profile does not support Dockerfile heredocs")
    stages = set()
    selected = set()
    for raw in logical.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        instruction = parts[0].upper()
        arguments = parts[1].strip() if len(parts) == 2 else ""
        if instruction == "FROM":
            match = re.fullmatch(r"([^\s]+)(?:\s+[Aa][Ss]\s+([A-Za-z0-9_-]+))?", arguments)
            if not match:
                raise ValueError("Offline FROM must use a literal approved base")
            base, stage = match.groups()
            if base not in stages and base != "scratch":
                if base not in bases:
                    raise ValueError("Offline build base was not registered")
                selected.add(base)
            if stage:
                stages.add(stage)
        elif instruction == "ADD":
            # COPY suffices for the restricted profile; ADD supports remote sources and extraction.
            raise ValueError("Offline build requires COPY instead of ADD")
        elif instruction in {"ONBUILD", "ARG"}:
            raise ValueError("Offline build does not support dynamic or inherited build instructions")
        elif instruction == "RUN" and re.search(r"--(?:network|mount|security)\b", arguments):
            raise ValueError("Offline RUN cannot override network or mount policy")
        elif instruction == "COPY" and "--from=" in arguments:
            match = re.search(r"--from=([^\s]+)", arguments)
            if not match or match[1] not in stages:
                raise ValueError("Offline COPY cannot pull an external image")
    for base in sorted(selected):
        actual = command(["docker", "image", "inspect", "--format", "{{.Id}}", base]).strip()
        if actual != bases[base]:
            raise ValueError("Offline cached base identity differs from registration")
        config = json.loads(command(["docker", "image", "inspect", "--format", "{{json .Config}}", base]))
        if not isinstance(config, dict) or config.get("OnBuild") not in (None, []):
            raise ValueError("Offline cached base has inherited build triggers")
