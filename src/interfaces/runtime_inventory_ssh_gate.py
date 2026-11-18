"""Forced-command gate for the dedicated runtime inventory SSH key."""

import os
import re
import shlex

from adapters.onprem.runtime_inventory import RUNTIME_HELPER_PATH

SUDO_PATH = "/usr/bin/sudo"


def validated_sudo_command(original_command):
    if not isinstance(original_command, str) or len(original_command.encode()) > 512:
        raise ValueError("Bounded SSH original command required")
    try:
        arguments = shlex.split(original_command, posix=True)
    except ValueError:
        raise ValueError("Invalid SSH original command") from None
    if (
        len(arguments) != 7
        or arguments[:4] != ["sudo", "-n", RUNTIME_HELPER_PATH, "--registration"]
        or not re.fullmatch(r"WRR-[a-f0-9]{64}", arguments[4])
        or arguments[5:] != ["--format", "json-v1"]
    ):
        raise ValueError("Only the fixed runtime inventory helper is permitted")
    return [SUDO_PATH, "-n", *arguments[2:]]


def main():
    try:
        command = validated_sudo_command(os.environ.get("SSH_ORIGINAL_COMMAND"))
    except Exception:  # noqa: BLE001 -- never echo rejected remote input
        raise SystemExit("runtime inventory command denied") from None
    environment = {
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    }
    os.execve(SUDO_PATH, command, environment)
