"""Explicit local-operator GitHub session; never injected into a source build job."""

import subprocess


class OperatorGitHubSession:
    def __call__(self):
        result = subprocess.run(
            ["gh", "auth", "token", "--hostname", "github.com"], capture_output=True, timeout=15, check=False
        )
        if result.returncode or not 1 <= len(result.stdout) <= 16384:
            raise OSError("Operator GitHub session unavailable")
        token = result.stdout.decode().strip()
        if not token or any(char.isspace() for char in token):
            raise ValueError("Invalid operator GitHub session")
        return token
