"""Bound command diagnostics and lifetime without writing untrusted logs to disk.

Killing the CLI group does not prove a Docker daemon stopped a submitted build.
Ephemeral daemon/VM teardown remains a separate orchestration responsibility.
"""

import os
import selectors
import signal
import subprocess
import time


def bounded_command(arguments, *, timeout=1200, env=None, output_limit=8 * 1024 * 1024):
    if (not isinstance(arguments, list) or not arguments
            or any(not isinstance(item, str) or "\x00" in item for item in arguments)
            or type(timeout) not in {int, float} or not 0 < timeout <= 3600
            or type(output_limit) is not int or not 1 <= output_limit <= 16 * 1024 * 1024):
        raise ValueError("Bounded command arguments and limits required")
    process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, env=env, start_new_session=True)
    diagnostic, size = bytearray(), 0
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise OSError("Builder command exceeded its time limit")
                for key, _ in selector.select(min(remaining, 0.1)):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    size += len(chunk)
                    if size > output_limit:
                        raise OSError("Builder command exceeded its output limit")
                    diagnostic.extend(chunk[:max(0, 65536 - len(diagnostic))])
            try:
                code = process.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                raise OSError("Builder command exceeded its time limit") from None
        return code, diagnostic.decode("utf-8", errors="replace")
    finally:
        # Always reap and kill descendants in our group, including those retaining
        # the pipe after the parent exits. Never target another runner's process.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        process.stdout.close()
