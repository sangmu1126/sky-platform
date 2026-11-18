"""Controlled migration workload, not an arbitrary-app write-drain adapter.

One process serializes all DB access and control under one lock. Every restart
starts write-closed. No background writers, sessions or schema migrations exist.
TLS/authentication are mandatory, including on the private demo network.
"""

import hashlib
import hmac
import json
import os
import ssl
import threading
import time
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import psycopg


class Workload:
    def __init__(self, config):
        self.config = config
        self.binding = config["binding"]
        self.generation = time.time_ns()
        self.closed, self.probed = True, False
        self.lock = threading.Lock()
        self.nonces = set()
        self.binding_hash = hashlib.sha256(
            json.dumps(self.binding, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    def connect(self):
        return psycopg.connect(
            **self.config["database"],
            connect_timeout=3,
            options="-c statement_timeout=3000 -c lock_timeout=1000",
        )

    def read(self):
        with self.connect() as db:
            rows = db.execute("SELECT id,score FROM public.scores ORDER BY id LIMIT 100").fetchall()
        return {"binding_hash": self.binding_hash, "rows": rows, "writes_blocked": self.closed}

    def control(self, command):
        required = {
            "schema_version",
            "controller_id",
            "request_id",
            "action",
            "expected_binding",
            "expected_generation",
            "target_binding",
        }
        if not isinstance(command, dict) or set(command) != required:
            raise ValueError("Invalid control schema")
        action, nonce = command["action"], command["request_id"]
        if (
            type(command["schema_version"]) is not int
            or command["schema_version"] != 1
            or command["controller_id"] != self.config["controller_id"]
            or command["expected_binding"] != self.binding
            or command["target_binding"] is not None
            or action not in {"quiesce", "probe", "resume"}
            or not isinstance(nonce, str)
            or len(nonce) != 32
            or any(c not in "0123456789abcdef" for c in nonce)
            or nonce in self.nonces
            or len(self.nonces) >= 4096
        ):
            raise ValueError("Unregistered or replayed control command")
        generation = command["expected_generation"]
        if (generation is None and action != "quiesce") or (
            generation is not None and (type(generation) is not int or generation != self.generation)
        ):
            raise ValueError("Stale controller generation")
        # The HTTP handler holds the same lock for all DB writers. Acquiring it
        # drains any in-flight write transaction before acknowledging closure.
        self.nonces.add(nonce)
        verified = False
        if action == "quiesce":
            self.closed, self.probed = True, False
        elif action == "probe":
            if not self.closed:
                raise ValueError("Close writers before probing")
            self.read()
            self.probed, verified = True, True
        elif action == "resume":
            if not self.closed or not self.probed:
                raise ValueError("Verified read required before resume")
            self.closed, self.probed = False, False
        self.generation += 1
        return {
            "schema_version": 1,
            "controller_id": self.config["controller_id"],
            "request_id": nonce,
            "action": action,
            "binding": self.binding,
            "generation": self.generation,
            "writes_blocked": self.closed,
            "active_writes": 0,
            "database_read_verified": verified,
        }


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass  # Never log Authorization, config, DSNs or request bodies.

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def respond(self, status, data):
        body = json.dumps(data, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def authorized(self, control=False):
        token = self.server.workload.config["control_token" if control else "client_token"]
        return hmac.compare_digest(self.headers.get("Authorization", ""), "Bearer " + token)

    def do_GET(self):
        if self.path == "/health":
            return self.respond(200, {"alive": True})
        if self.path != "/scores" or not self.authorized():
            return self.respond(403, {"error": "denied"})
        state = self.server.workload
        if not state.lock.acquire(timeout=5):
            return self.respond(503, {"error": "busy"})
        try:
            self.respond(200, state.read())
        except (psycopg.Error, OSError):
            self.respond(503, {"error": "database_unavailable"})
        finally:
            state.lock.release()

    def do_POST(self):
        control = self.path == "/control"
        if self.path not in {"/control", "/scores"} or not self.authorized(control):
            return self.respond(403, {"error": "denied"})
        try:
            if self.headers.get("Transfer-Encoding"):
                raise ValueError("Unsupported framing")
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 16384:
                raise ValueError("Bounded JSON required")
            command = json.loads(self.rfile.read(length))
        except (ValueError, OSError):
            return self.respond(400, {"error": "invalid_request"})
        state = self.server.workload
        if not state.lock.acquire(timeout=5):
            return self.respond(503, {"error": "busy"})
        try:
            if control:
                result = state.control(command)
            else:
                if state.closed:
                    return self.respond(503, {"error": "writes_paused"})
                if (
                    not isinstance(command, dict)
                    or set(command) != {"id", "score"}
                    or any(type(command[k]) is not int or not 0 < command[k] < 2**31 for k in command)
                ):
                    raise ValueError("Bounded score required")
                with state.connect() as db:
                    db.execute(
                        "INSERT INTO public.scores(id,score) VALUES(%s,%s)", (command["id"], command["score"])
                    )
                result = {"committed": True, "binding_hash": state.binding_hash}
            self.respond(200, result)
        except ValueError:
            self.respond(409, {"error": "control_or_input_rejected"})
        except (psycopg.Error, OSError):
            # Control effects may have occurred: caller must reconcile, not retry.
            self.respond(503, {"error": "outcome_requires_reconciliation"})
        finally:
            state.lock.release()


def main():
    raw = os.environ.pop("SKY_DEMO_CONFIG", None)
    config = json.loads(raw) if raw else json.loads(Path(os.environ["SKY_DEMO_CONFIG_FILE"]).read_text())
    # Linux memfd keeps TLS material off the image and filesystem. Both demo
    # runtimes can use a read-only root filesystem with no writable host mount.
    with ExitStack() as stack:
        files = {}
        for name in ("server_cert", "server_key", "database_ca"):
            handle = stack.enter_context(os.fdopen(os.memfd_create(name, os.MFD_CLOEXEC), "w+b"))
            handle.write(config.pop(name).encode())
            handle.flush()
            files[name] = "/proc/self/fd/" + str(handle.fileno())
        config["database"].update(sslmode="verify-full", sslrootcert=files["database_ca"])
        server = ThreadingHTTPServer(("0.0.0.0", 8443), Handler)
        server.workload = Workload(config)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(files["server_cert"], files["server_key"])
        server.socket = context.wrap_socket(server.socket, server_side=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
