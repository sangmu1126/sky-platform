"""One operating page over existing consent APIs and trusted recovery services."""

import re
from urllib.parse import urlsplit

from assets import ASSET_ROOT
from interfaces.http.mutation_requests import read_json_object
from ports.state import RecordConflict

_JOB = r"([a-f0-9]{16})"
_UUID = r"([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})"


def handler_for_operating_lifecycle(app, controller, *, base_handler):
    class Handler(base_handler):
        def respond(self, action):
            try:
                app.readiness()
                status, value = action()
                self.json_response(status, value)
            except PermissionError:
                self.json_response(403, {"error": "Operating access denied"})
            except FileNotFoundError:
                self.json_response(404, {"error": "Not found"})
            except (ValueError, RecordConflict):
                self.json_response(
                    409, {"error": "Operation changed or is unavailable; inspect the existing result"}
                )
            except OSError:
                self.json_response(503, {"error": "Operating state temporarily unavailable"})

        def do_GET(self):
            if urlsplit(self.path).path == "/operations":
                browser = getattr(app, "cognito_browser", None)
                if browser is None and not self.authenticate_api():
                    return
                payload = (ASSET_ROOT / "static/operating-lifecycle.html").read_bytes()
                if browser is not None:
                    payload = payload.replace(
                        b"</head>", b'<script src="/auth/client.js"></script></head>', 1
                    )
                self.send_response(200)
                for key, value in {
                    "Content-Type": "text/html; charset=utf-8",
                    "Content-Length": str(len(payload)),
                    "Cache-Control": "no-store",
                    "Referrer-Policy": "no-referrer",
                    "X-Content-Type-Options": "nosniff",
                    "Content-Security-Policy": "frame-ancestors 'self'",
                }.items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(payload)
                return
            route = re.fullmatch(r"/api/jobs/" + _JOB + r"/operating-lifecycle", self.path)
            if route:
                if self.authenticate_api():
                    self.respond(lambda: (200, controller.detail(self.principal, route[1])))
                return
            super().do_GET()

        def do_POST(self):
            effect = re.fullmatch(r"/api/jobs/" + _JOB + r"/operating-lifecycle/effect-review", self.path)
            recovery = re.fullmatch(
                r"/api/jobs/" + _JOB + r"/operations/" + _UUID + r"/resume-preparation", self.path
            )
            if not effect and not recovery:
                super().do_POST()
                return
            self.close_connection = True
            if not self.authenticate_api():
                return
            if self.headers.get_all("Origin") != [app.origin]:
                self.json_response(403, {"error": "Invalid request origin"})
                return
            try:
                body = read_json_object(self)
                if effect:
                    if (
                        set(body) != {"operation_id", "confirm_review"}
                        or body["confirm_review"] is not True
                        or not isinstance(body["operation_id"], str)
                        or not re.fullmatch(_UUID, body["operation_id"])
                    ):
                        raise ValueError()
                elif (
                    set(body) != {"attempt_id", "row_version", "confirm_reconciliation"}
                    or body["confirm_reconciliation"] is not True
                    or not isinstance(body["attempt_id"], str)
                    or not re.fullmatch(_UUID, body["attempt_id"])
                    or type(body["row_version"]) is not int
                    or not 1 <= body["row_version"] < 2**63
                ):
                    raise ValueError()
            except (ValueError, UnicodeError, OSError):
                self.json_response(400, {"error": "Invalid operating request"})
                return
            self.respond(
                lambda: (
                    (200, controller.review_effect(self.principal, effect[1], body["operation_id"]))
                    if effect
                    else (
                        202,
                        controller.resume_preparation(
                            self.principal, recovery[1], recovery[2], body["attempt_id"], body["row_version"]
                        ),
                    )
                )
            )

    return Handler
