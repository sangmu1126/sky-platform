"""Opt-in migration routes on the existing authenticated Sky HTTP service."""

import re

from interfaces.http.mutation_requests import read_json_object


def handler_for_environment_transfers(app, service, base_handler):
    class Handler(base_handler):
        def _environment_response(self, action, *, accepted=False):
            try:
                self.json_response(202 if accepted else 200, action())
            except PermissionError:
                self.json_response(404, {"error": "접근 가능한 이전 앱을 찾을 수 없습니다."})
            except ValueError:
                self.json_response(409, {"error": "이전 조건·승인·진행 상태를 다시 확인하세요."})
            except Exception:  # noqa: BLE001 -- no raw runtime, database or credential errors
                self.json_response(
                    503, {"error": "이전 상태를 확인할 수 없습니다. 새 작업으로 반복하지 마세요."}
                )

        def do_GET(self):
            if self.path == "/api/environment-transfers":
                if self.authenticate_api():
                    self._environment_response(lambda: {"registrations": service.list(self.principal)})
                return
            route = re.fullmatch(r"/api/environment-transfers/([A-Za-z0-9][A-Za-z0-9_-]{0,127})", self.path)
            if route:
                if self.authenticate_api():
                    self._environment_response(lambda: service.detail(self.principal, route[1]))
                return
            super().do_GET()

        def do_POST(self):
            route = re.fullmatch(r"/api/environment-transfers/([A-Za-z0-9][A-Za-z0-9_-]{0,127})", self.path)
            if not route:
                super().do_POST()
                return
            self.close_connection = True
            if not self.authenticate_api():
                return
            if self.headers.get_all("Origin") != [app.origin]:
                self.json_response(403, {"error": "같은 Sky 화면에서 요청하세요."})
                return
            try:
                body = read_json_object(self)
                if (
                    set(body)
                    != {
                        "action",
                        "review_revision",
                        "request_key",
                        "confirm_write_pause",
                        "confirm_websocket_reconnect",
                    }
                    or not isinstance(body["review_revision"], str)
                    or not re.fullmatch(r"[a-f0-9]{64}", body["review_revision"])
                    or not isinstance(body["action"], str)
                ):
                    raise ValueError()
            except (ValueError, UnicodeError, TimeoutError, OSError):
                self.json_response(400, {"error": "이전 요청 형식이 올바르지 않습니다."})
                return
            self._environment_response(
                lambda: service.submit(self.principal, route[1], **body), accepted=True
            )

    return Handler
