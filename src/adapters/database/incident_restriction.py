"""Reuse SQL ownership checks to restrict only one registered application role.

The composition root must verify the connection's AWS/TLS/pool registration.
This adapter does not verify those external facts, rotate secrets, or restore LOGIN.
"""

from dataclasses import asdict

from adapters.database.promotion_fence import PostgresApplicationFence


class PostgresIncidentRestriction:
    def __init__(self, fence: PostgresApplicationFence):
        if not isinstance(fence, PostgresApplicationFence):
            raise TypeError("An ownership-checking application fence is required")
        self.fence, self.binding = fence, fence.binding

    def restrict(self, *, guard):
        receipt = self.fence.set_login(False, guard=guard)
        if receipt["binding"] != asdict(self.binding) or receipt["login_enabled"] is not False:
            raise ValueError("Application login restriction could not be verified")
        return {"binding": receipt["binding"], "login_enabled": False}

    def inspect(self, *, guard):
        return self.fence.inspect(guard=guard)
