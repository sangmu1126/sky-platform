"""Read-preserving ACL fence for a pinned cross-environment workload.

Uses the same qualified SQL ACL profile as legacy promotion, with a separate
marker and typed registration. No worker queue or input can select a new role.
"""

import re
from contextlib import contextmanager

from adapters.database.environment_transfer import PostgresEnvironmentTransfer
from adapters.database.promotion_write_fence import PostgresPromotionWriteFence


class PostgresEnvironmentWriteFence(PostgresPromotionWriteFence):
    def __init__(self, transport, endpoint, login_role, ownership_marker):
        if not isinstance(transport, PostgresEnvironmentTransfer) or endpoint not in {"source", "target"}:
            raise ValueError("Registered environment transfer and endpoint required")
        if (
            not isinstance(login_role, str)
            or not re.fullmatch(r"sky_transfer_[a-f0-9]{16,32}", login_role)
            or not isinstance(ownership_marker, str)
            or not re.fullmatch(r"sky-transfer-v1:[a-f0-9]{64}", ownership_marker)
        ):
            raise ValueError("Exact owned environment writer registration required")
        self.transport, self.endpoint = transport, endpoint
        index = 0 if endpoint == "source" else 1
        self.binding = (transport.transfer.source, transport.transfer.target)[index]
        self.role, self.marker = login_role, ownership_marker
        self.administrative_database = self.binding.database_name
        self._guard = None
        connect = transport.source_connect if index == 0 else transport.target_connect

        @contextmanager
        def verified_connect():
            if self._guard is None:
                raise RuntimeError("Fence execution guard is not active")
            transport._registered(transport.transfer, self._guard)
            with connect() as db:
                transport._verify_connection(db, transport.endpoints[index])
                yield db

        self.connect = verified_connect

    def set_writes(self, enabled, *, guard):
        if type(enabled) is not bool or self._guard is not None:
            raise ValueError("Explicit serial environment write fence required")
        self._guard = guard
        try:
            return self._set_registered_writes(enabled, guard=guard)
        finally:
            self._guard = None

    def set_login(self, enabled, *, guard):
        raise ValueError("Environment transfer uses read-preserving write ACLs, not login replacement")

    def inspect(self, *, guard):
        raise ValueError("Environment writer inspection requires its registered metadata collector")
