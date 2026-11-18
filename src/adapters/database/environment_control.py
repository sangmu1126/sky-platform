"""Pinned authenticated control client for fixed cross-environment app instances.

This registers an existing cooperating controller; it does not retrofit arbitrary
apps with a write barrier or authorize a migration by itself.
"""

from dataclasses import asdict

from adapters.database.application_traffic import RegisteredApplicationTraffic
from domain.database_transfer import RegisteredDatabaseTransfer


class EnvironmentApplicationControl(RegisteredApplicationTraffic):
    def __init__(self, transfer, endpoint, token, *, controller_id, guard, transport=None, ssl_context=None):
        if not isinstance(transfer, RegisteredDatabaseTransfer):
            raise TypeError("Typed environment transfer registration required")
        self.transfer = transfer
        self._initialize_registered(
            endpoint,
            token,
            controller_id=controller_id,
            bindings=[asdict(transfer.source), asdict(transfer.target)],
            guard=guard,
            transport=transport,
            ssl_context=ssl_context,
        )

    def activate(self, expected_binding, target_binding):
        raise ValueError(
            "Environment app revisions have fixed database bindings; switch the registered router"
        )
