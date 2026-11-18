"""Same guarded blue/green protocol with explicit provider-neutral placements."""

from dataclasses import asdict

from adapters.database.blue_green_traffic import BlueGreenApplicationTraffic
from domain.database_transfer import RegisteredDatabaseTransfer


class EnvironmentBlueGreenTraffic(BlueGreenApplicationTraffic):
    def __init__(self, transfer, blue, green, router, *, guard):
        if not isinstance(transfer, RegisteredDatabaseTransfer) or blue is green:
            raise ValueError("Distinct registered source and destination applications required")
        self.bindings = [asdict(transfer.source), asdict(transfer.target)]
        self.controllers = [blue, green]
        self.router, self.guard = router, guard
        self.closed, self.verified, self.uncertain = False, None, False
