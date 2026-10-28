"""REST-only application pair controlled by an audited WAF gate and DB fences.

The gate's reviewed contract excludes WebSocket/background writers and mutating
GETs. Read availability during DB fencing/edge propagation is measured, never
assumed. This adapter is not selected for apps lacking that contract.
"""

from copy import deepcopy


class RestGatedBlueGreenTraffic:
    def __init__(self, source, target, gate, router, runtime, *, guard, stable_url):
        self.bindings = [deepcopy(source), deepcopy(target)]
        if source == target or gate.bindings != self.bindings:
            raise ValueError("Same registered REST gate and promotion bindings required")
        self.gate, self.router, self.runtime, self.guard = gate, router, runtime, guard
        self.stable_url = stable_url
        self.closed, self.verified, self.uncertain = False, None, False

    def recovery_binding(self):
        self.guard()
        return self.router.current()

    def quiesce(self, expected_binding):
        if (
            self.uncertain
            or expected_binding not in self.bindings
            or self.router.current() != expected_binding
        ):
            raise ValueError("Registered current route required before pausing REST writes")
        self.guard()
        self.uncertain = True
        receipt = self.gate.set_active(None)
        self.guard()
        self.closed, self.verified, self.uncertain = True, None, False
        return receipt

    def activate(self, expected_binding, target_binding):
        if (
            not self.closed
            or self.uncertain
            or expected_binding == target_binding
            or target_binding not in self.bindings
        ):
            raise ValueError("Verified closed REST writer gate required")
        self.guard()
        self.uncertain = True
        runtime = self.runtime(target_binding)
        if runtime.get("database", {}).get("binding") != target_binding:
            raise ValueError("Ready runtime differs from target DB binding")
        receipt = self.router.switch(expected_binding, target_binding)
        self.guard()
        self.uncertain = False
        return receipt

    def probe(self, expected_binding):
        if not self.closed or self.uncertain or self.router.current() != expected_binding:
            raise ValueError("Closed REST gate and matching stable route required")
        self.guard()
        self.uncertain = True
        receipt = self.router.probe(expected_binding)
        runtime = self.runtime(expected_binding)
        if runtime.get("database", {}).get("binding") != expected_binding:
            raise ValueError("Runtime DB identity changed after stable-route probe")
        self.guard()
        self.verified, self.uncertain = deepcopy(expected_binding), False
        return receipt

    def resume(self, expected_binding):
        if (
            not self.closed
            or self.uncertain
            or self.verified != expected_binding
            or self.router.current() != expected_binding
        ):
            raise ValueError("Verified REST runtime and route required before opening writes")
        self.guard()
        self.uncertain = True
        receipt = self.gate.set_active(expected_binding)
        self.guard()
        self.closed, self.verified, self.uncertain = False, None, False
        return receipt

    def published_runtime(self, binding):
        if self.closed or self.uncertain or self.router.current() != binding:
            raise ValueError("Verified resumed route required before publication")
        self.guard()
        runtime = self.runtime(binding)
        if runtime.get("database", {}).get("binding") != binding:
            raise ValueError("Published runtime DB binding changed")
        return {
            **runtime,
            "origin_url": runtime["url"],
            "url": self.stable_url,
            "health_url": self.stable_url + "/health",
            "traffic_strategy": "blue_green",
            "verification": {
                **runtime["verification"],
                "stable_route": "verified",
                "application_data_path": "read_verified",
            },
        }
