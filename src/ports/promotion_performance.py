"""Trusted optional measurements; never supplied by an app upload or HTTP body."""

from abc import ABC, abstractmethod


class PromotionPerformanceObserver(ABC):
    @abstractmethod
    def measure(self, plan, binding, *, guard):
        """Return bounded evidence from the exact registered app database/runtime."""
