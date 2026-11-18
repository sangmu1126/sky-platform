"""Hosted loop for the isolated reviewed environment execution queue."""

import re


def require_isolated_environment_queue(environment_queue_url, reserved_queue_urls):
    if (
        not isinstance(environment_queue_url, str)
        or not re.fullmatch(
            r"https://sqs\.[a-z0-9-]+\.amazonaws\.com/\d{12}/[A-Za-z0-9_-]+\.fifo", environment_queue_url
        )
        or not isinstance(reserved_queue_urls, tuple)
        or any(not isinstance(value, str) for value in reserved_queue_urls)
        or environment_queue_url in {value for value in reserved_queue_urls if value}
    ):
        raise ValueError("Dedicated reviewed environment FIFO queue required")
    return environment_queue_url


def run_reviewed_environment_consumer(consumer, stop, *, once=False, wait_seconds=1):
    if not callable(getattr(consumer, "consume_once", None)) or not callable(getattr(stop, "wait", None)):
        raise TypeError("Reviewed environment consumer and stop event required")
    if type(wait_seconds) not in {int, float} or not 0 <= wait_seconds <= 60:
        raise ValueError("Bounded reviewed environment poll interval required")
    while not stop.is_set():
        result = consumer.consume_once()
        if once:
            return result
        if result == "idle":
            stop.wait(wait_seconds)
    return "stopped"
