"""Bounded, unambiguous JSON decoding for external runtime evidence."""

import json
import math


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate external JSON field")
        value[key] = item
    return value


def _finite_float(value):
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("Finite external JSON number required")
    return result


def _reject_constant(_value):
    raise ValueError("Standard external JSON required")


def strict_external_json(value, *, maximum, expected_type):
    if isinstance(value, str):
        size = len(value.encode("utf-8"))
    elif isinstance(value, bytes):
        size = len(value)
    else:
        raise TypeError("External JSON text required")
    if type(maximum) is not int or not 1 <= size <= maximum:
        raise ValueError("Bounded external JSON required")
    try:
        result = json.loads(
            value,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("Valid external JSON required") from None
    if not isinstance(result, expected_type):
        raise TypeError("Expected external JSON shape required")
    return result
