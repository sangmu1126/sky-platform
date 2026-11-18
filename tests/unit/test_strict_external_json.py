import pytest

from adapters.runtime.strict_json import strict_external_json


def decode(value, expected_type=dict):
    return strict_external_json(value, maximum=128, expected_type=expected_type)


def test_accepts_bounded_unique_standard_json_and_bytes():
    assert decode(b'{"outer":{"value":1.5}}') == {"outer": {"value": 1.5}}
    assert decode('"daemon"', str) == "daemon"


@pytest.mark.parametrize(
    "value",
    [
        '{"value":1,"value":2}',
        '{"outer":{"value":1,"value":2}}',
        '{"value":NaN}',
        '{"value":Infinity}',
        '{"value":-Infinity}',
        '{"value":1e999}',
    ],
)
def test_rejects_duplicate_or_nonfinite_external_values(value):
    with pytest.raises(ValueError):
        decode(value)


def test_rejects_empty_oversized_nontext_or_wrong_shape():
    for value in ("", " " * 129):
        with pytest.raises(ValueError, match="Bounded"):
            decode(value)
    with pytest.raises(TypeError, match="text"):
        decode({})
    with pytest.raises(TypeError, match="shape"):
        decode("[]")
