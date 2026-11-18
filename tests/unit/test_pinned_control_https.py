"""Pinned control transport performs one bounded authenticated TLS mutation."""

import json
import ssl
from unittest.mock import Mock, patch

import pytest

from adapters.database.pinned_control_https import PinnedHTTPSControlTransport


def fixture():
    context = Mock(verify_mode=ssl.CERT_REQUIRED, check_hostname=True)
    wrapped = Mock()
    context.wrap_socket.return_value = wrapped
    raw = Mock()
    response = Mock(
        status=200,
        getheader=Mock(return_value="application/json; charset=utf-8"),
        read=Mock(return_value=b'{"generation":2,"verified":true}'),
    )
    connection = Mock(getresponse=Mock(return_value=response))
    guard = Mock()
    transport = PinnedHTTPSControlTransport(
        "https://controller.rehearsal.test:8443/control",
        "private-control-token",
        address="127.0.0.1",
        ssl_context=context,
        guard=guard,
        response_timeout=7,
    )
    return transport, context, raw, wrapped, response, connection, guard


def test_control_transport_posts_canonical_command_to_one_pinned_tls_address():
    transport, context, raw, _wrapped, _response, connection, guard = fixture()
    command = {"schema_version": 1, "action": "quiesce"}
    with (
        patch(
            "adapters.database.pinned_control_https.socket.create_connection",
            return_value=raw,
        ) as create,
        patch(
            "adapters.database.pinned_control_https.http.client.HTTPSConnection",
            return_value=connection,
        ),
    ):
        assert transport(command) == {"generation": 2, "verified": True}
    create.assert_called_once_with(("127.0.0.1", 8443), timeout=7)
    context.wrap_socket.assert_called_once_with(raw, server_hostname="controller.rehearsal.test")
    connection.request.assert_called_once_with(
        "POST",
        "/control",
        body=json.dumps(command, separators=(",", ":")).encode(),
        headers={
            "Authorization": "Bearer private-control-token",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Connection": "close",
        },
    )
    assert guard.call_count == 2
    connection.close.assert_called_once_with()
    assert "private-control-token" not in repr(transport)


@pytest.mark.parametrize(
    "change", ["status", "redirect", "content", "oversize", "duplicate", "nonfinite", "network"]
)
def test_control_transport_failure_is_sanitized_and_never_retried(change):
    transport, _context, raw, _wrapped, response, connection, _guard = fixture()
    if change == "status":
        response.status = 503
    elif change == "redirect":
        response.status = 307
    elif change == "content":
        response.getheader.return_value = "text/plain"
    elif change == "oversize":
        response.read.return_value = b"x" * 16385
    elif change == "duplicate":
        response.read.return_value = b'{"generation":1,"generation":2}'
    elif change == "nonfinite":
        response.read.return_value = b'{"generation":NaN}'
    with (
        patch(
            "adapters.database.pinned_control_https.socket.create_connection",
            side_effect=OSError("private-network-detail") if change == "network" else None,
            return_value=raw,
        ) as create,
        patch(
            "adapters.database.pinned_control_https.http.client.HTTPSConnection",
            return_value=connection,
        ),
        pytest.raises(RuntimeError, match="requires reconciliation") as error,
    ):
        transport({"schema_version": 1, "action": "quiesce"})
    assert "private" not in str(error.value)
    assert create.call_count == 1
    connection.close.assert_called_once_with()


@pytest.mark.parametrize(
    "change",
    ["public", "path", "query", "token", "context", "guard", "timeout"],
)
def test_control_transport_rejects_unpinned_or_ambiguous_registration(change):
    values = {
        "endpoint": "https://controller.rehearsal.test:8443/control",
        "token": "token",
        "address": "127.0.0.1",
        "ssl_context": Mock(verify_mode=ssl.CERT_REQUIRED, check_hostname=True),
        "guard": Mock(),
        "response_timeout": 7,
    }
    if change == "public":
        values["address"] = "8.8.8.8"
    elif change == "path":
        values["endpoint"] = "https://controller.rehearsal.test:8443"
    elif change == "query":
        values["endpoint"] += "?redirect=true"
    elif change == "token":
        values["token"] = "bad\nheader"
    elif change == "context":
        values["ssl_context"].check_hostname = False
    elif change == "guard":
        values["guard"] = None
    else:
        values["response_timeout"] = 0
    with pytest.raises(ValueError, match="Registered private address"):
        PinnedHTTPSControlTransport(**values)
