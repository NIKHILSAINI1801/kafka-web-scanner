import ipaddress

import pytest

from kafka import http_client
from kafka.config import HttpLimits
from kafka.http_client import ConnectFailed, FetchError, _attempt_order, fetch
from kafka.scope import validate_url
from tests.helpers import make_snapshot

TARGET = validate_url("https://example.test/")


def _ips(*values):
    return [ipaddress.ip_address(v) for v in values]


def test_attempt_order_alternates_families_starting_with_the_first_address():
    order = _attempt_order(_ips("2001:db8::1", "2001:db8::2", "192.0.2.1", "192.0.2.2"))
    assert [str(ip) for ip in order] == ["2001:db8::1", "192.0.2.1", "2001:db8::2", "192.0.2.2"]


def test_attempt_order_keeps_a_single_family_in_order():
    assert [str(i) for i in _attempt_order(_ips("192.0.2.1", "192.0.2.2"))] == [
        "192.0.2.1",
        "192.0.2.2",
    ]


def test_attempt_order_removes_duplicates_and_caps_attempts():
    many = _ips(*[f"192.0.2.{n}" for n in range(1, 10)])
    assert len(_attempt_order(many + many)) == http_client.MAX_CONNECT_ATTEMPTS
    assert len(_attempt_order(_ips("192.0.2.1", "192.0.2.1"))) == 1
    assert _attempt_order([]) == []


def test_ipv6_first_is_not_a_dead_end_for_an_ipv4_only_network():
    order = _attempt_order(_ips("2001:db8::1", "2001:db8::2", "2001:db8::3", "192.0.2.1"))
    assert str(order[1]) == "192.0.2.1"  # IPv4 is tried second, not last


def _record_attempts(monkeypatch, outcomes):
    calls = []

    def fake(target, address, limits, ca_bundle, deadline):
        calls.append(str(address))
        outcome = outcomes[len(calls) - 1]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(http_client, "_fetch_from", fake)
    return calls


def test_connect_failure_moves_on_to_the_next_address(monkeypatch):
    snapshot = make_snapshot({})
    calls = _record_attempts(monkeypatch, [ConnectFailed("connection_failed", "x"), snapshot])
    assert fetch(TARGET, _ips("2001:db8::1", "192.0.2.1")) is snapshot
    assert calls == ["2001:db8::1", "192.0.2.1"]


@pytest.mark.parametrize(
    "error",
    [
        FetchError("tls_verification_failed", "bad cert"),
        FetchError("timeout", "read timed out"),
        FetchError("http_error", "boom"),
    ],
)
def test_only_connect_failures_allow_a_second_attempt(monkeypatch, error):
    calls = _record_attempts(monkeypatch, [error, make_snapshot({})])
    with pytest.raises(FetchError) as excinfo:
        fetch(TARGET, _ips("192.0.2.1", "2001:db8::1"))
    assert excinfo.value is error and len(calls) == 1


def test_when_every_attempt_fails_the_last_error_is_raised(monkeypatch):
    first, last = ConnectFailed("connection_failed", "a"), ConnectFailed("timeout", "b")
    calls = _record_attempts(monkeypatch, [first, last])
    with pytest.raises(FetchError) as excinfo:
        fetch(TARGET, _ips("192.0.2.1", "2001:db8::1"))
    assert excinfo.value is last and len(calls) == 2


def test_a_single_address_object_is_accepted(monkeypatch):
    snapshot = make_snapshot({})
    calls = _record_attempts(monkeypatch, [snapshot])
    assert fetch(TARGET, ipaddress.ip_address("192.0.2.1")) is snapshot
    assert calls == ["192.0.2.1"]


def test_no_addresses_is_a_clean_error():
    with pytest.raises(FetchError, match="no address"):
        fetch(TARGET, [])


def test_overall_deadline_stops_further_attempts(monkeypatch):
    calls = _record_attempts(monkeypatch, [ConnectFailed("timeout", "a"), make_snapshot({})])
    with pytest.raises(FetchError):
        fetch(TARGET, _ips("192.0.2.1", "2001:db8::1"), HttpLimits(total_timeout=0))
    assert len(calls) == 1
