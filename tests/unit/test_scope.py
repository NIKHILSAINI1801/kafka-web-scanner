import ipaddress
import socket

import pytest

from kafka.scope import (
    ResolutionError,
    ScopeError,
    URLValidationError,
    classify_address,
    resolve_and_check,
    validate_url,
)


def _resolver(*addresses):
    """Fake getaddrinfo returning the given IP strings."""

    def resolver(host, port, type=0):  # noqa: A002 - mirrors socket.getaddrinfo
        out = []
        for address in addresses:
            family = socket.AF_INET6 if ":" in address else socket.AF_INET
            out.append((family, socket.SOCK_STREAM, 6, "", (address, port)))
        return out

    return resolver


# ---- URL validation -------------------------------------------------------------------------


def test_valid_https_url_is_normalised():
    target = validate_url("HTTPS://Example.COM/path/to?x=1#frag")
    assert (target.scheme, target.hostname, target.port) == ("https", "example.com", 443)
    assert target.path_query == "/path/to?x=1"
    assert not target.explicit_port


def test_http_default_port_and_root_path():
    target = validate_url("http://example.com")
    assert (target.port, target.path_query) == (80, "/")


def test_explicit_port_is_kept():
    target = validate_url("https://example.com:8443/")
    assert target.port == 8443 and target.explicit_port
    assert target.host_header == "example.com:8443"


def test_host_header_omits_default_port():
    assert validate_url("https://example.com:443/").host_header == "example.com"


def test_surrounding_whitespace_is_trimmed():
    assert validate_url("  https://example.com/  ").hostname == "example.com"


def test_ipv6_literal_is_supported():
    target = validate_url("http://[2001:db8::1]:8080/")
    assert target.hostname == "2001:db8::1" and target.is_ip_literal
    assert target.host_header == "[2001:db8::1]:8080"


def test_idn_host_is_converted_to_punycode():
    assert validate_url("https://bücher.example/").hostname == "xn--bcher-kva.example"


def test_trailing_dot_host_is_normalised():
    assert validate_url("https://example.com./").hostname == "example.com"


def test_display_url_hides_query_string_and_fragment():
    shown = validate_url("https://example.com/a?token=SECRET#frag").display_url
    assert "SECRET" not in shown and "frag" not in shown
    assert shown == "https://example.com/a?<query omitted>"


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "   ",
        "example.com",
        "ftp://example.com/",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "gopher://example.com",
        "//example.com/",
        "http://",
        "http:///path",
    ],
)
def test_bad_scheme_or_missing_host_is_rejected(bad):
    with pytest.raises(URLValidationError):
        validate_url(bad)


@pytest.mark.parametrize(
    "bad",
    [
        "http://user:pass@example.com/",
        "http://user@example.com/",
        "https://example.com@evil.test/",
        "http://:pw@example.com/",
    ],
)
def test_credentials_in_url_are_rejected(bad):
    with pytest.raises(URLValidationError, match="credentials"):
        validate_url(bad)


@pytest.mark.parametrize(
    "bad",
    [
        "http://example.com:0/",
        "http://example.com:65536/",
        "http://example.com:99999/",
        "http://example.com:abc/",
    ],
)
def test_invalid_ports_are_rejected(bad):
    with pytest.raises(URLValidationError):
        validate_url(bad)


@pytest.mark.parametrize(
    "bad",
    [
        "http://exa_mple.com/",
        "http://-bad.example/",
        "http://bad-.example/",
        "http://a..b/",
        "http://" + "a" * 64 + ".example/",
        "http://[::1/",
        "http://[fe80::1%25eth0]/",
        "http://example.com\\@evil.test/",
        "http://exa mple.com/",
        "http://example.com/\x00",
        "http://example.com/a\nb",
        "http://exam\x7fple.com/",
    ],
)
def test_malformed_hosts_and_control_characters_are_rejected(bad):
    with pytest.raises(URLValidationError):
        validate_url(bad)


@pytest.mark.parametrize(
    "ambiguous", ["http://127.1/", "http://2130706433/", "http://0x7f.0.0.1/", "http://010.0.0.1/"]
)
def test_ambiguous_numeric_hosts_are_rejected(ambiguous):
    with pytest.raises(URLValidationError, match="numeric"):
        validate_url(ambiguous)


def test_overlong_url_is_rejected():
    with pytest.raises(URLValidationError, match="longer"):
        validate_url("http://example.com/" + "a" * 3000)


def test_non_string_input_is_rejected():
    with pytest.raises(URLValidationError):
        validate_url(None)  # type: ignore[arg-type]


# ---- address classification -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("address", "reason"),
    [
        ("127.0.0.1", "loopback"),
        ("127.255.255.254", "loopback"),
        ("::1", "loopback"),
        ("10.0.0.5", "private"),
        ("172.16.9.9", "private"),
        ("192.168.1.1", "private"),
        ("fd00::1", "private"),
        ("169.254.169.254", "link-local"),
        ("fe80::1", "link-local"),
        ("224.0.0.1", "multicast"),
        ("ff02::1", "multicast"),
        ("240.0.0.1", "reserved"),
        ("255.255.255.255", "reserved"),
        ("0.0.0.0", "unspecified"),
        ("::", "unspecified"),
        ("100.64.0.1", "non-global"),
        ("::ffff:127.0.0.1", "loopback"),
        ("::ffff:10.0.0.1", "private"),
        ("64:ff9b::7f00:1", "loopback"),
        ("2002:7f00:1::", "loopback"),
    ],
)
def test_non_public_addresses_are_classified(address, reason):
    assert classify_address(ipaddress.ip_address(address)) == reason


@pytest.mark.parametrize(
    "address", ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2001:4860:4860::8888", "::ffff:8.8.8.8"]
)
def test_public_addresses_are_allowed(address):
    assert classify_address(ipaddress.ip_address(address)) is None


# ---- resolve_and_check ---------------------------------------------------------------------


def test_public_host_returns_all_validated_addresses_in_resolver_order():
    target = validate_url("https://example.com/")
    ips = resolve_and_check(target, resolver=_resolver("93.184.216.34", "2606:2800:220:1::1"))
    assert [str(ip) for ip in ips] == ["93.184.216.34", "2606:2800:220:1::1"]


@pytest.mark.parametrize("address", ["127.0.0.1", "10.1.2.3", "169.254.169.254", "::1", "fc00::1"])
def test_private_destinations_are_blocked_by_default(address):
    with pytest.raises(ScopeError, match="allow-private"):
        resolve_and_check(validate_url("http://example.com/"), resolver=_resolver(address))


def test_any_private_address_in_a_multi_record_answer_blocks_the_scan():
    with pytest.raises(ScopeError):
        resolve_and_check(
            validate_url("http://example.com/"), resolver=_resolver("93.184.216.34", "10.0.0.1")
        )


def test_dns_rebinding_style_name_resolving_to_loopback_is_blocked():
    with pytest.raises(ScopeError):
        resolve_and_check(
            validate_url("http://looks-public.example/"), resolver=_resolver("127.0.0.1")
        )


def test_lab_mode_allows_loopback_private_and_link_local():
    target = validate_url("http://lab.example/")
    for address in ("127.0.0.1", "10.1.2.3", "192.168.0.9", "169.254.1.1", "::1"):
        ips = resolve_and_check(target, allow_private=True, resolver=_resolver(address))
        assert [str(ip) for ip in ips] == [address]


@pytest.mark.parametrize("address", ["0.0.0.0", "224.0.0.1", "240.0.0.1", "ff02::1", "::"])
def test_lab_mode_does_not_lift_the_other_safeguards(address):
    with pytest.raises(ScopeError, match="never scanned"):
        resolve_and_check(
            validate_url("http://lab.example/"), allow_private=True, resolver=_resolver(address)
        )


def test_lab_mode_still_allows_public_addresses():
    ips = resolve_and_check(
        validate_url("http://example.com/"), allow_private=True, resolver=_resolver("8.8.8.8")
    )
    assert [str(ip) for ip in ips] == ["8.8.8.8"]


def test_dns_failure_is_reported_without_a_traceback():
    def failing(host, port, type=0):  # noqa: A002
        raise socket.gaierror(-2, "Name or service not known")

    with pytest.raises(ResolutionError, match="Could not resolve"):
        resolve_and_check(validate_url("http://nonexistent.example/"), resolver=failing)


def test_empty_resolution_is_an_error():
    with pytest.raises(ResolutionError):
        resolve_and_check(
            validate_url("http://example.com/"), resolver=lambda host, port, type=0: []
        )


def test_ip_literal_targets_are_checked_too():
    with pytest.raises(ScopeError):
        resolve_and_check(validate_url("http://192.168.0.1/"))
    with pytest.raises(ScopeError):
        resolve_and_check(validate_url("http://[::1]:8080/"))
