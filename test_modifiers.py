"""
Comprehensive test suite for modifiers (subnet filtering logic)

Tests all modifier types: IPvPermit, IPvDeny, IPv4Only, IPv6Only, IPvAnyOnly
This is critical for pipeline data transformation.
"""

import pytest
from ipaddress import IPv4Network, IPv6Network

from fwdev_edl_server.models.modifiers import (
    IPvPermit,
    IPvDeny,
    IPv4Only,
    IPv6Only,
    IPvAnyOnly,
)


# ============================================================================
# TEST IPV4ONLY MODIFIER
# ============================================================================

class TestIPv4OnlyModifier:
    """Test IPv4Only modifier - filters to IPv4 addresses only"""

    def test_filters_ipv4_from_mixed_list(self):
        """Should keep only IPv4, remove IPv6 and strings"""
        modifier = IPv4Only(type="ipv4-only")

        values = [
            IPv4Network("192.168.1.0/24"),
            IPv6Network("2001:db8::/32"),
            IPv4Network("10.0.0.0/8"),
            "example.com",
            IPv4Network("172.16.0.0/12"),
        ]

        result = modifier.refresh(values)

        assert len(result) == 3
        assert IPv4Network("192.168.1.0/24") in result
        assert IPv4Network("10.0.0.0/8") in result
        assert IPv4Network("172.16.0.0/12") in result

    def test_removes_ipv6_addresses(self):
        """IPv6 addresses should be filtered out"""
        modifier = IPv4Only(type="ipv4-only")

        values = [
            IPv6Network("2001:db8::/32"),
            IPv6Network("fe80::/10"),
            IPv6Network("::1/128"),
        ]

        result = modifier.refresh(values)

        assert result == []

    def test_removes_string_values(self):
        """String values (URLs, FQDNs) should be filtered out"""
        modifier = IPv4Only(type="ipv4-only")

        values = [
            "example.com",
            "malicious.org/",
            "bad-site.net",
        ]

        result = modifier.refresh(values)

        assert result == []

    def test_empty_list_returns_empty(self):
        """Empty input should return empty output"""
        modifier = IPv4Only(type="ipv4-only")

        result = modifier.refresh([])

        assert result == []

    def test_all_ipv4_passes_through(self):
        """List with only IPv4 should pass through unchanged"""
        modifier = IPv4Only(type="ipv4-only")

        values = [
            IPv4Network("192.168.1.0/24"),
            IPv4Network("10.0.0.0/8"),
            IPv4Network("172.16.0.0/12"),
        ]

        result = modifier.refresh(values)

        assert len(result) == 3
        assert result == values


# ============================================================================
# TEST IPV6ONLY MODIFIER
# ============================================================================

class TestIPv6OnlyModifier:
    """Test IPv6Only modifier - filters to IPv6 addresses only"""

    def test_filters_ipv6_from_mixed_list(self):
        """Should keep only IPv6, remove IPv4 and strings"""
        modifier = IPv6Only(type="ipv6-only")

        values = [
            IPv4Network("192.168.1.0/24"),
            IPv6Network("2001:db8::/32"),
            IPv4Network("10.0.0.0/8"),
            "example.com",
            IPv6Network("fe80::/10"),
        ]

        result = modifier.refresh(values)

        assert len(result) == 2
        assert IPv6Network("2001:db8::/32") in result
        assert IPv6Network("fe80::/10") in result

    def test_removes_ipv4_addresses(self):
        """IPv4 addresses should be filtered out"""
        modifier = IPv6Only(type="ipv6-only")

        values = [
            IPv4Network("192.168.1.0/24"),
            IPv4Network("10.0.0.0/8"),
            IPv4Network("172.16.0.0/12"),
        ]

        result = modifier.refresh(values)

        assert result == []

    def test_removes_string_values(self):
        """String values should be filtered out"""
        modifier = IPv6Only(type="ipv6-only")

        values = [
            "example.com",
            "malicious.org/",
        ]

        result = modifier.refresh(values)

        assert result == []

    def test_empty_list_returns_empty(self):
        """Empty input should return empty output"""
        modifier = IPv6Only(type="ipv6-only")

        result = modifier.refresh([])

        assert result == []

    def test_all_ipv6_passes_through(self):
        """List with only IPv6 should pass through unchanged"""
        modifier = IPv6Only(type="ipv6-only")

        values = [
            IPv6Network("2001:db8::/32"),
            IPv6Network("fe80::/10"),
            IPv6Network("::1/128"),
        ]

        result = modifier.refresh(values)

        assert len(result) == 3
        assert result == values


# ============================================================================
# TEST IPVANYONLY MODIFIER
# ============================================================================

class TestIPvAnyOnlyModifier:
    """Test IPvAnyOnly modifier - keeps both IPv4 and IPv6, removes strings"""

    def test_keeps_both_ipv4_and_ipv6(self):
        """Should keep all IP addresses (IPv4 and IPv6)"""
        modifier = IPvAnyOnly(type="ip-only")

        values = [
            IPv4Network("192.168.1.0/24"),
            IPv6Network("2001:db8::/32"),
            IPv4Network("10.0.0.0/8"),
            IPv6Network("fe80::/10"),
        ]

        result = modifier.refresh(values)

        assert len(result) == 4
        assert IPv4Network("192.168.1.0/24") in result
        assert IPv6Network("2001:db8::/32") in result
        assert IPv4Network("10.0.0.0/8") in result
        assert IPv6Network("fe80::/10") in result

    def test_removes_fqdns_and_urls(self):
        """Should remove string values (FQDNs and URLs)"""
        modifier = IPvAnyOnly(type="ip-only")

        values = [
            IPv4Network("192.168.1.0/24"),
            "example.com",
            IPv6Network("2001:db8::/32"),
            "malicious.org/",
            IPv4Network("10.0.0.0/8"),
        ]

        result = modifier.refresh(values)

        assert len(result) == 3
        assert "example.com" not in result
        assert "malicious.org/" not in result

    def test_empty_list_returns_empty(self):
        """Empty input should return empty output"""
        modifier = IPvAnyOnly(type="ip-only")

        result = modifier.refresh([])

        assert result == []

    def test_only_strings_returns_empty(self):
        """List with only strings should return empty"""
        modifier = IPvAnyOnly(type="ip-only")

        values = [
            "example.com",
            "test.org",
            "malicious.net/",
        ]

        result = modifier.refresh(values)

        assert result == []


# ============================================================================
# TEST IPVPERMIT MODIFIER (COMPLEX SUBNET FILTERING)
# ============================================================================

class TestIPvPermitModifier:
    """Test IPvPermit modifier - permits IPs within specified subnets"""

    def test_single_subnet_permit_ipv4(self):
        """Permit IPs within a single IPv4 subnet"""
        modifier = IPvPermit(
            type="ip-permit",
            subnets=["192.168.0.0/16"]
        )

        values = [
            IPv4Network("192.168.1.0/24"),    # Within subnet
            IPv4Network("192.168.2.5/32"),    # Within subnet
            IPv4Network("10.0.0.0/8"),        # Outside subnet
            IPv4Network("192.168.255.0/24"),  # Within subnet
        ]

        result = modifier.refresh(values)

        assert len(result) == 3
        assert IPv4Network("192.168.1.0/24") in result
        assert IPv4Network("192.168.2.5/32") in result
        assert IPv4Network("192.168.255.0/24") in result
        assert IPv4Network("10.0.0.0/8") not in result

    def test_single_subnet_permit_ipv6(self):
        """Permit IPs within a single IPv6 subnet"""
        modifier = IPvPermit(
            type="ip-permit",
            subnets=["2001:db8::/32"]
        )

        values = [
            IPv6Network("2001:db8::1/128"),      # Within subnet
            IPv6Network("2001:db8:abcd::/48"),   # Within subnet
            IPv6Network("fe80::/10"),            # Outside subnet
            IPv6Network("2001:db8:ffff::/48"),   # Within subnet
        ]

        result = modifier.refresh(values)

        assert len(result) == 3
        assert IPv6Network("2001:db8::1/128") in result
        assert IPv6Network("2001:db8:abcd::/48") in result
        assert IPv6Network("2001:db8:ffff::/48") in result
        assert IPv6Network("fe80::/10") not in result

    def test_multiple_subnets_permit(self):
        """Permit IPs within multiple subnets"""
        modifier = IPvPermit(
            type="ip-permit",
            subnets=["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]
        )

        values = [
            IPv4Network("192.168.1.0/24"),    # Within 192.168.0.0/16
            IPv4Network("10.5.0.0/16"),       # Within 10.0.0.0/8
            IPv4Network("8.8.8.8/32"),        # Outside all
            IPv4Network("172.20.0.0/16"),     # Within 172.16.0.0/12
        ]

        result = modifier.refresh(values)

        assert len(result) == 3
        assert IPv4Network("8.8.8.8/32") not in result

    def test_mixed_ipv4_ipv6_subnets(self):
        """Permit with both IPv4 and IPv6 subnets"""
        modifier = IPvPermit(
            type="ip-permit",
            subnets=["192.168.0.0/16", "2001:db8::/32"]
        )

        values = [
            IPv4Network("192.168.1.0/24"),       # Permitted
            IPv6Network("2001:db8::1/128"),      # Permitted
            IPv4Network("10.0.0.0/8"),           # Not permitted
            IPv6Network("fe80::/10"),            # Not permitted
        ]

        result = modifier.refresh(values)

        assert len(result) == 2
        assert IPv4Network("192.168.1.0/24") in result
        assert IPv6Network("2001:db8::1/128") in result

    def test_exact_match_slash_32(self):
        """Test /32 exact IP match"""
        modifier = IPvPermit(
            type="ip-permit",
            subnets=["192.168.1.100/32"]
        )

        values = [
            IPv4Network("192.168.1.100/32"),  # Exact match
            IPv4Network("192.168.1.101/32"),  # Different IP
            IPv4Network("192.168.1.0/24"),    # Broader subnet
        ]

        result = modifier.refresh(values)

        # Only exact match should pass
        assert len(result) == 1
        assert IPv4Network("192.168.1.100/32") in result

    def test_exact_match_slash_128(self):
        """Test /128 exact IPv6 match"""
        modifier = IPvPermit(
            type="ip-permit",
            subnets=["2001:db8::1/128"]
        )

        values = [
            IPv6Network("2001:db8::1/128"),   # Exact match
            IPv6Network("2001:db8::2/128"),   # Different IP
            IPv6Network("2001:db8::/32"),     # Broader subnet
        ]

        result = modifier.refresh(values)

        # Only exact match should pass
        assert len(result) == 1
        assert IPv6Network("2001:db8::1/128") in result

    def test_overlapping_subnets(self):
        """Test with overlapping permit subnets"""
        modifier = IPvPermit(
            type="ip-permit",
            subnets=["192.168.0.0/16", "192.168.1.0/24"]  # Second is subset of first
        )

        values = [
            IPv4Network("192.168.1.100/32"),  # In both subnets
            IPv4Network("192.168.2.0/24"),    # Only in first subnet
        ]

        result = modifier.refresh(values)

        # Both should appear (may have duplicates if logic adds from each subnet)
        assert IPv4Network("192.168.1.100/32") in result
        assert IPv4Network("192.168.2.0/24") in result

    def test_non_ip_values_pass_through(self):
        """Non-IP values (strings) should pass through unchanged"""
        modifier = IPvPermit(
            type="ip-permit",
            subnets=["192.168.0.0/16"]
        )

        values = [
            IPv4Network("192.168.1.0/24"),  # Permitted
            "example.com",                   # String passes through
            IPv4Network("10.0.0.0/8"),      # Not permitted
            "malicious.org/",                # String passes through
        ]

        result = modifier.refresh(values)

        assert IPv4Network("192.168.1.0/24") in result
        assert "example.com" in result
        assert "malicious.org/" in result
        assert IPv4Network("10.0.0.0/8") not in result

    def test_empty_values_list(self):
        """Empty values list should return empty"""
        modifier = IPvPermit(
            type="ip-permit",
            subnets=["192.168.0.0/16"]
        )

        result = modifier.refresh([])

        assert result == []

    def test_no_matching_ips(self):
        """No IPs match the permit subnets"""
        modifier = IPvPermit(
            type="ip-permit",
            subnets=["192.168.0.0/16"]
        )

        values = [
            IPv4Network("10.0.0.0/8"),
            IPv4Network("172.16.0.0/12"),
            IPv4Network("8.8.8.8/32"),
        ]

        result = modifier.refresh(values)

        assert result == []

    def test_all_ips_match(self):
        """All IPs match the permit subnets"""
        modifier = IPvPermit(
            type="ip-permit",
            subnets=["0.0.0.0/0"]  # Permits all IPv4
        )

        values = [
            IPv4Network("192.168.1.0/24"),
            IPv4Network("10.0.0.0/8"),
            IPv4Network("8.8.8.8/32"),
        ]

        result = modifier.refresh(values)

        assert len(result) == 3


# ============================================================================
# TEST IPVDENY MODIFIER (INVERSE OF PERMIT)
# ============================================================================

class TestIPvDenyModifier:
    """Test IPvDeny modifier - denies IPs within specified subnets"""

    def test_single_subnet_deny_ipv4(self):
        """Deny IPs within a single IPv4 subnet"""
        modifier = IPvDeny(
            type="ip-deny",
            subnets=["192.168.0.0/16"]
        )

        values = [
            IPv4Network("192.168.1.0/24"),    # Within subnet - denied
            IPv4Network("10.0.0.0/8"),        # Outside subnet - allowed
            IPv4Network("192.168.2.5/32"),    # Within subnet - denied
            IPv4Network("8.8.8.8/32"),        # Outside subnet - allowed
        ]

        result = modifier.refresh(values)

        assert len(result) == 2
        assert IPv4Network("10.0.0.0/8") in result
        assert IPv4Network("8.8.8.8/32") in result
        assert IPv4Network("192.168.1.0/24") not in result
        assert IPv4Network("192.168.2.5/32") not in result

    def test_single_subnet_deny_ipv6(self):
        """Deny IPs within a single IPv6 subnet"""
        modifier = IPvDeny(
            type="ip-deny",
            subnets=["2001:db8::/32"]
        )

        values = [
            IPv6Network("2001:db8::1/128"),      # Within - denied
            IPv6Network("fe80::/10"),            # Outside - allowed
            IPv6Network("2001:db8:abcd::/48"),   # Within - denied
        ]

        result = modifier.refresh(values)

        assert len(result) == 1
        assert IPv6Network("fe80::/10") in result

    def test_multiple_subnets_deny(self):
        """Deny IPs within multiple subnets"""
        modifier = IPvDeny(
            type="ip-deny",
            subnets=["192.168.0.0/16", "10.0.0.0/8"]
        )

        values = [
            IPv4Network("192.168.1.0/24"),    # Denied
            IPv4Network("10.5.0.0/16"),       # Denied
            IPv4Network("8.8.8.8/32"),        # Allowed
            IPv4Network("172.16.0.0/12"),     # Allowed
        ]

        result = modifier.refresh(values)

        assert len(result) == 2
        assert IPv4Network("8.8.8.8/32") in result
        assert IPv4Network("172.16.0.0/12") in result

    def test_mixed_ipv4_ipv6_subnets(self):
        """Deny with both IPv4 and IPv6 subnets"""
        modifier = IPvDeny(
            type="ip-deny",
            subnets=["192.168.0.0/16", "2001:db8::/32"]
        )

        values = [
            IPv4Network("192.168.1.0/24"),       # Denied
            IPv6Network("2001:db8::1/128"),      # Denied
            IPv4Network("10.0.0.0/8"),           # Allowed
            IPv6Network("fe80::/10"),            # Allowed
        ]

        result = modifier.refresh(values)

        assert len(result) == 2
        assert IPv4Network("10.0.0.0/8") in result
        assert IPv6Network("fe80::/10") in result

    def test_exact_match_deny_slash_32(self):
        """Test /32 exact IP deny"""
        modifier = IPvDeny(
            type="ip-deny",
            subnets=["192.168.1.100/32"]
        )

        values = [
            IPv4Network("192.168.1.100/32"),  # Exact match - denied
            IPv4Network("192.168.1.101/32"),  # Different - allowed
            IPv4Network("192.168.1.0/24"),    # Broader - allowed
        ]

        result = modifier.refresh(values)

        assert len(result) == 2
        assert IPv4Network("192.168.1.100/32") not in result

    def test_overlapping_deny_subnets(self):
        """Test with overlapping deny subnets"""
        modifier = IPvDeny(
            type="ip-deny",
            subnets=["192.168.0.0/16", "192.168.1.0/24"]
        )

        values = [
            IPv4Network("192.168.1.100/32"),  # In both - denied
            IPv4Network("192.168.2.0/24"),    # In first - denied
            IPv4Network("10.0.0.0/8"),        # In neither - allowed
        ]

        result = modifier.refresh(values)

        assert len(result) == 1
        assert IPv4Network("10.0.0.0/8") in result

    def test_non_ip_values_pass_through(self):
        """Non-IP values should pass through"""
        modifier = IPvDeny(
            type="ip-deny",
            subnets=["192.168.0.0/16"]
        )

        values = [
            IPv4Network("192.168.1.0/24"),  # Denied
            "example.com",                   # Passes through
            IPv4Network("10.0.0.0/8"),      # Allowed
            "malicious.org/",                # Passes through
        ]

        result = modifier.refresh(values)

        assert IPv4Network("10.0.0.0/8") in result
        assert "example.com" in result
        assert "malicious.org/" in result
        assert IPv4Network("192.168.1.0/24") not in result

    def test_empty_values_list(self):
        """Empty values list should return empty"""
        modifier = IPvDeny(
            type="ip-deny",
            subnets=["192.168.0.0/16"]
        )

        result = modifier.refresh([])

        assert result == []

    def test_deny_all_ipv4(self):
        """Deny all IPv4 (0.0.0.0/0)"""
        modifier = IPvDeny(
            type="ip-deny",
            subnets=["0.0.0.0/0"]
        )

        values = [
            IPv4Network("192.168.1.0/24"),
            IPv4Network("10.0.0.0/8"),
            IPv4Network("8.8.8.8/32"),
        ]

        result = modifier.refresh(values)

        # All IPv4 should be denied
        assert result == []

    def test_deny_all_ipv6(self):
        """Deny all IPv6 (::/0)"""
        modifier = IPvDeny(
            type="ip-deny",
            subnets=["::/0"]
        )

        values = [
            IPv6Network("2001:db8::/32"),
            IPv6Network("fe80::/10"),
            IPv6Network("::1/128"),
        ]

        result = modifier.refresh(values)

        # All IPv6 should be denied
        assert result == []


# ============================================================================
# TEST MODIFIER SERIALIZATION
# ============================================================================

class TestModifierSerialization:
    """Test subnet serialization in IPvPermit and IPvDeny"""

    def test_ipv_permit_subnet_serialization(self):
        """Test that subnets are serialized to strings"""
        modifier = IPvPermit(
            type="ip-permit",
            subnets=["192.168.0.0/16", "10.0.0.0/8"]
        )

        # Model should serialize subnets
        data = modifier.model_dump()

        assert "subnets" in data
        assert isinstance(data["subnets"], list)
        assert "192.168.0.0/16" in data["subnets"]
        assert "10.0.0.0/8" in data["subnets"]

    def test_ipv_deny_subnet_serialization(self):
        """Test that subnets are serialized to strings"""
        modifier = IPvDeny(
            type="ip-deny",
            subnets=["2001:db8::/32", "fe80::/10"]
        )

        data = modifier.model_dump()

        assert "subnets" in data
        assert isinstance(data["subnets"], list)
        assert "2001:db8::/32" in data["subnets"]
        assert "fe80::/10" in data["subnets"]
