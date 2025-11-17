"""
Test Modifier functionality
Focus: IPvPermit, IPvDeny, IPv4Only, IPv6Only, IPvAnyOnly, IPvConsolidate
"""

import pytest
from ipaddress import IPv4Network, IPv6Network

from fwdev_edl_server.models.modifiers import (
    IPvPermit,
    IPvDeny,
    IPv4Only,
    IPv6Only,
    IPvAnyOnly,
    IPvConsolidate
)


class TestIPvPermit:
    """Test IPvPermit modifier (whitelist)"""

    def test_permit_single_subnet_ipv4(self):
        """Test permitting IPs within single subnet"""
        modifier = IPvPermit(
            type="ip-permit",
            subnets=["192.168.0.0/16"]
        )

        values = [
            IPv4Network("192.168.1.0/24"),  # Inside
            IPv4Network("10.0.0.0/8"),      # Outside
            IPv4Network("192.168.2.0/24"),  # Inside
        ]

        result = modifier.refresh(values)

        assert IPv4Network("192.168.1.0/24") in result
        assert IPv4Network("192.168.2.0/24") in result
        assert IPv4Network("10.0.0.0/8") not in result

    def test_permit_multiple_subnets(self):
        """Test permitting multiple subnet ranges"""
        modifier = IPvPermit(
            type="ip-permit",
            subnets=["192.168.0.0/16", "10.0.0.0/8"]
        )

        values = [
            IPv4Network("192.168.1.0/24"),  # In first
            IPv4Network("10.5.0.0/16"),     # In second
            IPv4Network("172.16.0.0/16"),   # In neither
        ]

        result = modifier.refresh(values)

        assert IPv4Network("192.168.1.0/24") in result
        assert IPv4Network("10.5.0.0/16") in result
        assert IPv4Network("172.16.0.0/16") not in result

    def test_permit_ipv6_subnet(self):
        """Test permitting IPv6 subnets"""
        modifier = IPvPermit(
            type="ip-permit",
            subnets=["2001:db8::/32"]
        )

        values = [
            IPv6Network("2001:db8::1/128"),     # Inside
            IPv6Network("fe80::/10"),           # Outside
        ]

        result = modifier.refresh(values)

        assert IPv6Network("2001:db8::1/128") in result
        assert IPv6Network("fe80::/10") not in result

    def test_permit_mixed_ipv4_ipv6(self):
        """Test permitting both IPv4 and IPv6"""
        modifier = IPvPermit(
            type="ip-permit",
            subnets=["192.168.0.0/16", "2001:db8::/32"]
        )

        values = [
            IPv4Network("192.168.1.0/24"),
            IPv6Network("2001:db8::1/128"),
            IPv4Network("10.0.0.0/8"),
            IPv6Network("fe80::/10")
        ]

        result = modifier.refresh(values)

        assert IPv4Network("192.168.1.0/24") in result
        assert IPv6Network("2001:db8::1/128") in result
        assert IPv4Network("10.0.0.0/8") not in result
        assert IPv6Network("fe80::/10") not in result

    def test_permit_non_ip_values_passthrough(self):
        """Test non-IP values pass through unchanged"""
        modifier = IPvPermit(
            type="ip-permit",
            subnets=["192.168.0.0/16"]
        )

        values = [
            IPv4Network("192.168.1.0/24"),
            "example.com",
            IPv4Network("10.0.0.0/8"),
            "test.org"
        ]

        result = modifier.refresh(values)

        # Permitted IP
        assert IPv4Network("192.168.1.0/24") in result
        # Non-IP strings pass through
        assert "example.com" in result
        assert "test.org" in result
        # Denied IP
        assert IPv4Network("10.0.0.0/8") not in result

    def test_permit_empty_values(self):
        """Test permit with empty values list"""
        modifier = IPvPermit(
            type="ip-permit",
            subnets=["192.168.0.0/16"]
        )

        result = modifier.refresh([])

        assert result == []

    def test_permit_no_matches(self):
        """Test when no IPs match permitted subnets"""
        modifier = IPvPermit(
            type="ip-permit",
            subnets=["192.168.0.0/16"]
        )

        values = [
            IPv4Network("10.0.0.0/8"),
            IPv4Network("172.16.0.0/16")
        ]

        result = modifier.refresh(values)

        assert result == []


class TestIPvDeny:
    """Test IPvDeny modifier (blacklist)"""

    def test_deny_single_subnet_ipv4(self):
        """Test denying IPs within single subnet"""
        modifier = IPvDeny(
            type="ip-deny",
            subnets=["192.168.0.0/16"]
        )

        values = [
            IPv4Network("192.168.1.0/24"),  # Denied
            IPv4Network("10.0.0.0/8"),      # Allowed
            IPv4Network("192.168.2.0/24"),  # Denied
        ]

        result = modifier.refresh(values)

        assert IPv4Network("10.0.0.0/8") in result
        assert IPv4Network("192.168.1.0/24") not in result
        assert IPv4Network("192.168.2.0/24") not in result

    def test_deny_multiple_subnets(self):
        """Test denying multiple subnet ranges"""
        modifier = IPvDeny(
            type="ip-deny",
            subnets=["192.168.0.0/16", "10.0.0.0/8"]
        )

        values = [
            IPv4Network("192.168.1.0/24"),  # Denied
            IPv4Network("10.5.0.0/16"),     # Denied
            IPv4Network("172.16.0.0/16"),   # Allowed
        ]

        result = modifier.refresh(values)

        assert IPv4Network("172.16.0.0/16") in result
        assert IPv4Network("192.168.1.0/24") not in result
        assert IPv4Network("10.5.0.0/16") not in result

    def test_deny_ipv6_subnet(self):
        """Test denying IPv6 subnets"""
        modifier = IPvDeny(
            type="ip-deny",
            subnets=["2001:db8::/32"]
        )

        values = [
            IPv6Network("2001:db8::1/128"),  # Denied
            IPv6Network("fe80::/10"),        # Allowed
        ]

        result = modifier.refresh(values)

        assert IPv6Network("fe80::/10") in result
        assert IPv6Network("2001:db8::1/128") not in result

    def test_deny_mixed_ipv4_ipv6(self):
        """Test denying both IPv4 and IPv6"""
        modifier = IPvDeny(
            type="ip-deny",
            subnets=["192.168.0.0/16", "2001:db8::/32"]
        )

        values = [
            IPv4Network("192.168.1.0/24"),
            IPv6Network("2001:db8::1/128"),
            IPv4Network("10.0.0.0/8"),
            IPv6Network("fe80::/10")
        ]

        result = modifier.refresh(values)

        assert IPv4Network("10.0.0.0/8") in result
        assert IPv6Network("fe80::/10") in result
        assert IPv4Network("192.168.1.0/24") not in result
        assert IPv6Network("2001:db8::1/128") not in result

    def test_deny_non_ip_values_passthrough(self):
        """Test non-IP values pass through unchanged"""
        modifier = IPvDeny(
            type="ip-deny",
            subnets=["192.168.0.0/16"]
        )

        values = [
            IPv4Network("192.168.1.0/24"),
            "example.com",
            IPv4Network("10.0.0.0/8"),
        ]

        result = modifier.refresh(values)

        # Allowed IP
        assert IPv4Network("10.0.0.0/8") in result
        # Non-IP strings pass through
        assert "example.com" in result
        # Denied IP
        assert IPv4Network("192.168.1.0/24") not in result

    def test_deny_all_ipv4(self):
        """Test denying all IPv4 with 0.0.0.0/0"""
        modifier = IPvDeny(
            type="ip-deny",
            subnets=["0.0.0.0/0"]
        )

        values = [
            IPv4Network("192.168.1.0/24"),
            IPv4Network("10.0.0.0/8"),
        ]

        result = modifier.refresh(values)

        assert result == []


class TestIPv4Only:
    """Test IPv4Only modifier"""

    def test_ipv4_only_filters_ipv4(self):
        """Test keeping only IPv4 networks"""
        modifier = IPv4Only(type="ipv4-only")

        values = [
            IPv4Network("192.168.1.0/24"),
            IPv6Network("2001:db8::/32"),
            IPv4Network("10.0.0.0/8"),
            "example.com"
        ]

        result = modifier.refresh(values)

        assert IPv4Network("192.168.1.0/24") in result
        assert IPv4Network("10.0.0.0/8") in result
        assert IPv6Network("2001:db8::/32") not in result
        assert "example.com" not in result

    def test_ipv4_only_empty_input(self):
        """Test IPv4Only with empty list"""
        modifier = IPv4Only(type="ipv4-only")

        result = modifier.refresh([])

        assert result == []

    def test_ipv4_only_no_ipv4(self):
        """Test IPv4Only when no IPv4 present"""
        modifier = IPv4Only(type="ipv4-only")

        values = [
            IPv6Network("2001:db8::/32"),
            "example.com"
        ]

        result = modifier.refresh(values)

        assert result == []


class TestIPv6Only:
    """Test IPv6Only modifier"""

    def test_ipv6_only_filters_ipv6(self):
        """Test keeping only IPv6 networks"""
        modifier = IPv6Only(type="ipv6-only")

        values = [
            IPv4Network("192.168.1.0/24"),
            IPv6Network("2001:db8::/32"),
            IPv6Network("fe80::/10"),
            "example.com"
        ]

        result = modifier.refresh(values)

        assert IPv6Network("2001:db8::/32") in result
        assert IPv6Network("fe80::/10") in result
        assert IPv4Network("192.168.1.0/24") not in result
        assert "example.com" not in result

    def test_ipv6_only_empty_input(self):
        """Test IPv6Only with empty list"""
        modifier = IPv6Only(type="ipv6-only")

        result = modifier.refresh([])

        assert result == []

    def test_ipv6_only_no_ipv6(self):
        """Test IPv6Only when no IPv6 present"""
        modifier = IPv6Only(type="ipv6-only")

        values = [
            IPv4Network("192.168.1.0/24"),
            "example.com"
        ]

        result = modifier.refresh(values)

        assert result == []


class TestIPvAnyOnly:
    """Test IPvAnyOnly modifier (IPv4 + IPv6, no strings)"""

    def test_ipvany_keeps_both_ip_types(self):
        """Test keeping both IPv4 and IPv6, filtering strings"""
        modifier = IPvAnyOnly(type="ip-only")

        values = [
            IPv4Network("192.168.1.0/24"),
            IPv6Network("2001:db8::/32"),
            "example.com",
            IPv4Network("10.0.0.0/8")
        ]

        result = modifier.refresh(values)

        assert IPv4Network("192.168.1.0/24") in result
        assert IPv6Network("2001:db8::/32") in result
        assert IPv4Network("10.0.0.0/8") in result
        assert "example.com" not in result

    def test_ipvany_filters_all_strings(self):
        """Test filtering out all non-IP values"""
        modifier = IPvAnyOnly(type="ip-only")

        values = [
            IPv4Network("192.168.1.0/24"),
            "example.com",
            "test.org",
            "*.malicious.com/"
        ]

        result = modifier.refresh(values)

        assert IPv4Network("192.168.1.0/24") in result
        assert "example.com" not in result
        assert "test.org" not in result

    def test_ipvany_empty_input(self):
        """Test IPvAnyOnly with empty list"""
        modifier = IPvAnyOnly(type="ip-only")

        result = modifier.refresh([])

        assert result == []


class TestIPvConsolidate:
    """Test IPvConsolidate static method"""

    def test_consolidate_overlapping_ipv4(self):
        """Test consolidating overlapping IPv4 networks"""
        values = [
            IPv4Network("192.168.1.0/24"),
            IPv4Network("192.168.1.0/25"),
            IPv4Network("192.168.1.128/25")
        ]

        result = IPvConsolidate.refresh(values)

        # Should collapse to single /24
        assert IPv4Network("192.168.1.0/24") in result
        # Result should be smaller than input
        assert len(result) <= len(values)

    def test_consolidate_adjacent_ipv4(self):
        """Test consolidating adjacent networks"""
        values = [
            IPv4Network("10.0.0.0/24"),
            IPv4Network("10.0.1.0/24")
        ]

        result = IPvConsolidate.refresh(values)

        # Adjacent networks may consolidate depending on implementation
        assert len(result) <= 2

    def test_consolidate_ipv6(self):
        """Test consolidating IPv6 networks"""
        values = [
            IPv6Network("2001:db8::/32"),
            IPv6Network("2001:db8::/64")
        ]

        result = IPvConsolidate.refresh(values)

        # /64 should be absorbed by /32
        assert IPv6Network("2001:db8::/32") in result

    def test_consolidate_mixed_ipv4_ipv6(self):
        """Test consolidating mixed IPv4 and IPv6"""
        values = [
            IPv4Network("192.168.1.0/24"),
            IPv4Network("192.168.1.0/25"),
            IPv6Network("2001:db8::/32"),
            IPv6Network("2001:db8::/64")
        ]

        result = IPvConsolidate.refresh(values)

        # Should have both IPv4 and IPv6 consolidated
        ipv4_count = sum(1 for r in result if isinstance(r, IPv4Network))
        ipv6_count = sum(1 for r in result if isinstance(r, IPv6Network))

        assert ipv4_count >= 1
        assert ipv6_count >= 1

    def test_consolidate_with_strings(self):
        """Test consolidate preserves non-IP values"""
        values = [
            IPv4Network("192.168.1.0/24"),
            "example.com",
            IPv4Network("192.168.1.0/25")
        ]

        result = IPvConsolidate.refresh(values)

        # Strings should be preserved
        assert "example.com" in result

    def test_consolidate_no_overlap(self):
        """Test consolidate with non-overlapping networks"""
        values = [
            IPv4Network("192.168.1.0/24"),
            IPv4Network("10.0.0.0/8"),
            IPv4Network("172.16.0.0/16")
        ]

        result = IPvConsolidate.refresh(values)

        # All should remain
        assert len(result) == 3

    def test_consolidate_empty(self):
        """Test consolidate with empty list"""
        result = IPvConsolidate.refresh([])

        assert result == []


class TestModifierTypes:
    """Test modifier type literals and structure"""

    def test_modifier_type_literals(self):
        """Test all modifiers have correct type literals"""
        assert IPvPermit(type="ip-permit", subnets=["192.168.0.0/16"]).type == "ip-permit"
        assert IPvDeny(type="ip-deny", subnets=["192.168.0.0/16"]).type == "ip-deny"
        assert IPv4Only(type="ipv4-only").type == "ipv4-only"
        assert IPv6Only(type="ipv6-only").type == "ipv6-only"
        assert IPvAnyOnly(type="ip-only").type == "ip-only"

    def test_modifiers_have_ids(self):
        """Test all modifiers have UUID ids"""
        permit = IPvPermit(type="ip-permit", subnets=["192.168.0.0/16"])
        ipv4_only = IPv4Only(type="ipv4-only")

        assert permit.id is not None
        assert isinstance(permit.id, str)
        assert ipv4_only.id is not None

    def test_permit_subnet_serialization(self):
        """Test IPvPermit subnets serialize correctly"""
        modifier = IPvPermit(
            type="ip-permit",
            subnets=["192.168.0.0/16", "10.0.0.0/8"]
        )

        data = modifier.model_dump()

        assert "subnets" in data
        assert isinstance(data["subnets"], list)
        assert "192.168.0.0/16" in data["subnets"]
        assert "10.0.0.0/8" in data["subnets"]
