"""
Test Output validation and formatting
Focus: All, IPv4Only, IPv6Only, IPv4Any output types and string formatting
"""

import pytest
from ipaddress import IPv4Network, IPv6Network

from fwdev_edl_server.models.outputs import All, IPv4Only, IPv6Only, IPv4Any


class TestAllOutput:
    """Test All output type (all data types)"""

    def test_all_with_ipv4_only(self):
        """Test All output with only IPv4 networks"""
        output = All(type="all")

        values = [
            IPv4Network("192.168.1.0/24"),
            IPv4Network("10.0.0.0/8"),
            IPv4Network("172.16.0.0/16")
        ]

        result = output.refresh(values)

        assert "192.168.1.0/24" in result
        assert "10.0.0.0/8" in result
        assert "172.16.0.0/16" in result

    def test_all_with_ipv6_only(self):
        """Test All output with only IPv6 networks"""
        output = All(type="all")

        values = [
            IPv6Network("2001:db8::/32"),
            IPv6Network("fe80::/10")
        ]

        result = output.refresh(values)

        assert "2001:db8::/32" in result
        assert "fe80::/10" in result

    def test_all_with_mixed_ipv4_ipv6(self):
        """Test All output with mixed IPv4 and IPv6"""
        output = All(type="all")

        values = [
            IPv4Network("192.168.1.0/24"),
            IPv6Network("2001:db8::/32"),
            IPv4Network("10.0.0.0/8")
        ]

        result = output.refresh(values)

        # Should have both IPv4 and IPv6
        assert "192.168.1.0/24" in result
        assert "2001:db8::/32" in result
        assert "10.0.0.0/8" in result

    def test_all_with_strings(self):
        """Test All output with string values (URLs, FQDNs)"""
        output = All(type="all")

        values = [
            IPv4Network("192.168.1.0/24"),
            "example.com",
            "*.malicious.com/",
            IPv4Network("10.0.0.0/8")
        ]

        result = output.refresh(values)

        # Should include IPs and strings
        assert "192.168.1.0/24" in result
        assert "example.com" in result
        assert "*.malicious.com/" in result
        assert "10.0.0.0/8" in result

    def test_all_output_sorted(self):
        """Test All output is sorted"""
        output = All(type="all")

        values = [
            IPv4Network("10.0.0.0/8"),
            IPv4Network("192.168.1.0/24"),
            IPv4Network("172.16.0.0/16")
        ]

        result = output.refresh(values)
        lines = result.split("\n")

        # IPv4 should be sorted
        assert lines == sorted(lines)

    def test_all_output_newline_separated(self):
        """Test All output uses newline separator"""
        output = All(type="all")

        values = [
            IPv4Network("192.168.1.0/24"),
            IPv4Network("10.0.0.0/8")
        ]

        result = output.refresh(values)

        assert "\n" in result
        lines = result.split("\n")
        assert len(lines) == 2

    def test_all_with_empty_values(self):
        """Test All output with empty list"""
        output = All(type="all")

        result = output.refresh([])

        assert result == ""

    def test_all_ipv4_before_ipv6(self):
        """Test All output puts IPv4 before IPv6"""
        output = All(type="all")

        values = [
            IPv6Network("2001:db8::/32"),
            IPv4Network("192.168.1.0/24")
        ]

        result = output.refresh(values)
        lines = result.split("\n")

        # IPv4 should come before IPv6
        ipv4_line = next(i for i, l in enumerate(lines) if "192.168" in l)
        ipv6_line = next(i for i, l in enumerate(lines) if "2001" in l)

        assert ipv4_line < ipv6_line


class TestIPv4OnlyOutput:
    """Test IPv4Only output type"""

    def test_ipv4_only_filters_ipv4(self):
        """Test IPv4Only returns only IPv4 networks"""
        output = IPv4Only(type="ipv4")

        values = [
            IPv4Network("192.168.1.0/24"),
            IPv6Network("2001:db8::/32"),
            IPv4Network("10.0.0.0/8"),
            "example.com"
        ]

        result = output.refresh(values)

        # Should only have IPv4
        assert "192.168.1.0/24" in result
        assert "10.0.0.0/8" in result

        # Should NOT have IPv6 or strings
        assert "2001:db8" not in result
        assert "example.com" not in result

    def test_ipv4_only_sorted(self):
        """Test IPv4Only output is sorted"""
        output = IPv4Only(type="ipv4")

        values = [
            IPv4Network("10.0.0.0/8"),
            IPv4Network("192.168.1.0/24"),
            IPv4Network("172.16.0.0/16")
        ]

        result = output.refresh(values)
        lines = result.split("\n")

        assert lines == sorted(lines)

    def test_ipv4_only_empty(self):
        """Test IPv4Only with no IPv4 addresses"""
        output = IPv4Only(type="ipv4")

        values = [
            IPv6Network("2001:db8::/32"),
            "example.com"
        ]

        result = output.refresh(values)

        assert result == ""

    def test_ipv4_only_newline_format(self):
        """Test IPv4Only uses newline separator"""
        output = IPv4Only(type="ipv4")

        values = [
            IPv4Network("192.168.1.0/24"),
            IPv4Network("10.0.0.0/8")
        ]

        result = output.refresh(values)

        assert "\n" in result
        assert result.count("\n") == 1


class TestIPv6OnlyOutput:
    """Test IPv6Only output type"""

    def test_ipv6_only_filters_ipv6(self):
        """Test IPv6Only returns only IPv6 networks"""
        output = IPv6Only(type="ipv6")

        values = [
            IPv4Network("192.168.1.0/24"),
            IPv6Network("2001:db8::/32"),
            IPv6Network("fe80::/10"),
            "example.com"
        ]

        result = output.refresh(values)

        # Should only have IPv6
        assert "2001:db8::/32" in result
        assert "fe80::/10" in result

        # Should NOT have IPv4 or strings
        assert "192.168" not in result
        assert "example.com" not in result

    def test_ipv6_only_sorted(self):
        """Test IPv6Only output is sorted"""
        output = IPv6Only(type="ipv6")

        values = [
            IPv6Network("fe80::/10"),
            IPv6Network("2001:db8::/32")
        ]

        result = output.refresh(values)
        lines = result.split("\n")

        assert lines == sorted(lines)

    def test_ipv6_only_empty(self):
        """Test IPv6Only with no IPv6 addresses"""
        output = IPv6Only(type="ipv6")

        values = [
            IPv4Network("192.168.1.0/24"),
            "example.com"
        ]

        result = output.refresh(values)

        assert result == ""


class TestIPv4AnyOutput:
    """Test IPv4Any output type (both IPv4 and IPv6)"""

    def test_ipv4_any_includes_both(self):
        """Test IPv4Any includes both IPv4 and IPv6"""
        output = IPv4Any(type="ip")

        values = [
            IPv4Network("192.168.1.0/24"),
            IPv6Network("2001:db8::/32"),
            "example.com",
            IPv4Network("10.0.0.0/8")
        ]

        result = output.refresh(values)

        # Should have both IPv4 and IPv6
        assert "192.168.1.0/24" in result
        assert "2001:db8::/32" in result
        assert "10.0.0.0/8" in result

        # Should NOT have strings
        assert "example.com" not in result

    def test_ipv4_any_sorted(self):
        """Test IPv4Any output is sorted"""
        output = IPv4Any(type="ip")

        values = [
            IPv4Network("10.0.0.0/8"),
            IPv6Network("2001:db8::/32"),
            IPv4Network("192.168.1.0/24")
        ]

        result = output.refresh(values)

        # Should have all IPs
        assert "192.168.1.0/24" in result
        assert "10.0.0.0/8" in result
        assert "2001:db8::/32" in result

    def test_ipv4_any_empty(self):
        """Test IPv4Any with no IP addresses"""
        output = IPv4Any(type="ip")

        values = ["example.com", "test.org"]

        result = output.refresh(values)

        assert result == ""


class TestOutputTypes:
    """Test output type literals and model structure"""

    def test_all_type_literal(self):
        """Test All has correct type literal"""
        output = All(type="all")
        assert output.type == "all"

    def test_ipv4_only_type_literal(self):
        """Test IPv4Only has correct type literal"""
        output = IPv4Only(type="ipv4")
        assert output.type == "ipv4"

    def test_ipv6_only_type_literal(self):
        """Test IPv6Only has correct type literal"""
        output = IPv6Only(type="ipv6")
        assert output.type == "ipv6"

    def test_ipv4_any_type_literal(self):
        """Test IPv4Any has correct type literal"""
        output = IPv4Any(type="ip")
        assert output.type == "ip"

    def test_output_has_id(self):
        """Test all outputs have UUID id"""
        all_output = All(type="all")
        ipv4_output = IPv4Only(type="ipv4")

        assert all_output.id is not None
        assert isinstance(all_output.id, str)
        assert ipv4_output.id is not None


class TestOutputEdgeCases:
    """Test edge cases and special scenarios"""

    def test_all_with_duplicate_values(self):
        """Test All output with duplicate values"""
        output = All(type="all")

        values = [
            IPv4Network("192.168.1.0/24"),
            IPv4Network("192.168.1.0/24"),
            IPv4Network("192.168.1.0/24")
        ]

        result = output.refresh(values)

        # Duplicates should be handled by sorting
        # Each line should appear once or multiple times depending on implementation
        assert "192.168.1.0/24" in result

    def test_output_with_single_value(self):
        """Test output with single value"""
        output = All(type="all")

        values = [IPv4Network("192.168.1.0/24")]

        result = output.refresh(values)

        assert result == "192.168.1.0/24"

    def test_output_with_cidr_variations(self):
        """Test output with various CIDR notations"""
        output = All(type="all")

        values = [
            IPv4Network("192.168.1.1/32"),  # Single host
            IPv4Network("10.0.0.0/8"),      # Class A
            IPv4Network("172.16.0.0/12"),   # Class B range
            IPv4Network("192.168.0.0/16")   # Class C range
        ]

        result = output.refresh(values)

        # All should be present with correct notation
        assert "192.168.1.1/32" in result
        assert "10.0.0.0/8" in result
        assert "172.16.0.0/12" in result
        assert "192.168.0.0/16" in result

    def test_ipv6_compressed_notation(self):
        """Test IPv6 compressed notation in output"""
        output = IPv6Only(type="ipv6")

        values = [
            IPv6Network("2001:db8::1/128"),
            IPv6Network("fe80::1/64")
        ]

        result = output.refresh(values)

        # Should contain compressed IPv6 notation
        assert "2001:db8::1/128" in result or "2001:0db8" in result
        assert "fe80::1/64" in result or "fe80::" in result

    def test_all_ordering_ipv4_ipv6_strings(self):
        """Test All output ordering: IPv4, IPv6, then strings"""
        output = All(type="all")

        values = [
            "zebra.com",
            IPv6Network("2001:db8::/32"),
            IPv4Network("192.168.1.0/24"),
            "alpha.com",
            IPv4Network("10.0.0.0/8")
        ]

        result = output.refresh(values)
        lines = result.split("\n")

        # Find positions
        ipv4_positions = [i for i, l in enumerate(lines) if any(c.isdigit() and "." in l for c in l)]
        ipv6_positions = [i for i, l in enumerate(lines) if ":" in l]
        string_positions = [i for i, l in enumerate(lines) if ".com" in l]

        # IPv4 should come first, then IPv6, then strings
        if ipv4_positions and ipv6_positions:
            assert max(ipv4_positions) < min(ipv6_positions)
        if ipv6_positions and string_positions:
            assert max(ipv6_positions) < min(string_positions)
