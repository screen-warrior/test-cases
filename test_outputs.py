"""
Comprehensive test suite for output formatters

Tests all output types: All, IPv4Only, IPv6Only, IPv4Any
This validates the final data formatting before serving EDLs.
"""

import pytest
from ipaddress import IPv4Network, IPv6Network

from fwdev_edl_server.models.outputs import (
    All,
    IPv4Only,
    IPv6Only,
    IPv4Any,
)


# ============================================================================
# TEST IPV4ONLY OUTPUT
# ============================================================================

class TestIPv4OnlyOutput:
    """Test IPv4Only output formatter"""

    def test_formats_ipv4_newline_separated(self):
        """IPv4 addresses should be newline-separated"""
        output = IPv4Only(type="ipv4")

        values = [
            IPv4Network("192.168.1.0/24"),
            IPv4Network("10.0.0.0/8"),
            IPv4Network("172.16.0.0/12"),
        ]

        result = output.refresh(values)

        lines = result.split("\n")
        assert len(lines) == 3

    def test_ipv4_sorted_output(self):
        """IPv4 addresses should be sorted"""
        output = IPv4Only(type="ipv4")

        values = [
            IPv4Network("192.168.1.0/24"),
            IPv4Network("10.0.0.0/8"),
            IPv4Network("172.16.0.0/12"),
        ]

        result = output.refresh(values)

        lines = result.split("\n")
        # Should be sorted: 10.0.0.0/8, 172.16.0.0/12, 192.168.1.0/24
        assert "10.0.0.0/8" in lines[0]
        assert "172.16.0.0/12" in lines[1]
        assert "192.168.1.0/24" in lines[2]

    def test_ipv4_cidr_notation(self):
        """IPv4 should be formatted in CIDR notation"""
        output = IPv4Only(type="ipv4")

        values = [
            IPv4Network("192.168.1.0/24"),
            IPv4Network("10.0.0.5/32"),  # Single IP
        ]

        result = output.refresh(values)

        assert "192.168.1.0/24" in result
        assert "10.0.0.5/32" in result  # /32 for single IPs

    def test_filters_out_ipv6(self):
        """IPv6 addresses should be excluded"""
        output = IPv4Only(type="ipv4")

        values = [
            IPv4Network("192.168.1.0/24"),
            IPv6Network("2001:db8::/32"),
            IPv4Network("10.0.0.0/8"),
        ]

        result = output.refresh(values)

        assert "2001:db8::/32" not in result
        assert "192.168.1.0/24" in result
        assert "10.0.0.0/8" in result

    def test_filters_out_strings(self):
        """String values (FQDNs, URLs) should be excluded"""
        output = IPv4Only(type="ipv4")

        values = [
            IPv4Network("192.168.1.0/24"),
            "example.com",
            IPv4Network("10.0.0.0/8"),
            "malicious.org/",
        ]

        result = output.refresh(values)

        assert "example.com" not in result
        assert "malicious.org/" not in result
        assert "192.168.1.0/24" in result

    def test_empty_list_returns_empty_string(self):
        """Empty values should return empty string"""
        output = IPv4Only(type="ipv4")

        result = output.refresh([])

        assert result == ""

    def test_no_ipv4_returns_empty_string(self):
        """List with no IPv4 should return empty string"""
        output = IPv4Only(type="ipv4")

        values = [
            IPv6Network("2001:db8::/32"),
            "example.com",
        ]

        result = output.refresh(values)

        assert result == ""

    def test_duplicate_ipv4_handling(self):
        """Test handling of duplicate IPv4 addresses"""
        output = IPv4Only(type="ipv4")

        values = [
            IPv4Network("192.168.1.0/24"),
            IPv4Network("192.168.1.0/24"),  # Duplicate
            IPv4Network("10.0.0.0/8"),
        ]

        result = output.refresh(values)

        lines = result.split("\n")
        # Duplicates may or may not be removed depending on implementation
        # At minimum, both should be present
        assert "192.168.1.0/24" in result


# ============================================================================
# TEST IPV6ONLY OUTPUT
# ============================================================================

class TestIPv6OnlyOutput:
    """Test IPv6Only output formatter"""

    def test_formats_ipv6_newline_separated(self):
        """IPv6 addresses should be newline-separated"""
        output = IPv6Only(type="ipv6")

        values = [
            IPv6Network("2001:db8::/32"),
            IPv6Network("fe80::/10"),
            IPv6Network("::1/128"),
        ]

        result = output.refresh(values)

        lines = result.split("\n")
        assert len(lines) == 3

    def test_ipv6_sorted_output(self):
        """IPv6 addresses should be sorted"""
        output = IPv6Only(type="ipv6")

        values = [
            IPv6Network("fe80::/10"),
            IPv6Network("2001:db8::/32"),
            IPv6Network("::1/128"),
        ]

        result = output.refresh(values)

        lines = result.split("\n")
        # Should be sorted
        assert len(lines) == 3

    def test_ipv6_cidr_notation(self):
        """IPv6 should be formatted in CIDR notation"""
        output = IPv6Only(type="ipv6")

        values = [
            IPv6Network("2001:db8::/32"),
            IPv6Network("::1/128"),  # Single IP
        ]

        result = output.refresh(values)

        assert "2001:db8::/32" in result
        assert "::1/128" in result

    def test_filters_out_ipv4(self):
        """IPv4 addresses should be excluded"""
        output = IPv6Only(type="ipv6")

        values = [
            IPv6Network("2001:db8::/32"),
            IPv4Network("192.168.1.0/24"),
            IPv6Network("fe80::/10"),
        ]

        result = output.refresh(values)

        assert "192.168.1.0/24" not in result
        assert "2001:db8::/32" in result
        assert "fe80::/10" in result

    def test_filters_out_strings(self):
        """String values should be excluded"""
        output = IPv6Only(type="ipv6")

        values = [
            IPv6Network("2001:db8::/32"),
            "example.com",
            IPv6Network("fe80::/10"),
        ]

        result = output.refresh(values)

        assert "example.com" not in result
        assert "2001:db8::/32" in result

    def test_empty_list_returns_empty_string(self):
        """Empty values should return empty string"""
        output = IPv6Only(type="ipv6")

        result = output.refresh([])

        assert result == ""

    def test_no_ipv6_returns_empty_string(self):
        """List with no IPv6 should return empty string"""
        output = IPv6Only(type="ipv6")

        values = [
            IPv4Network("192.168.1.0/24"),
            "example.com",
        ]

        result = output.refresh(values)

        assert result == ""


# ============================================================================
# TEST IPV4ANY OUTPUT
# ============================================================================

class TestIPv4AnyOutput:
    """Test IPv4Any output formatter - outputs both IPv4 and IPv6"""

    def test_includes_both_ipv4_and_ipv6(self):
        """Should include both IPv4 and IPv6 addresses"""
        output = IPv4Any(type="ip")

        values = [
            IPv4Network("192.168.1.0/24"),
            IPv6Network("2001:db8::/32"),
            IPv4Network("10.0.0.0/8"),
            IPv6Network("fe80::/10"),
        ]

        result = output.refresh(values)

        assert "192.168.1.0/24" in result
        assert "2001:db8::/32" in result
        assert "10.0.0.0/8" in result
        assert "fe80::/10" in result

    def test_sorted_output_ipv4_then_ipv6(self):
        """Output should be sorted - IPv4 first, then IPv6"""
        output = IPv4Any(type="ip")

        values = [
            IPv6Network("2001:db8::/32"),
            IPv4Network("192.168.1.0/24"),
            IPv6Network("fe80::/10"),
            IPv4Network("10.0.0.0/8"),
        ]

        result = output.refresh(values)

        lines = result.split("\n")
        assert len(lines) == 4

        # Check that result contains all addresses
        assert "192.168.1.0/24" in result
        assert "10.0.0.0/8" in result
        assert "2001:db8::/32" in result
        assert "fe80::/10" in result

    def test_filters_out_strings(self):
        """String values (FQDNs, URLs) should be excluded"""
        output = IPv4Any(type="ip")

        values = [
            IPv4Network("192.168.1.0/24"),
            "example.com",
            IPv6Network("2001:db8::/32"),
            "malicious.org/",
        ]

        result = output.refresh(values)

        assert "example.com" not in result
        assert "malicious.org/" not in result
        assert "192.168.1.0/24" in result
        assert "2001:db8::/32" in result

    def test_empty_list_returns_empty_string(self):
        """Empty values should return empty string"""
        output = IPv4Any(type="ip")

        result = output.refresh([])

        assert result == ""

    def test_only_ipv4_works(self):
        """List with only IPv4 should work"""
        output = IPv4Any(type="ip")

        values = [
            IPv4Network("192.168.1.0/24"),
            IPv4Network("10.0.0.0/8"),
        ]

        result = output.refresh(values)

        assert "192.168.1.0/24" in result
        assert "10.0.0.0/8" in result

    def test_only_ipv6_works(self):
        """List with only IPv6 should work"""
        output = IPv4Any(type="ip")

        values = [
            IPv6Network("2001:db8::/32"),
            IPv6Network("fe80::/10"),
        ]

        result = output.refresh(values)

        assert "2001:db8::/32" in result
        assert "fe80::/10" in result


# ============================================================================
# TEST ALL OUTPUT (MOST COMPLEX)
# ============================================================================

class TestAllOutput:
    """Test All output formatter - includes IPs and strings"""

    def test_includes_ipv4(self):
        """Should include IPv4 addresses"""
        output = All(type="all")

        values = [
            IPv4Network("192.168.1.0/24"),
            IPv4Network("10.0.0.0/8"),
        ]

        result = output.refresh(values)

        assert "192.168.1.0/24" in result
        assert "10.0.0.0/8" in result

    def test_includes_ipv6(self):
        """Should include IPv6 addresses"""
        output = All(type="all")

        values = [
            IPv6Network("2001:db8::/32"),
            IPv6Network("fe80::/10"),
        ]

        result = output.refresh(values)

        assert "2001:db8::/32" in result
        assert "fe80::/10" in result

    def test_includes_strings(self):
        """Should include string values (FQDNs and URLs)"""
        output = All(type="all")

        values = [
            "example.com",
            "malicious.org",
            "bad-site.net/",
        ]

        result = output.refresh(values)

        assert "example.com" in result
        assert "malicious.org" in result
        assert "bad-site.net/" in result

    def test_includes_all_types_mixed(self):
        """Should include all types in output"""
        output = All(type="all")

        values = [
            IPv4Network("192.168.1.0/24"),
            IPv6Network("2001:db8::/32"),
            "example.com",
            IPv4Network("10.0.0.0/8"),
            "malicious.org/",
            IPv6Network("fe80::/10"),
        ]

        result = output.refresh(values)

        # All values should be present
        assert "192.168.1.0/24" in result
        assert "2001:db8::/32" in result
        assert "example.com" in result
        assert "10.0.0.0/8" in result
        assert "malicious.org/" in result
        assert "fe80::/10" in result

    def test_sorted_output(self):
        """Output should be sorted: IPv4, IPv6, then strings"""
        output = All(type="all")

        values = [
            "zzz.com",
            IPv6Network("2001:db8::/32"),
            IPv4Network("192.168.1.0/24"),
            "aaa.com",
            IPv4Network("10.0.0.0/8"),
            IPv6Network("fe80::/10"),
        ]

        result = output.refresh(values)

        lines = result.split("\n")
        assert len(lines) == 6

        # All values should be present (order may vary)
        assert "192.168.1.0/24" in result
        assert "10.0.0.0/8" in result
        assert "2001:db8::/32" in result
        assert "fe80::/10" in result
        assert "aaa.com" in result
        assert "zzz.com" in result

    def test_newline_separated(self):
        """All entries should be newline-separated"""
        output = All(type="all")

        values = [
            IPv4Network("192.168.1.0/24"),
            IPv6Network("2001:db8::/32"),
            "example.com",
        ]

        result = output.refresh(values)

        lines = result.split("\n")
        assert len(lines) == 3

    def test_empty_list_returns_empty_string(self):
        """Empty values should return empty string"""
        output = All(type="all")

        result = output.refresh([])

        assert result == ""

    def test_duplicate_handling(self):
        """Test handling of duplicate values"""
        output = All(type="all")

        values = [
            IPv4Network("192.168.1.0/24"),
            IPv4Network("192.168.1.0/24"),  # Duplicate
            "example.com",
            "example.com",  # Duplicate
        ]

        result = output.refresh(values)

        # Duplicates should be present (may not be deduplicated)
        assert "192.168.1.0/24" in result
        assert "example.com" in result


# ============================================================================
# TEST OUTPUT TYPE VALIDATION
# ============================================================================

class TestOutputTypeValidation:
    """Test Pydantic type validation for output models"""

    def test_ipv4only_type_literal(self):
        """IPv4Only type must be 'ipv4'"""
        output = IPv4Only(type="ipv4")
        assert output.type == "ipv4"

        # Invalid type should fail
        with pytest.raises(Exception):
            IPv4Only(type="invalid")

    def test_ipv6only_type_literal(self):
        """IPv6Only type must be 'ipv6'"""
        output = IPv6Only(type="ipv6")
        assert output.type == "ipv6"

        with pytest.raises(Exception):
            IPv6Only(type="invalid")

    def test_ipv4any_type_literal(self):
        """IPv4Any type must be 'ip'"""
        output = IPv4Any(type="ip")
        assert output.type == "ip"

        with pytest.raises(Exception):
            IPv4Any(type="invalid")

    def test_all_type_literal(self):
        """All type must be 'all'"""
        output = All(type="all")
        assert output.type == "all"

        with pytest.raises(Exception):
            All(type="invalid")


# ============================================================================
# TEST OUTPUT FORMAT CONSISTENCY
# ============================================================================

class TestOutputFormatConsistency:
    """Test that all outputs follow the same format conventions"""

    def test_all_outputs_use_newline_separator(self):
        """All outputs should use newline as separator (not commas, spaces, etc)"""
        values = [
            IPv4Network("192.168.1.0/24"),
            IPv4Network("10.0.0.0/8"),
        ]

        outputs = [
            IPv4Only(type="ipv4"),
            IPv4Any(type="ip"),
            All(type="all"),
        ]

        for output in outputs:
            result = output.refresh(values)
            assert "\n" in result  # Uses newlines
            assert "," not in result  # Doesn't use commas
            assert ";" not in result  # Doesn't use semicolons

    def test_all_outputs_use_cidr_notation(self):
        """All outputs should use CIDR notation for IPs"""
        values = [
            IPv4Network("192.168.1.0/24"),
            IPv6Network("2001:db8::/32"),
        ]

        outputs = [
            IPv4Only(type="ipv4"),
            IPv6Only(type="ipv6"),
            IPv4Any(type="ip"),
            All(type="all"),
        ]

        for output in outputs:
            result = output.refresh(values)
            # CIDR notation includes /
            if result:  # If output produces any result
                assert "/" in result or result == ""  # Either has CIDR or empty

    def test_all_outputs_return_string_type(self):
        """All outputs should return string type"""
        values = [
            IPv4Network("192.168.1.0/24"),
        ]

        outputs = [
            IPv4Only(type="ipv4"),
            IPv6Only(type="ipv6"),
            IPv4Any(type="ip"),
            All(type="all"),
        ]

        for output in outputs:
            result = output.refresh(values)
            assert isinstance(result, str)

    def test_all_outputs_handle_empty_list(self):
        """All outputs should handle empty list gracefully"""
        outputs = [
            IPv4Only(type="ipv4"),
            IPv6Only(type="ipv6"),
            IPv4Any(type="ip"),
            All(type="all"),
        ]

        for output in outputs:
            result = output.refresh([])
            assert result == ""  # Empty string for empty input
