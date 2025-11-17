"""
Comprehensive tests for validators.py
Tests skip_invalid wrapper, type aliases, and data validation patterns.
"""

import pytest
from ipaddress import IPv4Network, IPv6Network, IPv4Interface, IPv6Interface
from pydantic import ValidationError, BaseModel
from typing import List

from fwdev_edl_server.validators import (
    skip_invalid,
    AnyUrl,
    AnyFQDN,
    EDL_SUPPORTED_INPUT_TYPES,
    EDL_SUPPORTED_OUTPUT_TYPES
)


class TestSkipInvalidWrapper:
    """Test skip_invalid validator wrapper functionality"""

    def test_skip_invalid_with_valid_ipv4_network(self):
        """Test skip_invalid passes valid IPv4 network"""
        def handler(value):
            return IPv4Network(value)

        result = skip_invalid("192.168.1.0/24", handler)
        assert result == IPv4Network("192.168.1.0/24")

    def test_skip_invalid_with_invalid_ipv4_network(self):
        """Test skip_invalid returns None for invalid IPv4"""
        def handler(value):
            return IPv4Network(value)

        result = skip_invalid("invalid-ip", handler)
        assert result is None

    def test_skip_invalid_with_valid_ipv6_network(self):
        """Test skip_invalid passes valid IPv6 network"""
        def handler(value):
            return IPv6Network(value)

        result = skip_invalid("2001:db8::/32", handler)
        assert result == IPv6Network("2001:db8::/32")

    def test_skip_invalid_with_invalid_ipv6_network(self):
        """Test skip_invalid returns None for invalid IPv6"""
        def handler(value):
            return IPv6Network(value)

        result = skip_invalid("not-an-ipv6", handler)
        assert result is None

    def test_skip_invalid_with_validation_error(self):
        """Test skip_invalid catches ValidationError"""
        def handler(value):
            if not isinstance(value, int):
                raise ValidationError.from_exception_data(
                    "value_error",
                    [{"type": "int_type", "loc": ("value",), "input": value}]
                )
            return value

        result = skip_invalid("not-an-int", handler)
        assert result is None

    def test_skip_invalid_with_valid_string(self):
        """Test skip_invalid with string validation"""
        def handler(value):
            if len(value) < 3:
                raise ValidationError.from_exception_data(
                    "value_error",
                    [{"type": "string_too_short", "loc": ("value",), "input": value}]
                )
            return value

        # Valid
        result = skip_invalid("valid", handler)
        assert result == "valid"

        # Invalid
        result = skip_invalid("no", handler)
        assert result is None


class TestAnyUrlTypeAlias:
    """Test AnyUrl type alias validation"""

    def test_anyurl_valid_url(self):
        """Test AnyUrl accepts valid URLs"""
        class TestModel(BaseModel):
            url: AnyUrl

        # Valid URL with wildcard
        model = TestModel(url="*.example.com/")
        assert model.url == "*.example.com/"

    def test_anyurl_valid_subdomain_url(self):
        """Test AnyUrl with subdomains"""
        class TestModel(BaseModel):
            url: AnyUrl

        model = TestModel(url="sub.example.com/")
        assert model.url == "sub.example.com/"

    def test_anyurl_valid_multi_subdomain(self):
        """Test AnyUrl with multiple subdomains"""
        class TestModel(BaseModel):
            url: AnyUrl

        model = TestModel(url="a.b.c.example.com/")
        assert model.url == "a.b.c.example.com/"

    def test_anyurl_invalid_without_trailing_slash(self):
        """Test AnyUrl requires trailing slash"""
        class TestModel(BaseModel):
            url: AnyUrl

        with pytest.raises(ValidationError) as exc_info:
            TestModel(url="example.com")

        assert "string_pattern_mismatch" in str(exc_info.value)

    def test_anyurl_invalid_without_tld(self):
        """Test AnyUrl requires TLD"""
        class TestModel(BaseModel):
            url: AnyUrl

        with pytest.raises(ValidationError) as exc_info:
            TestModel(url="invalid/")

        assert "string_pattern_mismatch" in str(exc_info.value)

    def test_anyurl_with_wildcard(self):
        """Test AnyUrl with wildcard subdomain"""
        class TestModel(BaseModel):
            url: AnyUrl

        model = TestModel(url="*.wildcard.example.com/")
        assert model.url == "*.wildcard.example.com/"

    def test_anyurl_with_hyphen(self):
        """Test AnyUrl with hyphenated subdomain"""
        class TestModel(BaseModel):
            url: AnyUrl

        model = TestModel(url="sub-domain.example.com/")
        assert model.url == "sub-domain.example.com/"

    def test_anyurl_invalid_tld_too_long(self):
        """Test AnyUrl rejects TLD longer than 18 characters"""
        class TestModel(BaseModel):
            url: AnyUrl

        with pytest.raises(ValidationError):
            TestModel(url="example.verylongtldthatistoolong/")


class TestAnyFQDNTypeAlias:
    """Test AnyFQDN type alias validation"""

    def test_anyfqdn_valid_simple(self):
        """Test AnyFQDN with simple domain"""
        class TestModel(BaseModel):
            fqdn: AnyFQDN

        model = TestModel(fqdn="example.com")
        assert model.fqdn == "example.com"

    def test_anyfqdn_valid_subdomain(self):
        """Test AnyFQDN with subdomain"""
        class TestModel(BaseModel):
            fqdn: AnyFQDN

        model = TestModel(fqdn="sub.example.com")
        assert model.fqdn == "sub.example.com"

    def test_anyfqdn_valid_multi_subdomain(self):
        """Test AnyFQDN with multiple subdomains"""
        class TestModel(BaseModel):
            fqdn: AnyFQDN

        model = TestModel(fqdn="a.b.c.example.com")
        assert model.fqdn == "a.b.c.example.com"

    def test_anyfqdn_invalid_with_trailing_slash(self):
        """Test AnyFQDN rejects trailing slash"""
        class TestModel(BaseModel):
            fqdn: AnyFQDN

        with pytest.raises(ValidationError) as exc_info:
            TestModel(fqdn="example.com/")

        assert "string_pattern_mismatch" in str(exc_info.value)

    def test_anyfqdn_invalid_without_tld(self):
        """Test AnyFQDN requires TLD"""
        class TestModel(BaseModel):
            fqdn: AnyFQDN

        with pytest.raises(ValidationError):
            TestModel(fqdn="invalid")

    def test_anyfqdn_with_hyphen(self):
        """Test AnyFQDN with hyphenated subdomain"""
        class TestModel(BaseModel):
            fqdn: AnyFQDN

        model = TestModel(fqdn="sub-domain.example.com")
        assert model.fqdn == "sub-domain.example.com"

    def test_anyfqdn_max_length_255(self):
        """Test AnyFQDN enforces 255 character limit"""
        class TestModel(BaseModel):
            fqdn: AnyFQDN

        # Create a domain close to 255 characters
        long_domain = "a" * 60 + "." + "b" * 60 + "." + "c" * 60 + "." + "d" * 60 + ".com"

        if len(long_domain) <= 255:
            model = TestModel(fqdn=long_domain)
            assert model.fqdn == long_domain
        else:
            with pytest.raises(ValidationError) as exc_info:
                TestModel(fqdn=long_domain)
            assert "string_too_long" in str(exc_info.value)

    def test_anyfqdn_invalid_starts_with_hyphen(self):
        """Test AnyFQDN rejects label starting with hyphen"""
        class TestModel(BaseModel):
            fqdn: AnyFQDN

        with pytest.raises(ValidationError):
            TestModel(fqdn="-invalid.example.com")

    def test_anyfqdn_no_wildcard(self):
        """Test AnyFQDN does not accept wildcards (unlike AnyUrl)"""
        class TestModel(BaseModel):
            fqdn: AnyFQDN

        with pytest.raises(ValidationError):
            TestModel(fqdn="*.example.com")


class TestEDLSupportedTypes:
    """Test EDL_SUPPORTED_INPUT_TYPES and EDL_SUPPORTED_OUTPUT_TYPES"""

    def test_edl_input_types_ipv4_network(self):
        """Test EDL_SUPPORTED_INPUT_TYPES with IPv4Network"""
        class TestModel(BaseModel):
            value: EDL_SUPPORTED_INPUT_TYPES

        model = TestModel(value="192.168.1.0/24")
        assert isinstance(model.value, IPv4Network)

    def test_edl_input_types_ipv6_network(self):
        """Test EDL_SUPPORTED_INPUT_TYPES with IPv6Network"""
        class TestModel(BaseModel):
            value: EDL_SUPPORTED_INPUT_TYPES

        model = TestModel(value="2001:db8::/32")
        assert isinstance(model.value, IPv6Network)

    def test_edl_input_types_ipv4_interface(self):
        """Test EDL_SUPPORTED_INPUT_TYPES with IPv4Interface"""
        class TestModel(BaseModel):
            value: EDL_SUPPORTED_INPUT_TYPES

        model = TestModel(value="192.168.1.1/24")
        # Could be IPv4Network or IPv4Interface depending on parsing
        assert isinstance(model.value, (IPv4Network, IPv4Interface))

    def test_edl_input_types_ipv6_interface(self):
        """Test EDL_SUPPORTED_INPUT_TYPES with IPv6Interface"""
        class TestModel(BaseModel):
            value: EDL_SUPPORTED_INPUT_TYPES

        model = TestModel(value="2001:db8::1/64")
        assert isinstance(model.value, (IPv6Network, IPv6Interface))

    def test_edl_input_types_url(self):
        """Test EDL_SUPPORTED_INPUT_TYPES with AnyUrl"""
        class TestModel(BaseModel):
            value: EDL_SUPPORTED_INPUT_TYPES

        model = TestModel(value="*.example.com/")
        assert isinstance(model.value, str)
        assert model.value == "*.example.com/"

    def test_edl_input_types_fqdn(self):
        """Test EDL_SUPPORTED_INPUT_TYPES with AnyFQDN"""
        class TestModel(BaseModel):
            value: EDL_SUPPORTED_INPUT_TYPES

        model = TestModel(value="example.com")
        assert isinstance(model.value, str)
        assert model.value == "example.com"

    def test_edl_output_types_ipv4_network(self):
        """Test EDL_SUPPORTED_OUTPUT_TYPES with IPv4Network"""
        class TestModel(BaseModel):
            value: EDL_SUPPORTED_OUTPUT_TYPES

        model = TestModel(value="192.168.1.0/24")
        assert isinstance(model.value, IPv4Network)

    def test_edl_output_types_ipv6_network(self):
        """Test EDL_SUPPORTED_OUTPUT_TYPES with IPv6Network"""
        class TestModel(BaseModel):
            value: EDL_SUPPORTED_OUTPUT_TYPES

        model = TestModel(value="2001:db8::/32")
        assert isinstance(model.value, IPv6Network)

    def test_edl_output_types_url(self):
        """Test EDL_SUPPORTED_OUTPUT_TYPES with AnyUrl"""
        class TestModel(BaseModel):
            value: EDL_SUPPORTED_OUTPUT_TYPES

        model = TestModel(value="*.example.com/")
        assert model.value == "*.example.com/"

    def test_edl_output_types_fqdn(self):
        """Test EDL_SUPPORTED_OUTPUT_TYPES with AnyFQDN"""
        class TestModel(BaseModel):
            value: EDL_SUPPORTED_OUTPUT_TYPES

        model = TestModel(value="example.com")
        assert model.value == "example.com"


class TestRealWorldDataPatterns:
    """Test validators with real-world mixed data patterns"""

    def test_mixed_ip_list_validation(self):
        """Test validating a mixed list of IPs"""
        class TestModel(BaseModel):
            values: List[EDL_SUPPORTED_INPUT_TYPES]

        data = [
            "192.168.1.0/24",
            "10.0.0.0/8",
            "2001:db8::/32",
            "example.com",
            "*.wildcard.com/"
        ]

        model = TestModel(values=data)
        assert len(model.values) == 5

        # Check types
        assert isinstance(model.values[0], IPv4Network)
        assert isinstance(model.values[1], IPv4Network)
        assert isinstance(model.values[2], IPv6Network)
        assert isinstance(model.values[3], str)  # FQDN
        assert isinstance(model.values[4], str)  # URL

    def test_filtering_invalid_from_mixed_list(self):
        """Test filtering invalid entries from mixed data"""
        valid_data = []
        invalid_data = []

        test_values = [
            "192.168.1.0/24",     # Valid IPv4
            "invalid-ip",         # Invalid
            "example.com",        # Valid FQDN
            "not a valid entry",  # Invalid
            "2001:db8::/32",      # Valid IPv6
            "*.example.com/",     # Valid URL
            "999.999.999.999",    # Invalid IP
        ]

        class TestModel(BaseModel):
            value: EDL_SUPPORTED_INPUT_TYPES

        for value in test_values:
            try:
                model = TestModel(value=value)
                valid_data.append(model.value)
            except ValidationError:
                invalid_data.append(value)

        # Should have 4 valid, 3 invalid
        assert len(valid_data) == 4
        assert len(invalid_data) == 3

        assert "invalid-ip" in invalid_data
        assert "not a valid entry" in invalid_data
        assert "999.999.999.999" in invalid_data

    def test_cidr_notation_variations(self):
        """Test various CIDR notation formats"""
        class TestModel(BaseModel):
            value: EDL_SUPPORTED_INPUT_TYPES

        # Single host IPv4
        model = TestModel(value="192.168.1.1/32")
        assert str(model.value) == "192.168.1.1/32"

        # Full network IPv4
        model = TestModel(value="10.0.0.0/8")
        assert str(model.value) == "10.0.0.0/8"

        # Single host IPv6
        model = TestModel(value="2001:db8::1/128")
        assert str(model.value) == "2001:db8::1/128"

        # Full network IPv6
        model = TestModel(value="::/0")
        assert str(model.value) == "::/0"

    def test_url_pattern_variations(self):
        """Test various URL pattern formats"""
        class TestModel(BaseModel):
            url: AnyUrl

        # Simple domain
        model = TestModel(url="example.com/")
        assert model.url == "example.com/"

        # Wildcard subdomain
        model = TestModel(url="*.example.com/")
        assert model.url == "*.example.com/"

        # Multiple subdomains
        model = TestModel(url="a.b.c.example.com/")
        assert model.url == "a.b.c.example.com/"

        # Hyphenated
        model = TestModel(url="my-site.example.com/")
        assert model.url == "my-site.example.com/"

    def test_fqdn_pattern_variations(self):
        """Test various FQDN pattern formats"""
        class TestModel(BaseModel):
            fqdn: AnyFQDN

        # Simple
        model = TestModel(fqdn="example.com")
        assert model.fqdn == "example.com"

        # Subdomain
        model = TestModel(fqdn="www.example.com")
        assert model.fqdn == "www.example.com"

        # Multiple subdomains
        model = TestModel(fqdn="api.v1.example.com")
        assert model.fqdn == "api.v1.example.com"

        # Hyphenated
        model = TestModel(fqdn="my-api.example.com")
        assert model.fqdn == "my-api.example.com"

    def test_threat_intelligence_data_pattern(self):
        """Test real-world threat intelligence data pattern"""
        class ThreatData(BaseModel):
            indicators: List[EDL_SUPPORTED_INPUT_TYPES]

        # Simulating threat intel feed with mixed indicators
        threat_data = ThreatData(
            indicators=[
                "192.0.2.1/32",           # Malicious IP
                "198.51.100.0/24",        # Malicious subnet
                "malware.example.com",    # Malicious domain
                "*.phishing.com/",        # Wildcard phishing domain
                "2001:db8::bad:1/128",    # IPv6 threat
            ]
        )

        assert len(threat_data.indicators) == 5

        # Verify types
        ipv4_count = sum(1 for i in threat_data.indicators if isinstance(i, IPv4Network))
        ipv6_count = sum(1 for i in threat_data.indicators if isinstance(i, IPv6Network))
        string_count = sum(1 for i in threat_data.indicators if isinstance(i, str))

        assert ipv4_count == 2
        assert ipv6_count == 1
        assert string_count == 2


class TestEdgeCasesAndBoundaries:
    """Test edge cases and boundary conditions"""

    def test_empty_string_validation(self):
        """Test validators handle empty strings"""
        class TestModel(BaseModel):
            value: EDL_SUPPORTED_INPUT_TYPES

        with pytest.raises(ValidationError):
            TestModel(value="")

    def test_whitespace_only_validation(self):
        """Test validators handle whitespace-only strings"""
        class TestModel(BaseModel):
            value: EDL_SUPPORTED_INPUT_TYPES

        with pytest.raises(ValidationError):
            TestModel(value="   ")

    def test_ipv4_boundary_values(self):
        """Test IPv4 boundary values"""
        class TestModel(BaseModel):
            value: EDL_SUPPORTED_INPUT_TYPES

        # Minimum IPv4
        model = TestModel(value="0.0.0.0/0")
        assert str(model.value) == "0.0.0.0/0"

        # Maximum IPv4
        model = TestModel(value="255.255.255.255/32")
        assert str(model.value) == "255.255.255.255/32"

        # Invalid: out of range
        with pytest.raises(ValidationError):
            TestModel(value="256.0.0.0/24")

    def test_ipv6_boundary_values(self):
        """Test IPv6 boundary values"""
        class TestModel(BaseModel):
            value: EDL_SUPPORTED_INPUT_TYPES

        # Minimum IPv6
        model = TestModel(value="::/0")
        assert str(model.value) == "::/0"

        # Maximum IPv6 (all F's)
        model = TestModel(value="ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128")
        assert "ffff" in str(model.value)

        # Loopback
        model = TestModel(value="::1/128")
        assert str(model.value) == "::1/128"

    def test_skip_invalid_with_none_value(self):
        """Test skip_invalid with None value"""
        def handler(value):
            if value is None:
                raise ValidationError.from_exception_data(
                    "value_error",
                    [{"type": "none_not_allowed", "loc": ("value",), "input": value}]
                )
            return value

        result = skip_invalid(None, handler)
        assert result is None
