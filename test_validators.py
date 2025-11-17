"""
Test validators.py functionality
Focus: skip_invalid wrapper, AnyUrl, AnyFQDN type aliases, EDL types
"""

import pytest
from ipaddress import IPv4Network, IPv6Network
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
    """Test skip_invalid validator wrapper"""

    def test_skip_invalid_passes_valid_data(self):
        """Test skip_invalid returns valid data"""
        def handler(value):
            return IPv4Network(value)

        result = skip_invalid("192.168.1.0/24", handler)

        assert result == IPv4Network("192.168.1.0/24")

    def test_skip_invalid_returns_none_on_error(self):
        """Test skip_invalid returns None for invalid data"""
        def handler(value):
            return IPv4Network(value)

        result = skip_invalid("not-an-ip", handler)

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

        result = skip_invalid("string", handler)

        assert result is None

    def test_skip_invalid_with_ipv6(self):
        """Test skip_invalid with IPv6 networks"""
        def handler(value):
            return IPv6Network(value)

        # Valid
        result = skip_invalid("2001:db8::/32", handler)
        assert result == IPv6Network("2001:db8::/32")

        # Invalid
        result = skip_invalid("invalid-ipv6", handler)
        assert result is None


class TestAnyUrlTypeAlias:
    """Test AnyUrl type alias validation"""

    def test_anyurl_valid_domain(self):
        """Test AnyUrl with valid domain"""
        class TestModel(BaseModel):
            url: AnyUrl

        model = TestModel(url="example.com/")
        assert model.url == "example.com/"

    def test_anyurl_with_subdomain(self):
        """Test AnyUrl with subdomain"""
        class TestModel(BaseModel):
            url: AnyUrl

        model = TestModel(url="sub.example.com/")
        assert model.url == "sub.example.com/"

    def test_anyurl_with_wildcard(self):
        """Test AnyUrl with wildcard subdomain"""
        class TestModel(BaseModel):
            url: AnyUrl

        model = TestModel(url="*.example.com/")
        assert model.url == "*.example.com/"

    def test_anyurl_with_multiple_subdomains(self):
        """Test AnyUrl with multiple subdomains"""
        class TestModel(BaseModel):
            url: AnyUrl

        model = TestModel(url="a.b.c.example.com/")
        assert model.url == "a.b.c.example.com/"

    def test_anyurl_requires_trailing_slash(self):
        """Test AnyUrl requires trailing slash"""
        class TestModel(BaseModel):
            url: AnyUrl

        with pytest.raises(ValidationError):
            TestModel(url="example.com")

    def test_anyurl_requires_tld(self):
        """Test AnyUrl requires valid TLD"""
        class TestModel(BaseModel):
            url: AnyUrl

        with pytest.raises(ValidationError):
            TestModel(url="invalid/")

    def test_anyurl_with_hyphen(self):
        """Test AnyUrl with hyphenated domain"""
        class TestModel(BaseModel):
            url: AnyUrl

        model = TestModel(url="my-domain.example.com/")
        assert model.url == "my-domain.example.com/"


class TestAnyFQDNTypeAlias:
    """Test AnyFQDN type alias validation"""

    def test_anyfqdn_valid_domain(self):
        """Test AnyFQDN with valid domain"""
        class TestModel(BaseModel):
            fqdn: AnyFQDN

        model = TestModel(fqdn="example.com")
        assert model.fqdn == "example.com"

    def test_anyfqdn_with_subdomain(self):
        """Test AnyFQDN with subdomain"""
        class TestModel(BaseModel):
            fqdn: AnyFQDN

        model = TestModel(fqdn="www.example.com")
        assert model.fqdn == "www.example.com"

    def test_anyfqdn_with_multiple_subdomains(self):
        """Test AnyFQDN with multiple subdomains"""
        class TestModel(BaseModel):
            fqdn: AnyFQDN

        model = TestModel(fqdn="api.v1.example.com")
        assert model.fqdn == "api.v1.example.com"

    def test_anyfqdn_rejects_trailing_slash(self):
        """Test AnyFQDN rejects trailing slash"""
        class TestModel(BaseModel):
            fqdn: AnyFQDN

        with pytest.raises(ValidationError):
            TestModel(fqdn="example.com/")

    def test_anyfqdn_requires_tld(self):
        """Test AnyFQDN requires TLD"""
        class TestModel(BaseModel):
            fqdn: AnyFQDN

        with pytest.raises(ValidationError):
            TestModel(fqdn="invalid")

    def test_anyfqdn_with_hyphen(self):
        """Test AnyFQDN with hyphenated domain"""
        class TestModel(BaseModel):
            fqdn: AnyFQDN

        model = TestModel(fqdn="my-site.example.com")
        assert model.fqdn == "my-site.example.com"

    def test_anyfqdn_no_wildcard(self):
        """Test AnyFQDN does not accept wildcards"""
        class TestModel(BaseModel):
            fqdn: AnyFQDN

        with pytest.raises(ValidationError):
            TestModel(fqdn="*.example.com")

    def test_anyfqdn_max_length(self):
        """Test AnyFQDN max length constraint (255)"""
        class TestModel(BaseModel):
            fqdn: AnyFQDN

        # Very long domain
        long_domain = "a" * 250 + ".com"

        if len(long_domain) <= 255:
            model = TestModel(fqdn=long_domain)
            assert len(model.fqdn) <= 255
        else:
            with pytest.raises(ValidationError):
                TestModel(fqdn=long_domain)


class TestEDLSupportedInputTypes:
    """Test EDL_SUPPORTED_INPUT_TYPES union"""

    def test_edl_input_ipv4_network(self):
        """Test EDL_SUPPORTED_INPUT_TYPES with IPv4"""
        class TestModel(BaseModel):
            value: EDL_SUPPORTED_INPUT_TYPES

        model = TestModel(value="192.168.1.0/24")
        assert isinstance(model.value, IPv4Network)

    def test_edl_input_ipv6_network(self):
        """Test EDL_SUPPORTED_INPUT_TYPES with IPv6"""
        class TestModel(BaseModel):
            value: EDL_SUPPORTED_INPUT_TYPES

        model = TestModel(value="2001:db8::/32")
        assert isinstance(model.value, IPv6Network)

    def test_edl_input_url(self):
        """Test EDL_SUPPORTED_INPUT_TYPES with URL"""
        class TestModel(BaseModel):
            value: EDL_SUPPORTED_INPUT_TYPES

        model = TestModel(value="*.example.com/")
        assert isinstance(model.value, str)

    def test_edl_input_fqdn(self):
        """Test EDL_SUPPORTED_INPUT_TYPES with FQDN"""
        class TestModel(BaseModel):
            value: EDL_SUPPORTED_INPUT_TYPES

        model = TestModel(value="example.com")
        assert isinstance(model.value, str)

    def test_edl_input_list_mixed(self):
        """Test EDL_SUPPORTED_INPUT_TYPES with mixed list"""
        class TestModel(BaseModel):
            values: List[EDL_SUPPORTED_INPUT_TYPES]

        model = TestModel(values=[
            "192.168.1.0/24",
            "2001:db8::/32",
            "example.com",
            "*.malicious.com/"
        ])

        assert len(model.values) == 4


class TestEDLSupportedOutputTypes:
    """Test EDL_SUPPORTED_OUTPUT_TYPES union"""

    def test_edl_output_ipv4_network(self):
        """Test EDL_SUPPORTED_OUTPUT_TYPES with IPv4"""
        class TestModel(BaseModel):
            value: EDL_SUPPORTED_OUTPUT_TYPES

        model = TestModel(value="192.168.1.0/24")
        assert isinstance(model.value, IPv4Network)

    def test_edl_output_ipv6_network(self):
        """Test EDL_SUPPORTED_OUTPUT_TYPES with IPv6"""
        class TestModel(BaseModel):
            value: EDL_SUPPORTED_OUTPUT_TYPES

        model = TestModel(value="2001:db8::/32")
        assert isinstance(model.value, IPv6Network)

    def test_edl_output_url(self):
        """Test EDL_SUPPORTED_OUTPUT_TYPES with URL"""
        class TestModel(BaseModel):
            value: EDL_SUPPORTED_OUTPUT_TYPES

        model = TestModel(value="*.example.com/")
        assert isinstance(model.value, str)

    def test_edl_output_fqdn(self):
        """Test EDL_SUPPORTED_OUTPUT_TYPES with FQDN"""
        class TestModel(BaseModel):
            value: EDL_SUPPORTED_OUTPUT_TYPES

        model = TestModel(value="example.com")
        assert isinstance(model.value, str)


class TestValidationPatterns:
    """Test real-world validation patterns"""

    def test_filtering_invalid_from_list(self):
        """Test filtering invalid entries from mixed data"""
        valid_data = []
        invalid_data = []

        test_values = [
            "192.168.1.0/24",
            "invalid-entry",
            "example.com",
            "999.999.999.999",
            "2001:db8::/32"
        ]

        class TestModel(BaseModel):
            value: EDL_SUPPORTED_INPUT_TYPES

        for value in test_values:
            try:
                model = TestModel(value=value)
                valid_data.append(model.value)
            except ValidationError:
                invalid_data.append(value)

        # Should have valid entries
        assert len(valid_data) >= 3
        assert "invalid-entry" in invalid_data
        assert "999.999.999.999" in invalid_data

    def test_url_vs_fqdn_distinction(self):
        """Test distinction between URL and FQDN formats"""
        class UrlModel(BaseModel):
            value: AnyUrl

        class FqdnModel(BaseModel):
            value: AnyFQDN

        # URL requires trailing slash
        url_model = UrlModel(value="example.com/")
        assert url_model.value == "example.com/"

        # FQDN rejects trailing slash
        fqdn_model = FqdnModel(value="example.com")
        assert fqdn_model.value == "example.com"

        # URL with slash fails FQDN
        with pytest.raises(ValidationError):
            FqdnModel(value="example.com/")

        # FQDN without slash fails URL
        with pytest.raises(ValidationError):
            UrlModel(value="example.com")

    def test_wildcard_only_in_url(self):
        """Test wildcard is valid in URL but not FQDN"""
        class UrlModel(BaseModel):
            value: AnyUrl

        class FqdnModel(BaseModel):
            value: AnyFQDN

        # Wildcard valid in URL
        url_model = UrlModel(value="*.example.com/")
        assert url_model.value == "*.example.com/"

        # Wildcard invalid in FQDN
        with pytest.raises(ValidationError):
            FqdnModel(value="*.example.com")

    def test_cidr_notation_validation(self):
        """Test various CIDR notations"""
        class TestModel(BaseModel):
            value: EDL_SUPPORTED_INPUT_TYPES

        # Valid CIDR notations
        valid_cidrs = [
            "192.168.1.0/24",
            "10.0.0.0/8",
            "192.168.1.1/32",
            "0.0.0.0/0",
            "2001:db8::/32",
            "::/0"
        ]

        for cidr in valid_cidrs:
            model = TestModel(value=cidr)
            assert model.value is not None

    def test_single_ip_parsing(self):
        """Test single IP addresses (without CIDR)"""
        class TestModel(BaseModel):
            value: EDL_SUPPORTED_INPUT_TYPES

        # Single IPs should parse
        model = TestModel(value="192.168.1.1")
        # Depends on whether it becomes /32 network or interface
        assert model.value is not None


class TestEdgeCases:
    """Test edge cases and boundary conditions"""

    def test_empty_string_validation(self):
        """Test validators handle empty strings"""
        class TestModel(BaseModel):
            value: EDL_SUPPORTED_INPUT_TYPES

        with pytest.raises(ValidationError):
            TestModel(value="")

    def test_whitespace_only_validation(self):
        """Test validators handle whitespace"""
        class TestModel(BaseModel):
            value: EDL_SUPPORTED_INPUT_TYPES

        with pytest.raises(ValidationError):
            TestModel(value="   ")

    def test_ipv4_boundary_values(self):
        """Test IPv4 boundary values"""
        class TestModel(BaseModel):
            value: EDL_SUPPORTED_INPUT_TYPES

        # Min IPv4
        model = TestModel(value="0.0.0.0/0")
        assert model.value is not None

        # Max IPv4
        model = TestModel(value="255.255.255.255/32")
        assert model.value is not None

        # Invalid: out of range
        with pytest.raises(ValidationError):
            TestModel(value="256.0.0.0/24")

    def test_ipv6_boundary_values(self):
        """Test IPv6 boundary values"""
        class TestModel(BaseModel):
            value: EDL_SUPPORTED_INPUT_TYPES

        # Min IPv6
        model = TestModel(value="::/0")
        assert model.value is not None

        # Loopback
        model = TestModel(value="::1/128")
        assert model.value is not None

        # Full IPv6
        model = TestModel(value="ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128")
        assert model.value is not None

    def test_skip_invalid_with_none(self):
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
