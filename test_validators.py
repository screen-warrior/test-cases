"""
Comprehensive test suite for data validation

Tests the validation logic for IP addresses, FQDNs, URLs, and the skip_invalid wrapper.
This is critical infrastructure - all data passes through these validators.
"""

import pytest
from ipaddress import IPv4Network, IPv6Network
from pydantic import ValidationError

from fwdev_edl_server.validators import (
    AnyUrl,
    AnyFQDN,
    skip_invalid,
    EDL_SUPPORTED_TYPES,
)
from pydantic import TypeAdapter
from typing import Annotated
from pydantic.functional_validators import WrapValidator


# ============================================================================
# TEST ANYURL VALIDATION
# ============================================================================

class TestAnyUrlValidation:
    """Test AnyUrl type validation with regex patterns"""

    def test_valid_url_with_trailing_slash(self):
        """Valid URLs must end with /"""
        validator = TypeAdapter(AnyUrl)

        assert validator.validate_python("example.com/") == "example.com/"
        assert validator.validate_python("sub.example.com/") == "sub.example.com/"
        assert validator.validate_python("deep.sub.example.com/") == "deep.sub.example.com/"

    def test_valid_url_with_wildcard_subdomain(self):
        """Wildcard domains should be accepted"""
        validator = TypeAdapter(AnyUrl)

        assert validator.validate_python("*.example.com/") == "*.example.com/"
        assert validator.validate_python("*.sub.example.com/") == "*.sub.example.com/"

    def test_valid_url_with_hyphen_in_subdomain(self):
        """Subdomains with hyphens should be valid"""
        validator = TypeAdapter(AnyUrl)

        assert validator.validate_python("my-site.example.com/") == "my-site.example.com/"
        assert validator.validate_python("test-123.example.com/") == "test-123.example.com/"

    def test_valid_url_with_digits_in_subdomain(self):
        """Subdomains with digits should be valid"""
        validator = TypeAdapter(AnyUrl)

        assert validator.validate_python("site123.example.com/") == "site123.example.com/"
        assert validator.validate_python("123site.example.com/") == "123site.example.com/"

    def test_valid_url_various_tlds(self):
        """Test various TLD lengths (2-18 chars)"""
        validator = TypeAdapter(AnyUrl)

        # 2 char TLD
        assert validator.validate_python("example.io/") == "example.io/"
        # 3 char TLD
        assert validator.validate_python("example.com/") == "example.com/"
        # 4 char TLD
        assert validator.validate_python("example.info/") == "example.info/"
        # Long TLD (within limit)
        assert validator.validate_python("example.international/") == "example.international/"

    def test_invalid_url_without_trailing_slash(self):
        """URLs without trailing slash should fail"""
        validator = TypeAdapter(AnyUrl)

        with pytest.raises(ValidationError):
            validator.validate_python("example.com")

        with pytest.raises(ValidationError):
            validator.validate_python("sub.example.com")

    def test_invalid_url_with_invalid_tld(self):
        """Invalid TLDs should fail"""
        validator = TypeAdapter(AnyUrl)

        # TLD too short (1 char)
        with pytest.raises(ValidationError):
            validator.validate_python("example.c/")

        # TLD too long (19 chars)
        with pytest.raises(ValidationError):
            validator.validate_python("example.verylongtldthatexceeds/")

    def test_invalid_url_with_special_characters(self):
        """Special characters in domain should fail"""
        validator = TypeAdapter(AnyUrl)

        with pytest.raises(ValidationError):
            validator.validate_python("exam@ple.com/")

        with pytest.raises(ValidationError):
            validator.validate_python("exam ple.com/")

    def test_invalid_url_no_tld(self):
        """Domain without TLD should fail"""
        validator = TypeAdapter(AnyUrl)

        with pytest.raises(ValidationError):
            validator.validate_python("localhost/")

    def test_invalid_url_starting_with_hyphen(self):
        """Subdomain starting with hyphen should fail"""
        validator = TypeAdapter(AnyUrl)

        with pytest.raises(ValidationError):
            validator.validate_python("-invalid.example.com/")


# ============================================================================
# TEST ANYFQDN VALIDATION
# ============================================================================

class TestAnyFqdnValidation:
    """Test AnyFQDN type validation"""

    def test_valid_fqdn_simple(self):
        """Valid simple FQDNs"""
        validator = TypeAdapter(AnyFQDN)

        assert validator.validate_python("example.com") == "example.com"
        assert validator.validate_python("google.com") == "google.com"

    def test_valid_fqdn_with_subdomains(self):
        """Valid FQDNs with subdomains"""
        validator = TypeAdapter(AnyFQDN)

        assert validator.validate_python("www.example.com") == "www.example.com"
        assert validator.validate_python("mail.google.com") == "mail.google.com"
        assert validator.validate_python("deep.sub.example.com") == "deep.sub.example.com"

    def test_valid_fqdn_with_hyphens(self):
        """FQDNs with hyphens in labels"""
        validator = TypeAdapter(AnyFQDN)

        assert validator.validate_python("my-site.example.com") == "my-site.example.com"
        assert validator.validate_python("test-123-abc.com") == "test-123-abc.com"

    def test_valid_fqdn_with_digits(self):
        """FQDNs with digits"""
        validator = TypeAdapter(AnyFQDN)

        assert validator.validate_python("site123.example.com") == "site123.example.com"
        assert validator.validate_python("123.example.com") == "123.example.com"

    def test_valid_fqdn_max_label_length(self):
        """FQDN with max label length (63 chars)"""
        validator = TypeAdapter(AnyFQDN)

        # 63 character label (max allowed)
        long_label = "a" * 63
        fqdn = f"{long_label}.example.com"
        assert validator.validate_python(fqdn) == fqdn

    def test_valid_fqdn_max_total_length(self):
        """FQDN with max total length (255 chars)"""
        validator = TypeAdapter(AnyFQDN)

        # Create FQDN close to 255 chars
        # 63 + 1 (dot) + 63 + 1 + 63 + 1 + 63 = 255
        label1 = "a" * 63
        label2 = "b" * 63
        label3 = "c" * 63
        label4 = "d" * 60  # Leaves room for .com
        fqdn = f"{label1}.{label2}.{label3}.{label4}.com"

        assert len(fqdn) <= 255
        assert validator.validate_python(fqdn) == fqdn

    def test_invalid_fqdn_with_trailing_slash(self):
        """FQDN with trailing slash should fail (that's a URL)"""
        validator = TypeAdapter(AnyFQDN)

        with pytest.raises(ValidationError):
            validator.validate_python("example.com/")

    def test_invalid_fqdn_exceeds_max_length(self):
        """FQDN exceeding 255 chars should fail"""
        validator = TypeAdapter(AnyFQDN)

        # Create FQDN > 255 chars
        long_fqdn = "a" * 256 + ".com"

        with pytest.raises(ValidationError):
            validator.validate_python(long_fqdn)

    def test_invalid_fqdn_label_exceeds_63_chars(self):
        """FQDN label exceeding 63 chars should fail"""
        validator = TypeAdapter(AnyFQDN)

        # 64 character label (exceeds max)
        long_label = "a" * 64
        fqdn = f"{long_label}.example.com"

        with pytest.raises(ValidationError):
            validator.validate_python(fqdn)

    def test_invalid_fqdn_special_characters(self):
        """FQDN with special characters should fail"""
        validator = TypeAdapter(AnyFQDN)

        with pytest.raises(ValidationError):
            validator.validate_python("exam@ple.com")

        with pytest.raises(ValidationError):
            validator.validate_python("exam ple.com")

    def test_invalid_fqdn_starting_with_hyphen(self):
        """FQDN label starting with hyphen should fail"""
        validator = TypeAdapter(AnyFQDN)

        with pytest.raises(ValidationError):
            validator.validate_python("-invalid.example.com")

    def test_invalid_fqdn_ending_with_hyphen(self):
        """FQDN label ending with hyphen should fail"""
        validator = TypeAdapter(AnyFQDN)

        with pytest.raises(ValidationError):
            validator.validate_python("invalid-.example.com")

    def test_invalid_fqdn_consecutive_dots(self):
        """FQDN with consecutive dots should fail"""
        validator = TypeAdapter(AnyFQDN)

        with pytest.raises(ValidationError):
            validator.validate_python("example..com")

    def test_invalid_fqdn_no_tld(self):
        """FQDN without TLD should fail"""
        validator = TypeAdapter(AnyFQDN)

        with pytest.raises(ValidationError):
            validator.validate_python("localhost")


# ============================================================================
# TEST SKIP_INVALID WRAPPER
# ============================================================================

class TestSkipInvalidWrapper:
    """Test the skip_invalid validator wrapper"""

    def test_skip_invalid_returns_valid_value(self):
        """Valid values should pass through unchanged"""
        validator = TypeAdapter(
            Annotated[IPv4Network, WrapValidator(skip_invalid)]
        )

        result = validator.validate_python("192.168.1.0/24")
        assert result == IPv4Network("192.168.1.0/24")

    def test_skip_invalid_returns_none_on_error(self):
        """Invalid values should return None instead of raising"""
        validator = TypeAdapter(
            Annotated[IPv4Network, WrapValidator(skip_invalid)]
        )

        # Invalid IP should return None, not raise
        result = validator.validate_python("not-an-ip")
        assert result is None

    def test_skip_invalid_with_list_filters_none(self):
        """When used with List, None values should be filtered"""
        from typing import List

        validator = TypeAdapter(
            List[Annotated[IPv4Network, WrapValidator(skip_invalid)]]
        )

        # Mix of valid and invalid
        result = validator.validate_python([
            "192.168.1.0/24",
            "invalid",
            "10.0.0.0/8",
            "also-invalid",
            "172.16.0.0/12"
        ])

        # Filter out None values
        result = [r for r in result if r is not None]

        assert len(result) == 3
        assert IPv4Network("192.168.1.0/24") in result
        assert IPv4Network("10.0.0.0/8") in result
        assert IPv4Network("172.16.0.0/12") in result


# ============================================================================
# TEST EDL_SUPPORTED_TYPES UNION
# ============================================================================

class TestEdlSupportedTypes:
    """Test the complete EDL_SUPPORTED_TYPES validation pipeline"""

    def test_validates_ipv4_networks(self):
        """IPv4 networks should validate"""
        from typing import List

        validator = TypeAdapter(
            List[Annotated[EDL_SUPPORTED_TYPES, WrapValidator(skip_invalid)]]
        )

        result = validator.validate_python([
            "192.168.1.0/24",
            "10.0.0.0/8",
            "172.16.0.1/32"
        ])

        # Filter None
        result = [r for r in result if r is not None]

        assert len(result) == 3
        assert all(isinstance(r, IPv4Network) for r in result)

    def test_validates_ipv6_networks(self):
        """IPv6 networks should validate"""
        from typing import List

        validator = TypeAdapter(
            List[Annotated[EDL_SUPPORTED_TYPES, WrapValidator(skip_invalid)]]
        )

        result = validator.validate_python([
            "2001:db8::/32",
            "fe80::/10",
            "::1/128"
        ])

        # Filter None
        result = [r for r in result if r is not None]

        assert len(result) == 3
        assert all(isinstance(r, IPv6Network) for r in result)

    def test_validates_urls(self):
        """URLs should validate as strings"""
        from typing import List

        validator = TypeAdapter(
            List[Annotated[EDL_SUPPORTED_TYPES, WrapValidator(skip_invalid)]]
        )

        result = validator.validate_python([
            "example.com/",
            "*.malicious.com/",
            "bad-site.org/"
        ])

        # Filter None
        result = [r for r in result if r is not None]

        assert len(result) == 3
        assert all(isinstance(r, str) for r in result)

    def test_validates_fqdns(self):
        """FQDNs should validate as strings"""
        from typing import List

        validator = TypeAdapter(
            List[Annotated[EDL_SUPPORTED_TYPES, WrapValidator(skip_invalid)]]
        )

        result = validator.validate_python([
            "example.com",
            "malicious.org",
            "bad-actor.net"
        ])

        # Filter None
        result = [r for r in result if r is not None]

        assert len(result) == 3
        assert all(isinstance(r, str) for r in result)

    def test_filters_invalid_data(self):
        """Invalid data should be filtered out"""
        from typing import List

        validator = TypeAdapter(
            List[Annotated[EDL_SUPPORTED_TYPES, WrapValidator(skip_invalid)]]
        )

        result = validator.validate_python([
            "192.168.1.0/24",  # Valid IPv4
            "not-valid",        # Invalid
            "example.com",      # Valid FQDN
            "999.999.999.999",  # Invalid IP
            "test.com/",        # Valid URL
            "invalid@email.com",# Invalid
        ])

        # Filter None
        result = [r for r in result if r is not None]

        assert len(result) == 3  # Only 3 valid entries

    def test_mixed_types_validation(self):
        """All supported types in one list"""
        from typing import List

        validator = TypeAdapter(
            List[Annotated[EDL_SUPPORTED_TYPES, WrapValidator(skip_invalid)]]
        )

        result = validator.validate_python([
            "192.168.1.0/24",     # IPv4
            "2001:db8::/32",      # IPv6
            "example.com",        # FQDN
            "malicious.com/",     # URL
            "10.0.0.0/8",         # IPv4
            "bad-site.org",       # FQDN
        ])

        # Filter None
        result = [r for r in result if r is not None]

        assert len(result) == 6

        # Count types
        ipv4_count = sum(1 for r in result if isinstance(r, IPv4Network))
        ipv6_count = sum(1 for r in result if isinstance(r, IPv6Network))
        str_count = sum(1 for r in result if isinstance(r, str))

        assert ipv4_count == 2
        assert ipv6_count == 1
        assert str_count == 3  # 1 URL + 2 FQDNs

    def test_empty_list_validation(self):
        """Empty list should validate"""
        from typing import List

        validator = TypeAdapter(
            List[Annotated[EDL_SUPPORTED_TYPES, WrapValidator(skip_invalid)]]
        )

        result = validator.validate_python([])
        assert result == []

    def test_all_invalid_returns_empty_after_filter(self):
        """List with all invalid data should return empty after filtering"""
        from typing import List

        validator = TypeAdapter(
            List[Annotated[EDL_SUPPORTED_TYPES, WrapValidator(skip_invalid)]]
        )

        result = validator.validate_python([
            "invalid1",
            "invalid2",
            "999.999.999.999",
            "not-a-domain",
        ])

        # Filter None
        result = [r for r in result if r is not None]

        assert result == []

    def test_whitespace_handling(self):
        """Test handling of values with whitespace"""
        from typing import List

        validator = TypeAdapter(
            List[Annotated[EDL_SUPPORTED_TYPES, WrapValidator(skip_invalid)]]
        )

        result = validator.validate_python([
            "  192.168.1.0/24  ",  # Leading/trailing whitespace
            "example.com",          # Clean
            "  ",                    # Only whitespace
            "",                      # Empty string
        ])

        # Filter None
        result = [r for r in result if r is not None]

        # Whitespace is not stripped by validator, so may fail validation
        # This tests actual behavior
        assert len(result) >= 1  # At least the clean FQDN should pass
