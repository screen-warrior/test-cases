"""
Test Input validation and handling
Focus: Static and ExternalEdl input types, data validation, HTTP handling
"""

import pytest
from unittest.mock import Mock, patch
from ipaddress import IPv4Network, IPv6Network
import requests

from fwdev_edl_server.models.inputs import Static, ExternalEdl, _Input


class TestStaticInput:
    """Test Static input type"""

    def test_static_with_valid_ipv4(self):
        """Test Static with valid IPv4 networks"""
        static = Static(
            type="static",
            data=["192.168.1.0/24", "10.0.0.0/8"]
        )

        result = static.refresh()

        assert len(result) == 2
        assert IPv4Network("192.168.1.0/24") in result
        assert IPv4Network("10.0.0.0/8") in result

    def test_static_with_valid_ipv6(self):
        """Test Static with valid IPv6 networks"""
        static = Static(
            type="static",
            data=["2001:db8::/32", "fe80::/10"]
        )

        result = static.refresh()

        assert len(result) == 2
        assert IPv6Network("2001:db8::/32") in result
        assert IPv6Network("fe80::/10") in result

    def test_static_with_mixed_ips(self):
        """Test Static with mixed IPv4 and IPv6"""
        static = Static(
            type="static",
            data=[
                "192.168.1.0/24",
                "2001:db8::/32",
                "10.0.0.0/8"
            ]
        )

        result = static.refresh()

        assert len(result) == 3
        ipv4_count = sum(1 for r in result if isinstance(r, IPv4Network))
        ipv6_count = sum(1 for r in result if isinstance(r, IPv6Network))

        assert ipv4_count == 2
        assert ipv6_count == 1

    def test_static_filters_invalid_data(self):
        """Test Static skips invalid entries"""
        static = Static(
            type="static",
            data=[
                "192.168.1.0/24",  # Valid
                "invalid-ip",       # Invalid
                "10.0.0.0/8",       # Valid
                "not-a-network"     # Invalid
            ]
        )

        result = static.refresh()

        # Only valid entries
        assert len(result) == 2
        assert IPv4Network("192.168.1.0/24") in result
        assert IPv4Network("10.0.0.0/8") in result

    def test_static_with_urls(self):
        """Test Static with URL strings"""
        static = Static(
            type="static",
            data=[
                "192.168.1.0/24",
                "*.example.com/",
                "test.domain.com"
            ]
        )

        result = static.refresh()

        # Should have IP + valid domains
        assert len(result) >= 1
        assert IPv4Network("192.168.1.0/24") in result

    def test_static_empty_data(self):
        """Test Static with empty data list"""
        static = Static(type="static", data=[])

        result = static.refresh()

        assert result == []

    def test_static_with_single_host_ips(self):
        """Test Static converts single IPs to /32 networks"""
        static = Static(
            type="static",
            data=["192.168.1.1", "10.0.0.5"]
        )

        result = static.refresh()

        # Single IPs become /32 networks
        assert len(result) == 2
        assert all(isinstance(r, IPv4Network) for r in result)

    def test_static_data_serialization(self):
        """Test that data field serializes correctly"""
        static = Static(
            type="static",
            data=["192.168.1.0/24", "10.0.0.0/8"]
        )

        serialized = static.model_dump()

        assert "data" in serialized
        assert isinstance(serialized["data"], list)
        assert "192.168.1.0/24" in serialized["data"]


class TestExternalEdl:
    """Test ExternalEdl HTTP input type"""

    @patch("requests.get")
    def test_external_edl_basic_fetch(self, mock_get):
        """Test ExternalEdl fetches and parses data"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "text/plain"}
        mock_response.text = "192.168.1.1\n10.0.0.1\n172.16.0.1"
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        edl = ExternalEdl(
            type="edl",
            url="https://example.com/edl"
        )

        result = edl.refresh()

        # Should parse all IPs
        assert len(result) == 3
        assert IPv4Network("192.168.1.1/32") in result
        assert IPv4Network("10.0.0.1/32") in result
        assert IPv4Network("172.16.0.1/32") in result

        # Verify HTTP call
        mock_get.assert_called_once()

    @patch("requests.get")
    def test_external_edl_with_subnets(self, mock_get):
        """Test ExternalEdl with subnet notation"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "text/plain"}
        mock_response.text = "192.168.1.0/24\n10.0.0.0/8"
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        edl = ExternalEdl(type="edl", url="https://example.com/edl")

        result = edl.refresh()

        assert len(result) == 2
        assert IPv4Network("192.168.1.0/24") in result
        assert IPv4Network("10.0.0.0/8") in result

    @patch("requests.get")
    def test_external_edl_filters_invalid_lines(self, mock_get):
        """Test ExternalEdl skips invalid lines"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "text/plain"}
        mock_response.text = """192.168.1.1
invalid-line
10.0.0.1
not-an-ip
malformed data
172.16.0.1"""
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        edl = ExternalEdl(type="edl", url="https://example.com/edl")

        result = edl.refresh()

        # Only valid IPs
        assert len(result) == 3
        assert IPv4Network("192.168.1.1/32") in result
        assert IPv4Network("10.0.0.1/32") in result
        assert IPv4Network("172.16.0.1/32") in result

    @patch("requests.get")
    def test_external_edl_wrong_content_type(self, mock_get):
        """Test ExternalEdl returns empty for wrong Content-Type"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "application/json"}
        mock_response.text = '{"ips": ["192.168.1.1"]}'
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        edl = ExternalEdl(type="edl", url="https://example.com/edl")

        result = edl.refresh()

        # Should return empty for non-text/plain
        assert result == []

    @patch("requests.get")
    def test_external_edl_http_error(self, mock_get):
        """Test ExternalEdl raises on HTTP error"""
        mock_get.side_effect = requests.exceptions.HTTPError("404 Not Found")

        edl = ExternalEdl(type="edl", url="https://example.com/edl")

        with pytest.raises(requests.exceptions.HTTPError):
            edl.refresh()

    @patch("requests.get")
    def test_external_edl_empty_response(self, mock_get):
        """Test ExternalEdl handles empty response"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "text/plain"}
        mock_response.text = ""
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        edl = ExternalEdl(type="edl", url="https://example.com/edl")

        result = edl.refresh()

        assert result == []

    @patch("requests.get")
    def test_external_edl_mixed_ipv4_ipv6(self, mock_get):
        """Test ExternalEdl with mixed IPv4 and IPv6"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "text/plain"}
        mock_response.text = """192.168.1.1
2001:db8::1
10.0.0.1
fe80::1"""
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        edl = ExternalEdl(type="edl", url="https://example.com/edl")

        result = edl.refresh()

        assert len(result) == 4
        ipv4_count = sum(1 for r in result if isinstance(r, IPv4Network))
        ipv6_count = sum(1 for r in result if isinstance(r, IPv6Network))

        assert ipv4_count == 2
        assert ipv6_count == 2

    def test_external_edl_url_validation(self):
        """Test ExternalEdl validates URL format"""
        # Valid URLs
        edl = ExternalEdl(type="edl", url="https://example.com/edl")
        assert edl.url == "https://example.com/edl"

        edl = ExternalEdl(type="edl", url="http://example.com/list")
        assert edl.url == "http://example.com/list"

        # Invalid URL should raise validation error
        with pytest.raises(Exception):
            ExternalEdl(type="edl", url="not-a-url")

    @patch("requests.get")
    def test_external_edl_with_whitespace(self, mock_get):
        """Test ExternalEdl handles lines with whitespace"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "text/plain"}
        mock_response.text = """  192.168.1.1
10.0.0.1
  172.16.0.1"""
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        edl = ExternalEdl(type="edl", url="https://example.com/edl")

        result = edl.refresh()

        # Should handle whitespace correctly
        assert len(result) >= 2


class TestInputBaseClass:
    """Test _Input base class refresh logic"""

    def test_base_refresh_validates_data(self):
        """Test _Input.refresh validates and filters data"""
        data = [
            "192.168.1.0/24",  # Valid
            "invalid",          # Invalid
            "10.0.0.0/8",       # Valid
            "bad-data"          # Invalid
        ]

        result = _Input.refresh(data)

        # Only valid entries
        assert len(result) == 2
        assert IPv4Network("192.168.1.0/24") in result
        assert IPv4Network("10.0.0.0/8") in result

    def test_base_refresh_converts_interfaces_to_networks(self):
        """Test that IPv4Interface/IPv6Interface are converted to networks"""
        # This tests the interface conversion logic in _Input.refresh
        data = ["192.168.1.1/24"]

        result = _Input.refresh(data)

        # Should convert interface notation to network
        assert len(result) >= 1
        assert all(isinstance(r, (IPv4Network, IPv6Network)) for r in result)

    def test_base_refresh_removes_none_values(self):
        """Test that None values from invalid data are filtered"""
        data = ["192.168.1.0/24", "invalid", "10.0.0.0/8"]

        result = _Input.refresh(data)

        # No None values in result
        assert None not in result
        assert all(r is not None for r in result)


class TestInputTypes:
    """Test input type literals and model structure"""

    def test_static_type_literal(self):
        """Test Static has correct type literal"""
        static = Static(type="static", data=["192.168.1.0/24"])

        assert static.type == "static"

    def test_external_edl_type_literal(self):
        """Test ExternalEdl has correct type literal"""
        edl = ExternalEdl(type="edl", url="https://example.com/edl")

        assert edl.type == "edl"

    def test_input_has_id(self):
        """Test all inputs have UUID id"""
        static = Static(type="static", data=["192.168.1.0/24"])
        edl = ExternalEdl(type="edl", url="https://example.com/edl")

        assert static.id is not None
        assert isinstance(static.id, str)
        assert edl.id is not None
        assert isinstance(edl.id, str)

    def test_static_model_dump(self):
        """Test Static model serialization"""
        static = Static(type="static", data=["192.168.1.0/24"])

        data = static.model_dump()

        assert "id" in data
        assert "type" in data
        assert "data" in data
        assert data["type"] == "static"
