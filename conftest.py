"""
Pytest configuration file for test_cases

This file configures pytest to find the fwdev_edl_server module
and provides shared fixtures for testing
"""
import sys
from pathlib import Path
import pytest
from unittest.mock import Mock, patch
from ipaddress import IPv4Network

# Add the project root to Python path so imports work
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from fwdev_edl_server.models.inputs import ExternalEdl
from fwdev_edl_server.models.outputs import IPv4Only, All, IPv6Only
from fwdev_edl_server.models.modifiers import IPv4Only as IPv4OnlyModifier


# ============================================================================
# FIXTURES FOR REAL MODEL INSTANCES
# ============================================================================

@pytest.fixture
def real_input():
    """Create a real ExternalEdl input for testing"""
    return ExternalEdl(type="edl", url="https://test.example.com/edl")


@pytest.fixture
def real_input_2():
    """Create a second real ExternalEdl input for testing"""
    return ExternalEdl(type="edl", url="https://test2.example.com/edl")


@pytest.fixture
def real_input_3():
    """Create a third real ExternalEdl input for testing"""
    return ExternalEdl(type="edl", url="https://test3.example.com/edl")


@pytest.fixture
def real_modifier():
    """Create a real IPv4Only modifier for testing"""
    return IPv4OnlyModifier(type="ipv4-only")


@pytest.fixture
def real_output_ipv4():
    """Create a real IPv4Only output for testing"""
    return IPv4Only(type="ipv4")


@pytest.fixture
def real_output_ipv6():
    """Create a real IPv6Only output for testing"""
    return IPv6Only(type="ipv6")


@pytest.fixture
def real_output_all():
    """Create a real All output for testing"""
    return All(type="all")


# ============================================================================
# FIXTURES FOR HTTP MOCKING
# ============================================================================

@pytest.fixture
def mock_http_response():
    """Factory fixture for creating mock HTTP responses"""
    def _create_response(text="192.168.1.1\n10.0.0.5\n172.16.0.10", status=200, content_type="text/plain"):
        mock = Mock()
        mock.status_code = status
        mock.headers = {"Content-Type": content_type}
        mock.text = text
        mock.raise_for_status = Mock()
        return mock
    return _create_response


@pytest.fixture
def mock_requests_get(mock_http_response):
    """Patch requests.get and return the mock"""
    with patch('fwdev_edl_server.models.inputs.requests.get') as mock_get:
        # Default response
        mock_get.return_value = mock_http_response()
        yield mock_get
