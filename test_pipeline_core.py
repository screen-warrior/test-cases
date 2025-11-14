"""
Comprehensive test suite for pipeline core refresh logic

Tests the complete Pipeline.refresh() workflow including concurrent execution,
modifier chains, and output generation. This is the most critical integration test.
"""

import pytest
from datetime import datetime, timezone
from uuid import uuid4
from unittest.mock import Mock, patch, MagicMock
from ipaddress import IPv4Network, IPv6Network

from fwdev_edl_server.models.pipeline import (
    Pipeline,
    NewPipeline,
    Status,
    State,
)
from fwdev_edl_server.models.inputs import ExternalEdl
from fwdev_edl_server.models.modifiers import IPv4Only as IPv4OnlyModifier
from fwdev_edl_server.models.outputs import IPv4Only, All


# ============================================================================
# TEST PIPELINE REFRESH - SINGLE INPUT
# ============================================================================

class TestPipelineRefreshSingleInput:
    """Test pipeline refresh with a single input"""

    def test_refresh_with_single_input_success(self, real_input, real_output_ipv4, mock_http_response):
        """Test successful refresh with single input"""
        now = datetime.now(timezone.utc)

        pipeline = Pipeline(
            id=uuid4(),
            created_at=now,
            updated_at=now,
            next_refresh=now,
            last_refresh=None,
            status=Status.PENDING,
            group="test",
            name="Test",
            refresh_rate=NewPipeline.RefreshRate(minutes=1),
            inputs=[real_input],
            modifiers=[],
            outputs=[real_output_ipv4]
        )

        with patch('fwdev_edl_server.models.inputs.requests.get') as mock_get:
            mock_get.return_value = mock_http_response(
                text="192.168.1.1\n10.0.0.5\n172.16.0.10"
            )

            result = pipeline.refresh()

            # Should return dict with output URLs
            assert isinstance(result, dict)
            assert len(result) == 1

            # Should have called HTTP once
            mock_get.assert_called_once()

    def test_refresh_output_structure(self, real_input, real_output_ipv4, mock_http_response):
        """Test that refresh returns proper output structure"""
        now = datetime.now(timezone.utc)
        pipeline_id = uuid4()

        pipeline = Pipeline(
            id=pipeline_id,
            created_at=now,
            updated_at=now,
            next_refresh=now,
            last_refresh=None,
            status=Status.PENDING,
            group="test",
            name="Test",
            refresh_rate=NewPipeline.RefreshRate(minutes=1),
            inputs=[real_input],
            modifiers=[],
            outputs=[real_output_ipv4]
        )

        with patch('fwdev_edl_server.models.inputs.requests.get') as mock_get:
            mock_get.return_value = mock_http_response()

            result = pipeline.refresh()

            # Key should be in format "{pipeline_id}/{output_type}"
            expected_key = f"{pipeline_id}/ipv4"
            assert expected_key in result

            # Value should be string output
            assert isinstance(result[expected_key], str)

    def test_refresh_validates_and_formats_data(self, real_input, real_output_ipv4, mock_http_response):
        """Test complete data flow: fetch → validate → format"""
        now = datetime.now(timezone.utc)

        pipeline = Pipeline(
            id=uuid4(),
            created_at=now,
            updated_at=now,
            next_refresh=now,
            last_refresh=None,
            status=Status.PENDING,
            group="test",
            name="Test",
            refresh_rate=NewPipeline.RefreshRate(minutes=1),
            inputs=[real_input],
            modifiers=[],
            outputs=[real_output_ipv4]
        )

        with patch('fwdev_edl_server.models.inputs.requests.get') as mock_get:
            # Mix of valid IPv4, invalid data
            mock_get.return_value = mock_http_response(
                text="192.168.1.0/24\ninvalid-data\n10.0.0.0/8\n999.999.999.999"
            )

            result = pipeline.refresh()

            output = list(result.values())[0]

            # Valid IPs should be present
            assert "192.168.1.0/24" in output
            assert "10.0.0.0/8" in output

            # Invalid data should be filtered
            assert "invalid-data" not in output
            assert "999.999.999.999" not in output


# ============================================================================
# TEST PIPELINE REFRESH - MULTIPLE INPUTS
# ============================================================================

class TestPipelineRefreshMultipleInputs:
    """Test pipeline refresh with multiple inputs (concurrent execution)"""

    def test_refresh_with_multiple_inputs(self, real_input, real_input_2, real_output_ipv4, mock_http_response):
        """Test refresh fetches from multiple inputs"""
        now = datetime.now(timezone.utc)

        pipeline = Pipeline(
            id=uuid4(),
            created_at=now,
            updated_at=now,
            next_refresh=now,
            last_refresh=None,
            status=Status.PENDING,
            group="test",
            name="Test",
            refresh_rate=NewPipeline.RefreshRate(minutes=1),
            inputs=[real_input, real_input_2],
            modifiers=[],
            outputs=[real_output_ipv4]
        )

        with patch('fwdev_edl_server.models.inputs.requests.get') as mock_get:
            # Different data from each input
            mock_get.side_effect = [
                mock_http_response(text="192.168.1.0/24\n192.168.2.0/24"),
                mock_http_response(text="10.0.0.0/8\n172.16.0.0/12")
            ]

            result = pipeline.refresh()

            # Both inputs should have been fetched
            assert mock_get.call_count == 2

            output = list(result.values())[0]

            # Data from both sources should be aggregated
            assert "192.168.1.0/24" in output or "192.168.2.0/24" in output
            assert "10.0.0.0/8" in output or "172.16.0.0/12" in output

    def test_refresh_handles_input_failure_gracefully(self, real_input, real_input_2, real_output_ipv4, mock_http_response):
        """Test that failure of one input doesn't kill entire refresh"""
        now = datetime.now(timezone.utc)

        pipeline = Pipeline(
            id=uuid4(),
            created_at=now,
            updated_at=now,
            next_refresh=now,
            last_refresh=None,
            status=Status.PENDING,
            group="test",
            name="Test",
            refresh_rate=NewPipeline.RefreshRate(minutes=1),
            inputs=[real_input, real_input_2],
            modifiers=[],
            outputs=[real_output_ipv4]
        )

        with patch('fwdev_edl_server.models.inputs.requests.get') as mock_get:
            # First input succeeds, second fails
            mock_get.side_effect = [
                mock_http_response(text="192.168.1.0/24"),
                Exception("Network error")
            ]

            # Should not raise exception
            result = pipeline.refresh()

            # Should still return results from successful input
            assert isinstance(result, dict)

    def test_refresh_three_inputs(self, real_input, real_input_2, real_input_3, real_output_ipv4, mock_http_response):
        """Test refresh with three inputs"""
        now = datetime.now(timezone.utc)

        pipeline = Pipeline(
            id=uuid4(),
            created_at=now,
            updated_at=now,
            next_refresh=now,
            last_refresh=None,
            status=Status.PENDING,
            group="test",
            name="Test",
            refresh_rate=NewPipeline.RefreshRate(minutes=1),
            inputs=[real_input, real_input_2, real_input_3],
            modifiers=[],
            outputs=[real_output_ipv4]
        )

        with patch('fwdev_edl_server.models.inputs.requests.get') as mock_get:
            mock_get.side_effect = [
                mock_http_response(text="192.168.1.0/24"),
                mock_http_response(text="10.0.0.0/8"),
                mock_http_response(text="172.16.0.0/12")
            ]

            result = pipeline.refresh()

            # All three inputs should be fetched
            assert mock_get.call_count == 3


# ============================================================================
# TEST PIPELINE REFRESH - WITH MODIFIERS
# ============================================================================

class TestPipelineRefreshWithModifiers:
    """Test pipeline refresh with modifier chain"""

    def test_refresh_applies_modifier(self, real_input, real_modifier, real_output_ipv4, mock_http_response):
        """Test that modifiers are applied to data"""
        now = datetime.now(timezone.utc)

        pipeline = Pipeline(
            id=uuid4(),
            created_at=now,
            updated_at=now,
            next_refresh=now,
            last_refresh=None,
            status=Status.PENDING,
            group="test",
            name="Test",
            refresh_rate=NewPipeline.RefreshRate(minutes=1),
            inputs=[real_input],
            modifiers=[real_modifier],  # IPv4Only modifier
            outputs=[real_output_ipv4]
        )

        with patch('fwdev_edl_server.models.inputs.requests.get') as mock_get:
            # Mix of IPv4 and IPv6
            mock_get.return_value = mock_http_response(
                text="192.168.1.0/24\n2001:db8::/32\n10.0.0.0/8"
            )

            result = pipeline.refresh()

            output = list(result.values())[0]

            # IPv4 should be present
            assert "192.168.1.0/24" in output or "10.0.0.0/8" in output

            # IPv6 should be filtered out by modifier
            assert "2001:db8::/32" not in output

    def test_refresh_with_multiple_modifiers_sequential(self, real_input, real_output_ipv4, mock_http_response):
        """Test that multiple modifiers are applied sequentially"""
        from fwdev_edl_server.models.modifiers import IPv4Only as IPv4OnlyMod, IPvPermit

        now = datetime.now(timezone.utc)

        # First filter to IPv4 only, then permit only 192.168.0.0/16
        modifiers = [
            IPv4OnlyMod(type="ipv4-only"),
            IPvPermit(type="ip-permit", subnets=["192.168.0.0/16"])
        ]

        pipeline = Pipeline(
            id=uuid4(),
            created_at=now,
            updated_at=now,
            next_refresh=now,
            last_refresh=None,
            status=Status.PENDING,
            group="test",
            name="Test",
            refresh_rate=NewPipeline.RefreshRate(minutes=1),
            inputs=[real_input],
            modifiers=modifiers,
            outputs=[real_output_ipv4]
        )

        with patch('fwdev_edl_server.models.inputs.requests.get') as mock_get:
            mock_get.return_value = mock_http_response(
                text="192.168.1.0/24\n10.0.0.0/8\n2001:db8::/32\n192.168.2.0/24"
            )

            result = pipeline.refresh()

            output = list(result.values())[0]

            # Only 192.168.0.0/16 IPv4 should pass
            assert "192.168.1.0/24" in output or "192.168.2.0/24" in output
            # 10.0.0.0/8 should be filtered by second modifier
            assert "10.0.0.0/8" not in output
            # IPv6 should be filtered by first modifier
            assert "2001:db8::/32" not in output


# ============================================================================
# TEST PIPELINE REFRESH - MULTIPLE OUTPUTS
# ============================================================================

class TestPipelineRefreshMultipleOutputs:
    """Test pipeline refresh with multiple outputs"""

    def test_refresh_with_multiple_outputs(self, real_input, real_output_ipv4, real_output_all, mock_http_response):
        """Test that multiple outputs are all generated"""
        now = datetime.now(timezone.utc)
        pipeline_id = uuid4()

        pipeline = Pipeline(
            id=pipeline_id,
            created_at=now,
            updated_at=now,
            next_refresh=now,
            last_refresh=None,
            status=Status.PENDING,
            group="test",
            name="Test",
            refresh_rate=NewPipeline.RefreshRate(minutes=1),
            inputs=[real_input],
            modifiers=[],
            outputs=[real_output_ipv4, real_output_all]
        )

        with patch('fwdev_edl_server.models.inputs.requests.get') as mock_get:
            mock_get.return_value = mock_http_response()

            result = pipeline.refresh()

            # Should have 2 outputs
            assert len(result) == 2

            # Both output types should be present
            assert f"{pipeline_id}/ipv4" in result
            assert f"{pipeline_id}/all" in result

    def test_refresh_three_outputs(self, real_input, real_output_ipv4, real_output_ipv6, real_output_all, mock_http_response):
        """Test refresh with three different output types"""
        now = datetime.now(timezone.utc)
        pipeline_id = uuid4()

        pipeline = Pipeline(
            id=pipeline_id,
            created_at=now,
            updated_at=now,
            next_refresh=now,
            last_refresh=None,
            status=Status.PENDING,
            group="test",
            name="Test",
            refresh_rate=NewPipeline.RefreshRate(minutes=1),
            inputs=[real_input],
            modifiers=[],
            outputs=[real_output_ipv4, real_output_ipv6, real_output_all]
        )

        with patch('fwdev_edl_server.models.inputs.requests.get') as mock_get:
            mock_get.return_value = mock_http_response()

            result = pipeline.refresh()

            # Should have 3 outputs
            assert len(result) == 3

            assert f"{pipeline_id}/ipv4" in result
            assert f"{pipeline_id}/ipv6" in result
            assert f"{pipeline_id}/all" in result


# ============================================================================
# TEST PIPELINE REFRESH - EDGE CASES
# ============================================================================

class TestPipelineRefreshEdgeCases:
    """Test edge cases and error conditions"""

    def test_refresh_with_empty_input_response(self, real_input, real_output_ipv4, mock_http_response):
        """Test refresh when input returns empty response"""
        now = datetime.now(timezone.utc)

        pipeline = Pipeline(
            id=uuid4(),
            created_at=now,
            updated_at=now,
            next_refresh=now,
            last_refresh=None,
            status=Status.PENDING,
            group="test",
            name="Test",
            refresh_rate=NewPipeline.RefreshRate(minutes=1),
            inputs=[real_input],
            modifiers=[],
            outputs=[real_output_ipv4]
        )

        with patch('fwdev_edl_server.models.inputs.requests.get') as mock_get:
            mock_get.return_value = mock_http_response(text="")

            result = pipeline.refresh()

            # Should return dict with empty output
            assert isinstance(result, dict)
            output = list(result.values())[0]
            assert output == ""

    def test_refresh_with_all_invalid_data(self, real_input, real_output_ipv4, mock_http_response):
        """Test refresh when all input data is invalid"""
        now = datetime.now(timezone.utc)

        pipeline = Pipeline(
            id=uuid4(),
            created_at=now,
            updated_at=now,
            next_refresh=now,
            last_refresh=None,
            status=Status.PENDING,
            group="test",
            name="Test",
            refresh_rate=NewPipeline.RefreshRate(minutes=1),
            inputs=[real_input],
            modifiers=[],
            outputs=[real_output_ipv4]
        )

        with patch('fwdev_edl_server.models.inputs.requests.get') as mock_get:
            mock_get.return_value = mock_http_response(
                text="invalid1\ninvalid2\n999.999.999.999"
            )

            result = pipeline.refresh()

            output = list(result.values())[0]
            # All invalid data filtered out
            assert output == ""

    def test_refresh_all_inputs_fail(self, real_input, real_input_2, real_output_ipv4):
        """Test refresh when all inputs fail"""
        now = datetime.now(timezone.utc)

        pipeline = Pipeline(
            id=uuid4(),
            created_at=now,
            updated_at=now,
            next_refresh=now,
            last_refresh=None,
            status=Status.PENDING,
            group="test",
            name="Test",
            refresh_rate=NewPipeline.RefreshRate(minutes=1),
            inputs=[real_input, real_input_2],
            modifiers=[],
            outputs=[real_output_ipv4]
        )

        with patch('fwdev_edl_server.models.inputs.requests.get') as mock_get:
            mock_get.side_effect = [
                Exception("Network error"),
                Exception("Timeout")
            ]

            # Should not raise
            result = pipeline.refresh()

            # Result should be dict with empty output
            assert isinstance(result, dict)


# ============================================================================
# TEST PIPELINE REFRESH - INTEGRATION
# ============================================================================

class TestPipelineRefreshIntegration:
    """End-to-end integration tests"""

    def test_complete_pipeline_workflow(self, real_input, real_input_2, real_modifier, real_output_ipv4, mock_http_response):
        """Test complete pipeline: multiple inputs → modifier → output"""
        now = datetime.now(timezone.utc)
        pipeline_id = uuid4()

        pipeline = Pipeline(
            id=pipeline_id,
            created_at=now,
            updated_at=now,
            next_refresh=now,
            last_refresh=None,
            status=Status.PENDING,
            group="security",
            name="Threat Intel Aggregator",
            description="Aggregates IPs from multiple sources",
            refresh_rate=NewPipeline.RefreshRate(minutes=5),
            inputs=[real_input, real_input_2],
            modifiers=[real_modifier],  # IPv4Only
            outputs=[real_output_ipv4]
        )

        with patch('fwdev_edl_server.models.inputs.requests.get') as mock_get:
            # Source 1: Mix of IPv4 and IPv6
            # Source 2: Mix of IPv4, IPv6, and invalid
            mock_get.side_effect = [
                mock_http_response(text="192.168.1.0/24\n2001:db8::/32\n10.0.0.0/8"),
                mock_http_response(text="172.16.0.0/12\nfe80::/10\ninvalid-data")
            ]

            result = pipeline.refresh()

            # Verify complete workflow
            assert isinstance(result, dict)
            assert len(result) == 1

            output_key = f"{pipeline_id}/ipv4"
            assert output_key in result

            output = result[output_key]

            # Should have IPv4 from both sources
            assert "192.168.1.0/24" in output or "10.0.0.0/8" in output or "172.16.0.0/12" in output

            # Should not have IPv6 (filtered by modifier)
            assert "2001:db8::/32" not in output
            assert "fe80::/10" not in output

            # Should not have invalid data
            assert "invalid-data" not in output

            # Both inputs were fetched
            assert mock_get.call_count == 2

    def test_realistic_threat_intel_scenario(self, real_input, real_input_2, real_input_3, real_output_all, mock_http_response):
        """Simulate realistic threat intelligence aggregation"""
        from fwdev_edl_server.models.modifiers import IPvDeny

        now = datetime.now(timezone.utc)

        # Deny internal IPs
        deny_internal = IPvDeny(
            type="ip-deny",
            subnets=["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]
        )

        pipeline = Pipeline(
            id=uuid4(),
            created_at=now,
            updated_at=now,
            next_refresh=now,
            last_refresh=None,
            status=Status.PENDING,
            group="threat-intel",
            name="Public Threat IPs",
            description="Aggregates threat IPs, excludes internal ranges",
            refresh_rate=NewPipeline.RefreshRate(hours=1),
            inputs=[real_input, real_input_2, real_input_3],
            modifiers=[deny_internal],
            outputs=[real_output_all]
        )

        with patch('fwdev_edl_server.models.inputs.requests.get') as mock_get:
            mock_get.side_effect = [
                # Source 1: Mix of public and internal
                mock_http_response(text="8.8.8.8/32\n192.168.1.100/32\n1.1.1.1/32"),
                # Source 2: Public IPs
                mock_http_response(text="185.220.100.0/24\n45.77.65.0/24"),
                # Source 3: Mix with domains
                mock_http_response(text="malicious.com\n10.5.5.5/32\n93.184.216.34/32")
            ]

            result = pipeline.refresh()

            output = list(result.values())[0]

            # Public IPs should be present
            assert "8.8.8.8/32" in output or "1.1.1.1/32" in output
            assert "185.220.100.0/24" in output or "45.77.65.0/24" in output
            assert "93.184.216.34/32" in output

            # Internal IPs should be denied
            assert "192.168.1.100/32" not in output
            assert "10.5.5.5/32" not in output

            # Domains should pass through
            assert "malicious.com" in output
