"""
Fixed test suite for fwdev_edl_server.models.pipeline using real model instances

This demonstrates the correct approach: using real Pydantic models with mocked HTTP layer
"""

import pytest
from datetime import datetime, timezone
from uuid import uuid4
from unittest.mock import Mock, patch
from ipaddress import IPv4Network

from fwdev_edl_server.models.pipeline import (
    Pipeline,
    NewPipeline,
    Status,
    State,
)


# ============================================================================
# TEST ENUMS
# ============================================================================

class TestEnums:
    """Test Status and State enums"""

    def test_status_enum_values(self):
        """Test that Status enum has correct values"""
        assert Status.PENDING.value == "PENDING"
        assert Status.RUNNING.value == "RUNNING"
        assert Status.COMPLETED.value == "COMPLETED"
        assert Status.FAILED.value == "FAILED"

    def test_state_enum_values(self):
        """Test that State enum has correct values"""
        assert State.ENABLED.value == "ENABLED"
        assert State.DISABLED.value == "DISABLED"


# ============================================================================
# TEST REFRESH RATE
# ============================================================================

class TestRefreshRate:
    """Test RefreshRate validation"""

    def test_refresh_rate_creation_valid(self):
        """Test creating RefreshRate with valid values"""
        refresh_rate = NewPipeline.RefreshRate(days=1, hours=12, minutes=30)
        assert refresh_rate.days == 1
        assert refresh_rate.hours == 12
        assert refresh_rate.minutes == 30

    def test_refresh_rate_defaults_to_zero(self):
        """Test that RefreshRate fields default to 0"""
        refresh_rate = NewPipeline.RefreshRate()
        assert refresh_rate.days == 0
        assert refresh_rate.hours == 0
        assert refresh_rate.minutes == 0

    def test_refresh_rate_days_max_constraint(self):
        """Test that days cannot exceed 365"""
        with pytest.raises(ValueError):
            NewPipeline.RefreshRate(days=366, hours=0, minutes=0)


# ============================================================================
# TEST NEW PIPELINE WITH REAL MODELS
# ============================================================================

class TestNewPipeline:
    """Test NewPipeline with real model instances"""

    def test_new_pipeline_creation(self, real_input, real_output_ipv4):
        """Test creating NewPipeline with real models"""
        refresh_rate = NewPipeline.RefreshRate(minutes=1)

        pipeline = NewPipeline(
            group="test_group",
            name="Test Pipeline",
            description="A test pipeline",
            refresh_rate=refresh_rate,
            inputs=[real_input],
            outputs=[real_output_ipv4]
        )

        assert pipeline.group == "test_group"
        assert pipeline.name == "Test Pipeline"
        assert len(pipeline.inputs) == 1
        assert len(pipeline.outputs) == 1

    def test_new_pipeline_state_defaults_to_enabled(self, real_input):
        """Test that state defaults to ENABLED"""
        pipeline = NewPipeline(
            group="test",
            name="Test",
            refresh_rate=NewPipeline.RefreshRate(minutes=1),
            inputs=[real_input]
        )
        assert pipeline.state == State.ENABLED

    def test_new_pipeline_with_multiple_inputs(self, real_input, real_input_2, real_input_3):
        """Test pipeline with multiple real inputs"""
        pipeline = NewPipeline(
            group="test",
            name="Test",
            refresh_rate=NewPipeline.RefreshRate(minutes=1),
            inputs=[real_input, real_input_2, real_input_3]
        )
        assert len(pipeline.inputs) == 3


# ============================================================================
# TEST PIPELINE WITH REAL MODELS
# ============================================================================

class TestPipeline:
    """Test full Pipeline model"""

    def test_pipeline_creation(self, real_input, real_output_ipv4):
        """Test creating Pipeline with all fields"""
        now = datetime.now(timezone.utc)

        pipeline = Pipeline(
            id=uuid4(),
            created_at=now,
            updated_at=now,
            next_refresh=now,
            last_refresh=None,
            status=Status.PENDING,
            group="test",
            name="Test Pipeline",
            refresh_rate=NewPipeline.RefreshRate(minutes=1),
            inputs=[real_input],
            outputs=[real_output_ipv4]
        )

        assert pipeline.status == Status.PENDING
        assert pipeline.group == "test"
        assert len(pipeline.inputs) == 1

    def test_pipeline_output_urls(self, real_input, real_output_ipv4):
        """Test that output_urls are generated correctly"""
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
            outputs=[real_output_ipv4]
        )

        urls = pipeline.output_urls
        assert len(urls) == 1
        assert urls[0] == f"/edl/{pipeline_id}/ipv4"


# ============================================================================
# TEST PIPELINE REFRESH WITH REAL MODELS
# ============================================================================

class TestPipelineRefresh:
    """Test pipeline refresh with real models and mocked HTTP"""

    def test_refresh_with_single_input(self, real_input, real_output_ipv4, mock_http_response):
        """Test refresh with single real input and mocked HTTP"""
        now = datetime.now(timezone.utc)

        # Create pipeline with real models
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

        # Mock the HTTP layer
        with patch('fwdev_edl_server.models.inputs.requests.get') as mock_get:
            mock_get.return_value = mock_http_response()

            # Run refresh
            result = pipeline.refresh()

            # Verify
            assert isinstance(result, dict)
            assert len(result) == 1
            mock_get.assert_called_once()

    def test_refresh_with_multiple_inputs(self, real_input, real_input_2, real_output_ipv4, mock_http_response):
        """Test refresh with multiple inputs fetched in parallel"""
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
            # Return different data for each call
            mock_get.side_effect = [
                mock_http_response(text="192.168.1.1\n192.168.1.2"),
                mock_http_response(text="10.0.0.1\n10.0.0.2")
            ]

            result = pipeline.refresh()

            assert isinstance(result, dict)
            assert mock_get.call_count == 2  # Both inputs were fetched

    def test_refresh_with_modifier(self, real_input, real_modifier, real_output_ipv4, mock_http_response):
        """Test refresh with modifier applied"""
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
            modifiers=[real_modifier],  # Real modifier
            outputs=[real_output_ipv4]
        )

        with patch('fwdev_edl_server.models.inputs.requests.get') as mock_get:
            mock_get.return_value = mock_http_response()

            result = pipeline.refresh()

            assert isinstance(result, dict)

    def test_refresh_handles_http_error(self, real_input, real_output_ipv4):
        """Test that HTTP errors are handled gracefully"""
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
            outputs=[real_output_ipv4]
        )

        with patch('fwdev_edl_server.models.inputs.requests.get') as mock_get:
            # Simulate HTTP error
            mock_get.side_effect = Exception("Network error")

            # Should not raise, errors are caught
            result = pipeline.refresh()
            assert isinstance(result, dict)


# ============================================================================
# TEST INTEGRATION
# ============================================================================

class TestIntegration:
    """Test complete workflow with real models"""

    def test_complete_pipeline_workflow(self, real_input, real_input_2, real_modifier, real_output_ipv4, mock_http_response):
        """Test end-to-end pipeline with multiple inputs, modifier, and output"""
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
            modifiers=[real_modifier],
            outputs=[real_output_ipv4]
        )

        with patch('fwdev_edl_server.models.inputs.requests.get') as mock_get:
            # Mock responses for both inputs
            mock_get.side_effect = [
                mock_http_response(text="192.168.1.1\n192.168.1.2\n10.0.0.1"),
                mock_http_response(text="172.16.0.1\n192.168.1.1")  # Duplicate IP
            ]

            result = pipeline.refresh()

            # Verify workflow
            assert isinstance(result, dict)
            assert len(result) == 1
            assert f"{pipeline_id}/ipv4" in result

            # Both inputs were fetched
            assert mock_get.call_count == 2


"""
Summary:
========

This test file demonstrates the CORRECT approach to testing Pydantic models:

1. ✅ Use REAL model instances (ExternalEdl, IPv4Only, etc.)
2. ✅ Mock the HTTP layer (requests.get)
3. ✅ Tests actual Pydantic validation
4. ✅ Tests real model behavior
5. ✅ Only mocks external dependencies

Key Pattern:
-----------

```python
# Create real models
real_input = ExternalEdl(type="edl", url="https://test.com/edl")
real_output = IPv4Only(type="ipv4")

# Mock HTTP layer
with patch('fwdev_edl_server.models.inputs.requests.get') as mock_get:
    mock_get.return_value = mock_http_response()

    # Create pipeline with real models
    pipeline = Pipeline(..., inputs=[real_input], outputs=[real_output])

    # Test
    result = pipeline.refresh()
```

All tests in this file should PASS because they use real models!
"""
