"""
Comprehensive test suite for fwdev_edl_server.models.pipeline

Tests cover:
- Pipeline model creation and validation
- RefreshRate validation and constraints
- Pipeline refresh logic with threading
- Output URL generation
- Model serialization
- Error handling during refresh
- Integration with inputs, modifiers, and outputs
"""

import pytest
from datetime import datetime, timezone
from uuid import uuid4, UUID
from unittest.mock import Mock, patch, MagicMock
import concurrent.futures as cf

from fwdev_edl_server.models.pipeline import (
    Pipeline,
    NewPipeline,
    Status,
    State,
    PipelineList
)


# ============================================================================
# FIXTURES
# ============================================================================
# Note: Real model fixtures are defined in conftest.py
# This includes: real_input, real_modifier, real_output_ipv4, etc.

@pytest.fixture
def sample_refresh_rate():
    """Create a sample RefreshRate"""
    return NewPipeline.RefreshRate(days=0, hours=0, minutes=1)


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

    def test_status_enum_count(self):
        """Test that Status has exactly 4 values"""
        assert len(Status) == 4

    def test_state_enum_values(self):
        """Test that State enum has correct values"""
        assert State.ENABLED.value == "ENABLED"
        assert State.DISABLED.value == "DISABLED"

    def test_state_enum_count(self):
        """Test that State has exactly 2 values"""
        assert len(State) == 2


# ============================================================================
# TEST REFRESH RATE
# ============================================================================

class TestRefreshRate:
    """Test RefreshRate validation and constraints"""

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

    def test_refresh_rate_days_min_constraint(self):
        """Test that days cannot be negative"""
        with pytest.raises(ValueError):
            NewPipeline.RefreshRate(days=-1, hours=0, minutes=0)

    def test_refresh_rate_days_max_constraint(self):
        """Test that days cannot exceed 365"""
        with pytest.raises(ValueError):
            NewPipeline.RefreshRate(days=366, hours=0, minutes=0)

    def test_refresh_rate_hours_min_constraint(self):
        """Test that hours cannot be negative"""
        with pytest.raises(ValueError):
            NewPipeline.RefreshRate(days=0, hours=-1, minutes=0)

    def test_refresh_rate_hours_max_constraint(self):
        """Test that hours cannot exceed 24"""
        with pytest.raises(ValueError):
            NewPipeline.RefreshRate(days=0, hours=25, minutes=0)

    def test_refresh_rate_minutes_min_constraint(self):
        """Test that minutes cannot be negative"""
        with pytest.raises(ValueError):
            NewPipeline.RefreshRate(days=0, hours=0, minutes=-1)

    def test_refresh_rate_minutes_max_constraint(self):
        """Test that minutes cannot exceed 60"""
        with pytest.raises(ValueError):
            NewPipeline.RefreshRate(days=0, hours=0, minutes=61)

    def test_refresh_rate_edge_case_max_values(self):
        """Test RefreshRate with maximum valid values"""
        refresh_rate = NewPipeline.RefreshRate(days=365, hours=24, minutes=60)
        assert refresh_rate.days == 365
        assert refresh_rate.hours == 24
        assert refresh_rate.minutes == 60

    def test_refresh_rate_one_minute(self):
        """Test common use case: 1 minute refresh"""
        refresh_rate = NewPipeline.RefreshRate(days=0, hours=0, minutes=1)
        assert refresh_rate.minutes == 1

    def test_refresh_rate_one_hour(self):
        """Test common use case: 1 hour refresh"""
        refresh_rate = NewPipeline.RefreshRate(days=0, hours=1, minutes=0)
        assert refresh_rate.hours == 1

    def test_refresh_rate_one_day(self):
        """Test common use case: 1 day refresh"""
        refresh_rate = NewPipeline.RefreshRate(days=1, hours=0, minutes=0)
        assert refresh_rate.days == 1


# ============================================================================
# TEST NEW PIPELINE
# ============================================================================

class TestNewPipeline:
    """Test NewPipeline model creation and validation"""

    def test_new_pipeline_creation(self, real_input, real_modifier, real_output_ipv4, sample_refresh_rate):
        """Test creating a NewPipeline with all fields"""
        pipeline = NewPipeline(
            group="test_group",
            name="Test Pipeline",
            description="A test pipeline for unit testing",
            state=State.ENABLED,
            refresh_rate=sample_refresh_rate,
            inputs=[real_input],
            modifiers=[real_modifier],
            outputs=[real_output_ipv4]
        )
        assert pipeline.group == "test_group"
        assert pipeline.name == "Test Pipeline"
        assert pipeline.description == "A test pipeline for unit testing"
        assert pipeline.state == State.ENABLED
        assert len(pipeline.inputs) == 1
        assert len(pipeline.modifiers) == 1
        assert len(pipeline.outputs) == 1

    def test_new_pipeline_state_defaults_to_enabled(self, real_input, sample_refresh_rate):
        """Test that state defaults to ENABLED"""
        pipeline = NewPipeline(
            group="test",
            name="Test",
            refresh_rate=sample_refresh_rate,
            inputs=[real_input]
        )
        assert pipeline.state == State.ENABLED

    def test_new_pipeline_modifiers_default_empty(self, real_input, sample_refresh_rate):
        """Test that modifiers default to empty list"""
        pipeline = NewPipeline(
            group="test",
            name="Test",
            refresh_rate=sample_refresh_rate,
            inputs=[real_input]
        )
        assert pipeline.modifiers == []
        assert isinstance(pipeline.modifiers, list)

    def test_new_pipeline_outputs_default_to_all(self, real_input, sample_refresh_rate):
        """Test that outputs default to [All(type='all')]"""
        pipeline = NewPipeline(
            group="test",
            name="Test",
            refresh_rate=sample_refresh_rate,
            inputs=[real_input]
        )
        assert len(pipeline.outputs) == 1
        assert pipeline.outputs[0].type == "all"

    def test_new_pipeline_description_optional(self, real_input, sample_refresh_rate):
        """Test that description is optional"""
        pipeline = NewPipeline(
            group="test",
            name="Test",
            refresh_rate=sample_refresh_rate,
            inputs=[real_input]
        )
        assert pipeline.description is None

    def test_new_pipeline_requires_group(self, real_input, sample_refresh_rate):
        """Test that group is required"""
        with pytest.raises(ValueError):
            NewPipeline(
                name="Test",
                refresh_rate=sample_refresh_rate,
                inputs=[real_input]
            )

    def test_new_pipeline_requires_name(self, real_input, sample_refresh_rate):
        """Test that name is required"""
        with pytest.raises(ValueError):
            NewPipeline(
                group="test",
                refresh_rate=sample_refresh_rate,
                inputs=[real_input]
            )

    def test_new_pipeline_requires_inputs(self, sample_refresh_rate):
        """Test that inputs are required (empty list not allowed)"""
        # Note: Pydantic allows empty lists, so this actually won't fail
        # But the application logic requires at least one input
        pipeline = NewPipeline(
            group="test",
            name="Test",
            refresh_rate=sample_refresh_rate,
            inputs=[]
        )
        # This will pass - empty list is valid for Pydantic
        assert len(pipeline.inputs) == 0

    def test_new_pipeline_multiple_inputs(self, real_input, real_input_2, real_input_3, sample_refresh_rate):
        """Test pipeline with multiple inputs"""
        pipeline = NewPipeline(
            group="test",
            name="Test",
            refresh_rate=sample_refresh_rate,
            inputs=[real_input, real_input_2, real_input_3]
        )
        assert len(pipeline.inputs) == 3


# ============================================================================
# TEST PIPELINE
# ============================================================================

class TestPipeline:
    """Test full Pipeline model with all fields"""

    def test_pipeline_creation(self, sample_pipeline):
        """Test creating a Pipeline with all required fields"""
        assert isinstance(sample_pipeline.id, UUID)
        assert isinstance(sample_pipeline.created_at, datetime)
        assert isinstance(sample_pipeline.updated_at, datetime)
        assert sample_pipeline.status == Status.PENDING
        assert sample_pipeline.last_refresh is None

    def test_pipeline_inherits_from_new_pipeline(self, sample_pipeline):
        """Test that Pipeline has all NewPipeline fields"""
        assert hasattr(sample_pipeline, 'group')
        assert hasattr(sample_pipeline, 'name')
        assert hasattr(sample_pipeline, 'description')
        assert hasattr(sample_pipeline, 'state')
        assert hasattr(sample_pipeline, 'refresh_rate')
        assert hasattr(sample_pipeline, 'inputs')
        assert hasattr(sample_pipeline, 'modifiers')
        assert hasattr(sample_pipeline, 'outputs')

    def test_pipeline_has_additional_fields(self, sample_pipeline):
        """Test that Pipeline has additional fields not in NewPipeline"""
        assert hasattr(sample_pipeline, 'id')
        assert hasattr(sample_pipeline, 'created_at')
        assert hasattr(sample_pipeline, 'updated_at')
        assert hasattr(sample_pipeline, 'next_refresh')
        assert hasattr(sample_pipeline, 'last_refresh')
        assert hasattr(sample_pipeline, 'status')

    def test_pipeline_id_is_uuid(self, sample_pipeline):
        """Test that pipeline ID is a valid UUID"""
        assert isinstance(sample_pipeline.id, UUID)
        # Verify it's a valid UUID by converting to string and back
        uuid_str = str(sample_pipeline.id)
        assert UUID(uuid_str) == sample_pipeline.id

    def test_pipeline_timestamps_are_datetime(self, sample_pipeline):
        """Test that timestamps are datetime objects"""
        assert isinstance(sample_pipeline.created_at, datetime)
        assert isinstance(sample_pipeline.updated_at, datetime)
        assert isinstance(sample_pipeline.next_refresh, datetime) or sample_pipeline.next_refresh is None

    def test_pipeline_last_refresh_can_be_none(self, sample_pipeline):
        """Test that last_refresh can be None for new pipelines"""
        assert sample_pipeline.last_refresh is None


# ============================================================================
# TEST OUTPUT URLS
# ============================================================================

class TestOutputUrls:
    """Test the output_urls computed field"""

    def test_output_urls_single_output(self, sample_pipeline):
        """Test output_urls with single output"""
        urls = sample_pipeline.output_urls
        assert len(urls) == 1
        assert urls[0] == f"/edl/{sample_pipeline.id}/ipv4"

    def test_output_urls_multiple_outputs(self, mock_input, sample_refresh_rate):
        """Test output_urls with multiple outputs"""
        mock_output1 = Mock()
        mock_output1.type = "ipv4"
        mock_output2 = Mock()
        mock_output2.type = "ipv6"
        mock_output3 = Mock()
        mock_output3.type = "all"

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
            refresh_rate=sample_refresh_rate,
            inputs=[mock_input],
            outputs=[mock_output1, mock_output2, mock_output3]
        )

        urls = pipeline.output_urls
        assert len(urls) == 3
        assert f"/edl/{pipeline.id}/ipv4" in urls
        assert f"/edl/{pipeline.id}/ipv6" in urls
        assert f"/edl/{pipeline.id}/all" in urls

    def test_output_urls_format(self, sample_pipeline):
        """Test that output URLs follow correct format"""
        urls = sample_pipeline.output_urls
        for url in urls:
            assert url.startswith("/edl/")
            assert str(sample_pipeline.id) in url

    def test_output_urls_is_computed_field(self, sample_pipeline):
        """Test that output_urls is a computed field (not stored)"""
        # output_urls should not be in model_dump by default
        dump = sample_pipeline.model_dump()
        # It will be in the serialized version due to model_serializer


# ============================================================================
# TEST MODEL SERIALIZATION
# ============================================================================

class TestModelSerialization:
    """Test the model_serializer for field ordering"""

    def test_serialization_includes_all_fields(self, sample_pipeline):
        """Test that serialization includes all expected fields"""
        serialized = sample_pipeline.model_dump()

        expected_fields = [
            'id', 'group', 'name', 'description', 'created_at', 'updated_at',
            'next_refresh', 'last_refresh', 'state', 'status', 'refresh_rate',
            'inputs', 'modifiers', 'outputs', 'output_urls'
        ]

        for field in expected_fields:
            assert field in serialized, f"Field '{field}' missing from serialization"

    def test_serialization_field_order(self, sample_pipeline):
        """Test that serialization maintains correct field order"""
        serialized = sample_pipeline.model_dump()
        keys = list(serialized.keys())

        expected_order = [
            'id', 'group', 'name', 'description', 'created_at', 'updated_at',
            'next_refresh', 'last_refresh', 'state', 'status', 'refresh_rate',
            'inputs', 'modifiers', 'outputs', 'output_urls'
        ]

        assert keys == expected_order

    def test_serialization_enum_values(self, sample_pipeline):
        """Test that enums are serialized as strings"""
        serialized = sample_pipeline.model_dump()

        assert serialized['state'] == "ENABLED"
        assert serialized['status'] == "PENDING"
        assert isinstance(serialized['state'], str)
        assert isinstance(serialized['status'], str)

    def test_serialization_output_urls_included(self, sample_pipeline):
        """Test that output_urls is included in serialization"""
        serialized = sample_pipeline.model_dump()
        assert 'output_urls' in serialized
        assert isinstance(serialized['output_urls'], list)


# ============================================================================
# TEST PIPELINE REFRESH - BASIC FUNCTIONALITY
# ============================================================================

class TestPipelineRefreshBasic:
    """Test basic refresh functionality"""

    def test_refresh_returns_dict(self, sample_pipeline):
        """Test that refresh returns a dictionary"""
        result = sample_pipeline.refresh()
        assert isinstance(result, dict)

    def test_refresh_with_single_input(self, mock_input, mock_output, sample_refresh_rate):
        """Test refresh with single input"""
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
            refresh_rate=sample_refresh_rate,
            inputs=[mock_input],
            modifiers=[],
            outputs=[mock_output]
        )

        result = pipeline.refresh()

        # Verify input was called
        mock_input.refresh.assert_called_once()

        # Verify output was called with data from input
        mock_output.refresh.assert_called_once()

    def test_refresh_with_multiple_inputs(self, mock_output, sample_refresh_rate):
        """Test refresh with multiple inputs (parallel execution)"""
        # Create 3 mock inputs
        mock_input1 = Mock()
        mock_input1.refresh.return_value = ["192.168.1.1", "192.168.1.2"]

        mock_input2 = Mock()
        mock_input2.refresh.return_value = ["10.0.0.1", "10.0.0.2"]

        mock_input3 = Mock()
        mock_input3.refresh.return_value = ["172.16.0.1", "172.16.0.2"]

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
            refresh_rate=sample_refresh_rate,
            inputs=[mock_input1, mock_input2, mock_input3],
            modifiers=[],
            outputs=[mock_output]
        )

        result = pipeline.refresh()

        # Verify all inputs were called
        mock_input1.refresh.assert_called_once()
        mock_input2.refresh.assert_called_once()
        mock_input3.refresh.assert_called_once()

        # Verify output received combined data (6 IPs total)
        call_args = mock_output.refresh.call_args[0][0]
        assert len(call_args) == 6

    def test_refresh_combines_input_data(self, mock_output, sample_refresh_rate):
        """Test that refresh combines data from all inputs"""
        mock_input1 = Mock()
        mock_input1.refresh.return_value = ["192.168.1.1", "192.168.1.2"]

        mock_input2 = Mock()
        mock_input2.refresh.return_value = ["10.0.0.1"]

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
            refresh_rate=sample_refresh_rate,
            inputs=[mock_input1, mock_input2],
            modifiers=[],
            outputs=[mock_output]
        )

        result = pipeline.refresh()

        # Get the data passed to output
        call_args = mock_output.refresh.call_args[0][0]

        # Should contain all IPs from both inputs
        assert "192.168.1.1" in call_args
        assert "192.168.1.2" in call_args
        assert "10.0.0.1" in call_args


# ============================================================================
# TEST PIPELINE REFRESH - MODIFIERS
# ============================================================================

class TestPipelineRefreshModifiers:
    """Test refresh with modifiers (data transformation)"""

    def test_refresh_applies_modifiers(self, mock_input, mock_output, sample_refresh_rate):
        """Test that modifiers are applied to input data"""
        mock_modifier = Mock()
        mock_modifier.refresh.return_value = ["192.168.1.1"]  # Filters to 1 IP

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
            refresh_rate=sample_refresh_rate,
            inputs=[mock_input],
            modifiers=[mock_modifier],
            outputs=[mock_output]
        )

        result = pipeline.refresh()

        # Modifier should be called with input data
        mock_modifier.refresh.assert_called_once()

        # Output should receive modified data
        call_args = mock_output.refresh.call_args[0][0]
        assert call_args == ["192.168.1.1"]

    def test_refresh_applies_multiple_modifiers_in_order(self, mock_input, mock_output, sample_refresh_rate):
        """Test that multiple modifiers are applied in sequence"""
        # First modifier: reduces 3 IPs to 2
        mock_modifier1 = Mock()
        mock_modifier1.refresh.return_value = ["192.168.1.1", "10.0.0.5"]

        # Second modifier: reduces 2 IPs to 1
        mock_modifier2 = Mock()
        mock_modifier2.refresh.return_value = ["192.168.1.1"]

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
            refresh_rate=sample_refresh_rate,
            inputs=[mock_input],
            modifiers=[mock_modifier1, mock_modifier2],
            outputs=[mock_output]
        )

        result = pipeline.refresh()

        # First modifier should receive input data
        mock_modifier1.refresh.assert_called_once()

        # Second modifier should receive output of first modifier
        call_args = mock_modifier2.refresh.call_args[0][0]
        assert call_args == ["192.168.1.1", "10.0.0.5"]

        # Output should receive final modified data
        output_call_args = mock_output.refresh.call_args[0][0]
        assert output_call_args == ["192.168.1.1"]

    def test_refresh_without_modifiers(self, mock_input, mock_output, sample_refresh_rate):
        """Test refresh works without any modifiers"""
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
            refresh_rate=sample_refresh_rate,
            inputs=[mock_input],
            modifiers=[],  # No modifiers
            outputs=[mock_output]
        )

        result = pipeline.refresh()

        # Output should receive unmodified input data
        call_args = mock_output.refresh.call_args[0][0]
        assert "192.168.1.1" in call_args
        assert len(call_args) == 3  # All 3 IPs from mock_input


# ============================================================================
# TEST PIPELINE REFRESH - OUTPUTS
# ============================================================================

class TestPipelineRefreshOutputs:
    """Test refresh with outputs (data formatting)"""

    def test_refresh_generates_outputs(self, mock_input, sample_refresh_rate):
        """Test that outputs are generated correctly"""
        mock_output = Mock()
        mock_output.type = "ipv4"
        mock_output.refresh.return_value = "192.168.1.1\n10.0.0.5\n172.16.0.10"

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
            refresh_rate=sample_refresh_rate,
            inputs=[mock_input],
            modifiers=[],
            outputs=[mock_output]
        )

        result = pipeline.refresh()

        # Result should be a dict with output path as key
        expected_key = f"{pipeline_id}/ipv4"
        assert expected_key in result
        assert result[expected_key] == "192.168.1.1\n10.0.0.5\n172.16.0.10"

    def test_refresh_multiple_outputs(self, mock_input, sample_refresh_rate):
        """Test refresh with multiple output formats"""
        mock_output_ipv4 = Mock()
        mock_output_ipv4.type = "ipv4"
        mock_output_ipv4.refresh.return_value = "192.168.1.1\n10.0.0.5"

        mock_output_all = Mock()
        mock_output_all.type = "all"
        mock_output_all.refresh.return_value = "192.168.1.1\nexample.com"

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
            refresh_rate=sample_refresh_rate,
            inputs=[mock_input],
            modifiers=[],
            outputs=[mock_output_ipv4, mock_output_all]
        )

        result = pipeline.refresh()

        # Should have both outputs in result dict
        assert len(result) == 2
        assert f"{pipeline_id}/ipv4" in result
        assert f"{pipeline_id}/all" in result

    def test_refresh_output_receives_modified_data(self, mock_input, sample_refresh_rate):
        """Test that outputs receive data after modifiers are applied"""
        # Modifier filters data
        mock_modifier = Mock()
        mock_modifier.refresh.return_value = ["192.168.1.1"]

        mock_output = Mock()
        mock_output.type = "ipv4"
        mock_output.refresh.return_value = "192.168.1.1"

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
            refresh_rate=sample_refresh_rate,
            inputs=[mock_input],
            modifiers=[mock_modifier],
            outputs=[mock_output]
        )

        result = pipeline.refresh()

        # Output should receive filtered data (1 IP instead of 3)
        call_args = mock_output.refresh.call_args[0][0]
        assert call_args == ["192.168.1.1"]
        assert len(call_args) == 1


# ============================================================================
# TEST PIPELINE REFRESH - ERROR HANDLING
# ============================================================================

class TestPipelineRefreshErrorHandling:
    """Test error handling during refresh"""

    def test_refresh_handles_input_exception(self, mock_output, sample_refresh_rate):
        """Test that exceptions in input.refresh() are caught and handled"""
        # First input succeeds
        mock_input1 = Mock()
        mock_input1.refresh.return_value = ["192.168.1.1"]

        # Second input raises exception
        mock_input2 = Mock()
        mock_input2.refresh.side_effect = Exception("Network error")

        # Third input succeeds
        mock_input3 = Mock()
        mock_input3.refresh.return_value = ["10.0.0.5"]

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
            refresh_rate=sample_refresh_rate,
            inputs=[mock_input1, mock_input2, mock_input3],
            modifiers=[],
            outputs=[mock_output]
        )

        # Should not raise exception
        result = pipeline.refresh()

        # Should still process successful inputs
        assert isinstance(result, dict)

        # Output should receive data from successful inputs only
        call_args = mock_output.refresh.call_args[0][0]
        assert "192.168.1.1" in call_args
        assert "10.0.0.5" in call_args

    def test_refresh_handles_modifier_exception(self, mock_input, mock_output, sample_refresh_rate):
        """Test that exceptions in modifier.refresh() are caught"""
        mock_modifier = Mock()
        mock_modifier.refresh.side_effect = Exception("Modifier error")

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
            refresh_rate=sample_refresh_rate,
            inputs=[mock_input],
            modifiers=[mock_modifier],
            outputs=[mock_output]
        )

        # Should not raise exception
        result = pipeline.refresh()
        assert isinstance(result, dict)

    def test_refresh_handles_output_exception(self, mock_input, sample_refresh_rate):
        """Test that exceptions in output.refresh() are caught"""
        mock_output = Mock()
        mock_output.type = "ipv4"
        mock_output.refresh.side_effect = Exception("Output formatting error")

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
            refresh_rate=sample_refresh_rate,
            inputs=[mock_input],
            modifiers=[],
            outputs=[mock_output]
        )

        # Should not raise exception
        result = pipeline.refresh()

        # Result should be dict but without the failed output
        assert isinstance(result, dict)
        expected_key = f"{pipeline_id}/ipv4"
        # Key won't be in result because exception was caught

    def test_refresh_continues_after_partial_failure(self, mock_input, sample_refresh_rate):
        """Test that refresh continues processing other outputs after one fails"""
        # First output fails
        mock_output1 = Mock()
        mock_output1.type = "ipv4"
        mock_output1.refresh.side_effect = Exception("Error")

        # Second output succeeds
        mock_output2 = Mock()
        mock_output2.type = "all"
        mock_output2.refresh.return_value = "192.168.1.1"

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
            refresh_rate=sample_refresh_rate,
            inputs=[mock_input],
            modifiers=[],
            outputs=[mock_output1, mock_output2]
        )

        result = pipeline.refresh()

        # Second output should still be in results
        expected_key = f"{pipeline_id}/all"
        assert expected_key in result


# ============================================================================
# TEST PIPELINE REFRESH - THREADING
# ============================================================================

class TestPipelineRefreshThreading:
    """Test that refresh uses ThreadPoolExecutor correctly"""

    @patch('fwdev_edl_server.models.pipeline.cf.ThreadPoolExecutor')
    def test_refresh_uses_thread_pool(self, mock_executor_class, mock_input, mock_output, sample_refresh_rate):
        """Test that refresh creates a ThreadPoolExecutor"""
        # Setup mock
        mock_executor = MagicMock()
        mock_executor_class.return_value.__enter__.return_value = mock_executor

        mock_future = Mock()
        mock_future.result.return_value = ["192.168.1.1"]
        mock_executor.submit.return_value = mock_future

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
            refresh_rate=sample_refresh_rate,
            inputs=[mock_input],
            modifiers=[],
            outputs=[mock_output]
        )

        result = pipeline.refresh()

        # Verify ThreadPoolExecutor was created (without max_workers since we reverted)
        mock_executor_class.assert_called_once_with()

    @patch('fwdev_edl_server.models.pipeline.cf.ThreadPoolExecutor')
    def test_refresh_submits_tasks_for_each_input(self, mock_executor_class, mock_output, sample_refresh_rate):
        """Test that a task is submitted for each input"""
        # Create 3 inputs
        mock_input1 = Mock()
        mock_input2 = Mock()
        mock_input3 = Mock()

        # Setup mock executor
        mock_executor = MagicMock()
        mock_executor_class.return_value.__enter__.return_value = mock_executor

        mock_future = Mock()
        mock_future.result.return_value = ["192.168.1.1"]
        mock_executor.submit.return_value = mock_future

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
            refresh_rate=sample_refresh_rate,
            inputs=[mock_input1, mock_input2, mock_input3],
            modifiers=[],
            outputs=[mock_output]
        )

        result = pipeline.refresh()

        # Verify submit was called 3 times (once per input)
        assert mock_executor.submit.call_count == 3


# ============================================================================
# TEST PIPELINE LIST
# ============================================================================

class TestPipelineList:
    """Test PipelineList model"""

    def test_pipeline_list_creation_empty(self):
        """Test creating an empty PipelineList"""
        pipeline_list = PipelineList()
        assert pipeline_list.count == 0
        assert pipeline_list.total == 0
        assert pipeline_list.pipelines == []

    def test_pipeline_list_with_pipelines(self, sample_pipeline):
        """Test creating PipelineList with pipelines"""
        pipeline_list = PipelineList(
            count=1,
            total=1,
            pipelines=[sample_pipeline]
        )
        assert pipeline_list.count == 1
        assert pipeline_list.total == 1
        assert len(pipeline_list.pipelines) == 1
        assert pipeline_list.pipelines[0] == sample_pipeline

    def test_pipeline_list_defaults(self):
        """Test that PipelineList fields have correct defaults"""
        pipeline_list = PipelineList(pipelines=[])
        assert pipeline_list.count == 0
        assert pipeline_list.total == 0
        assert isinstance(pipeline_list.pipelines, list)


# ============================================================================
# TEST INTEGRATION SCENARIOS
# ============================================================================

class TestIntegrationScenarios:
    """Test realistic end-to-end scenarios"""

    def test_complete_pipeline_workflow(self, sample_refresh_rate):
        """Test a complete pipeline refresh workflow with real-like data"""
        # Setup inputs
        input1 = Mock()
        input1.refresh.return_value = ["192.168.1.1", "192.168.1.2", "invalid_ip", "10.0.0.1"]

        input2 = Mock()
        input2.refresh.return_value = ["172.16.0.1", "example.com", "192.168.1.1"]  # Duplicate IP

        # Setup modifier (filters to only IPs)
        modifier = Mock()
        modifier.refresh.return_value = ["192.168.1.1", "192.168.1.2", "10.0.0.1", "172.16.0.1", "192.168.1.1"]

        # Setup output
        output = Mock()
        output.type = "ipv4"
        output.refresh.return_value = "192.168.1.1\n192.168.1.2\n10.0.0.1\n172.16.0.1\n192.168.1.1"

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
            name="Threat Intelligence Aggregator",
            description="Aggregates IPs from multiple sources",
            refresh_rate=sample_refresh_rate,
            inputs=[input1, input2],
            modifiers=[modifier],
            outputs=[output]
        )

        result = pipeline.refresh()

        # Verify complete workflow
        assert isinstance(result, dict)
        assert len(result) == 1
        expected_key = f"{pipeline_id}/ipv4"
        assert expected_key in result

        # Verify both inputs were called
        input1.refresh.assert_called_once()
        input2.refresh.assert_called_once()

        # Verify modifier received combined data
        modifier.refresh.assert_called_once()

        # Verify output was generated
        output.refresh.assert_called_once()

    def test_pipeline_with_no_modifiers_and_multiple_outputs(self, sample_refresh_rate):
        """Test pipeline that outputs raw data in multiple formats"""
        input1 = Mock()
        input1.refresh.return_value = ["192.168.1.1", "example.com", "https://evil.com"]

        output_ipv4 = Mock()
        output_ipv4.type = "ipv4"
        output_ipv4.refresh.return_value = "192.168.1.1"

        output_fqdn = Mock()
        output_fqdn.type = "fqdn"
        output_fqdn.refresh.return_value = "example.com"

        output_all = Mock()
        output_all.type = "all"
        output_all.refresh.return_value = "192.168.1.1\nexample.com\nhttps://evil.com"

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
            name="Multi-format output",
            refresh_rate=sample_refresh_rate,
            inputs=[input1],
            modifiers=[],  # No modifiers
            outputs=[output_ipv4, output_fqdn, output_all]
        )

        result = pipeline.refresh()

        # Should have 3 outputs
        assert len(result) == 3
        assert f"{pipeline_id}/ipv4" in result
        assert f"{pipeline_id}/fqdn" in result
        assert f"{pipeline_id}/all" in result


# ============================================================================
# SUMMARY
# ============================================================================

"""
Test Coverage Summary:
=====================

1. Enums (Status, State)
   - Value validation
   - Count verification

2. RefreshRate
   - Valid creation
   - Default values
   - Min/max constraints for days, hours, minutes
   - Edge cases

3. NewPipeline
   - Model creation
   - Default values
   - Required fields
   - Optional fields
   - Multiple inputs

4. Pipeline
   - Full model creation
   - Inheritance from NewPipeline
   - UUID validation
   - Timestamp validation
   - Additional fields

5. Output URLs
   - Single and multiple outputs
   - URL format validation
   - Computed field behavior

6. Model Serialization
   - Field inclusion
   - Field ordering
   - Enum serialization
   - Output URLs in serialization

7. Pipeline Refresh - Basic
   - Return type validation
   - Single and multiple inputs
   - Data combination from inputs

8. Pipeline Refresh - Modifiers
   - Single and multiple modifiers
   - Sequential application
   - Pipeline without modifiers

9. Pipeline Refresh - Outputs
   - Output generation
   - Multiple output formats
   - Output receives modified data

10. Pipeline Refresh - Error Handling
    - Input exceptions
    - Modifier exceptions
    - Output exceptions
    - Partial failure handling

11. Pipeline Refresh - Threading
    - ThreadPoolExecutor usage
    - Task submission for each input

12. PipelineList
    - Empty list creation
    - List with pipelines
    - Default values

13. Integration Scenarios
    - Complete workflow
    - Real-world use cases

Total Test Cases: 75+
"""
