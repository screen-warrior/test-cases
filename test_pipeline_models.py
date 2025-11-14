"""
Comprehensive test suite for pipeline models

Tests NewPipeline, Pipeline, RefreshRate, Status, State enums, and PipelineList.
This validates all Pydantic model structures and constraints.
"""

import pytest
from datetime import datetime, timezone, timedelta
from uuid import uuid4, UUID

from fwdev_edl_server.models.pipeline import (
    Status,
    State,
    NewPipeline,
    Pipeline,
    PipelineList,
)


# ============================================================================
# TEST STATUS ENUM
# ============================================================================

class TestStatusEnum:
    """Test Status enum values and behavior"""

    def test_status_enum_values(self):
        """Test that Status enum has correct values"""
        assert Status.PENDING.value == "PENDING"
        assert Status.RUNNING.value == "RUNNING"
        assert Status.COMPLETED.value == "COMPLETED"
        assert Status.FAILED.value == "FAILED"

    def test_status_enum_count(self):
        """Test that Status has exactly 4 values"""
        assert len(Status) == 4

    def test_status_enum_membership(self):
        """Test membership checking"""
        assert Status.PENDING in Status
        assert Status.RUNNING in Status
        assert Status.COMPLETED in Status
        assert Status.FAILED in Status

    def test_status_string_conversion(self):
        """Test string conversion"""
        assert str(Status.PENDING) == "Status.PENDING"
        assert Status.PENDING.value == "PENDING"


# ============================================================================
# TEST STATE ENUM
# ============================================================================

class TestStateEnum:
    """Test State enum values and behavior"""

    def test_state_enum_values(self):
        """Test that State enum has correct values"""
        assert State.ENABLED.value == "ENABLED"
        assert State.DISABLED.value == "DISABLED"

    def test_state_enum_count(self):
        """Test that State has exactly 2 values"""
        assert len(State) == 2

    def test_state_enum_membership(self):
        """Test membership checking"""
        assert State.ENABLED in State
        assert State.DISABLED in State

    def test_state_string_conversion(self):
        """Test string conversion"""
        assert str(State.ENABLED) == "State.ENABLED"
        assert State.ENABLED.value == "ENABLED"


# ============================================================================
# TEST REFRESHRATE MODEL
# ============================================================================

class TestRefreshRateModel:
    """Test NewPipeline.RefreshRate validation"""

    def test_refresh_rate_valid_values(self):
        """Test creating RefreshRate with valid values"""
        rate = NewPipeline.RefreshRate(days=1, hours=12, minutes=30)

        assert rate.days == 1
        assert rate.hours == 12
        assert rate.minutes == 30

    def test_refresh_rate_defaults_to_zero(self):
        """Test that all fields default to 0"""
        rate = NewPipeline.RefreshRate()

        assert rate.days == 0
        assert rate.hours == 0
        assert rate.minutes == 0

    def test_refresh_rate_days_minimum(self):
        """Test days minimum value (0)"""
        rate = NewPipeline.RefreshRate(days=0)
        assert rate.days == 0

        # Negative should fail
        with pytest.raises(Exception):
            NewPipeline.RefreshRate(days=-1)

    def test_refresh_rate_days_maximum(self):
        """Test days maximum value (365)"""
        rate = NewPipeline.RefreshRate(days=365)
        assert rate.days == 365

        # 366 should fail
        with pytest.raises(Exception):
            NewPipeline.RefreshRate(days=366)

    def test_refresh_rate_hours_minimum(self):
        """Test hours minimum value (0)"""
        rate = NewPipeline.RefreshRate(hours=0)
        assert rate.hours == 0

        # Negative should fail
        with pytest.raises(Exception):
            NewPipeline.RefreshRate(hours=-1)

    def test_refresh_rate_hours_maximum(self):
        """Test hours maximum value (24)"""
        rate = NewPipeline.RefreshRate(hours=24)
        assert rate.hours == 24

        # 25 should fail
        with pytest.raises(Exception):
            NewPipeline.RefreshRate(hours=25)

    def test_refresh_rate_minutes_minimum(self):
        """Test minutes minimum value (0)"""
        rate = NewPipeline.RefreshRate(minutes=0)
        assert rate.minutes == 0

        # Negative should fail
        with pytest.raises(Exception):
            NewPipeline.RefreshRate(minutes=-1)

    def test_refresh_rate_minutes_maximum(self):
        """Test minutes maximum value (60)"""
        rate = NewPipeline.RefreshRate(minutes=60)
        assert rate.minutes == 60

        # 61 should fail
        with pytest.raises(Exception):
            NewPipeline.RefreshRate(minutes=61)

    def test_refresh_rate_boundary_values(self):
        """Test all boundary values together"""
        # Min values
        rate_min = NewPipeline.RefreshRate(days=0, hours=0, minutes=0)
        assert rate_min.days == 0
        assert rate_min.hours == 0
        assert rate_min.minutes == 0

        # Max values
        rate_max = NewPipeline.RefreshRate(days=365, hours=24, minutes=60)
        assert rate_max.days == 365
        assert rate_max.hours == 24
        assert rate_max.minutes == 60

    def test_refresh_rate_realistic_values(self):
        """Test realistic refresh rate values"""
        # Every hour
        rate = NewPipeline.RefreshRate(hours=1)
        assert rate.hours == 1

        # Every day
        rate = NewPipeline.RefreshRate(days=1)
        assert rate.days == 1

        # Every 5 minutes
        rate = NewPipeline.RefreshRate(minutes=5)
        assert rate.minutes == 5

        # Weekly
        rate = NewPipeline.RefreshRate(days=7)
        assert rate.days == 7


# ============================================================================
# TEST NEWPIPELINE MODEL
# ============================================================================

class TestNewPipelineModel:
    """Test NewPipeline model creation and validation"""

    def test_new_pipeline_creation(self, real_input, real_output_ipv4):
        """Test creating NewPipeline with required fields"""
        rate = NewPipeline.RefreshRate(minutes=1)

        pipeline = NewPipeline(
            group="test_group",
            name="Test Pipeline",
            refresh_rate=rate,
            inputs=[real_input],
            outputs=[real_output_ipv4]
        )

        assert pipeline.group == "test_group"
        assert pipeline.name == "Test Pipeline"
        assert len(pipeline.inputs) == 1
        assert len(pipeline.outputs) == 1

    def test_new_pipeline_with_description(self, real_input):
        """Test NewPipeline with optional description"""
        rate = NewPipeline.RefreshRate(minutes=1)

        pipeline = NewPipeline(
            group="test",
            name="Test",
            description="A test pipeline",
            refresh_rate=rate,
            inputs=[real_input]
        )

        assert pipeline.description == "A test pipeline"

    def test_new_pipeline_description_defaults_to_none(self, real_input):
        """Test that description defaults to None"""
        rate = NewPipeline.RefreshRate(minutes=1)

        pipeline = NewPipeline(
            group="test",
            name="Test",
            refresh_rate=rate,
            inputs=[real_input]
        )

        assert pipeline.description is None

    def test_new_pipeline_state_defaults_to_enabled(self, real_input):
        """Test that state defaults to ENABLED"""
        rate = NewPipeline.RefreshRate(minutes=1)

        pipeline = NewPipeline(
            group="test",
            name="Test",
            refresh_rate=rate,
            inputs=[real_input]
        )

        assert pipeline.state == State.ENABLED

    def test_new_pipeline_state_can_be_disabled(self, real_input):
        """Test setting state to DISABLED"""
        rate = NewPipeline.RefreshRate(minutes=1)

        pipeline = NewPipeline(
            group="test",
            name="Test",
            state=State.DISABLED,
            refresh_rate=rate,
            inputs=[real_input]
        )

        assert pipeline.state == State.DISABLED

    def test_new_pipeline_modifiers_default_empty(self, real_input):
        """Test that modifiers default to empty list"""
        rate = NewPipeline.RefreshRate(minutes=1)

        pipeline = NewPipeline(
            group="test",
            name="Test",
            refresh_rate=rate,
            inputs=[real_input]
        )

        assert pipeline.modifiers == []
        assert isinstance(pipeline.modifiers, list)

    def test_new_pipeline_with_modifiers(self, real_input, real_modifier):
        """Test NewPipeline with modifiers"""
        rate = NewPipeline.RefreshRate(minutes=1)

        pipeline = NewPipeline(
            group="test",
            name="Test",
            refresh_rate=rate,
            inputs=[real_input],
            modifiers=[real_modifier]
        )

        assert len(pipeline.modifiers) == 1

    def test_new_pipeline_outputs_default_to_all(self, real_input):
        """Test that outputs default to [All(type='all')]"""
        rate = NewPipeline.RefreshRate(minutes=1)

        pipeline = NewPipeline(
            group="test",
            name="Test",
            refresh_rate=rate,
            inputs=[real_input]
        )

        assert len(pipeline.outputs) == 1
        assert pipeline.outputs[0].type == "all"

    def test_new_pipeline_with_multiple_inputs(self, real_input, real_input_2, real_input_3):
        """Test pipeline with multiple inputs"""
        rate = NewPipeline.RefreshRate(minutes=1)

        pipeline = NewPipeline(
            group="test",
            name="Test",
            refresh_rate=rate,
            inputs=[real_input, real_input_2, real_input_3]
        )

        assert len(pipeline.inputs) == 3

    def test_new_pipeline_with_multiple_outputs(self, real_input, real_output_ipv4, real_output_ipv6):
        """Test pipeline with multiple outputs"""
        rate = NewPipeline.RefreshRate(minutes=1)

        pipeline = NewPipeline(
            group="test",
            name="Test",
            refresh_rate=rate,
            inputs=[real_input],
            outputs=[real_output_ipv4, real_output_ipv6]
        )

        assert len(pipeline.outputs) == 2

    def test_new_pipeline_requires_group(self, real_input):
        """Test that group is required"""
        rate = NewPipeline.RefreshRate(minutes=1)

        with pytest.raises(Exception):
            NewPipeline(
                name="Test",
                refresh_rate=rate,
                inputs=[real_input]
            )

    def test_new_pipeline_requires_name(self, real_input):
        """Test that name is required"""
        rate = NewPipeline.RefreshRate(minutes=1)

        with pytest.raises(Exception):
            NewPipeline(
                group="test",
                refresh_rate=rate,
                inputs=[real_input]
            )

    def test_new_pipeline_requires_refresh_rate(self, real_input):
        """Test that refresh_rate is required"""
        with pytest.raises(Exception):
            NewPipeline(
                group="test",
                name="Test",
                inputs=[real_input]
            )

    def test_new_pipeline_requires_inputs(self):
        """Test that inputs are required"""
        rate = NewPipeline.RefreshRate(minutes=1)

        with pytest.raises(Exception):
            NewPipeline(
                group="test",
                name="Test",
                refresh_rate=rate
            )

    def test_new_pipeline_allows_empty_inputs(self):
        """Test that empty inputs list is allowed by Pydantic"""
        rate = NewPipeline.RefreshRate(minutes=1)

        # Pydantic allows empty lists
        pipeline = NewPipeline(
            group="test",
            name="Test",
            refresh_rate=rate,
            inputs=[]
        )

        assert len(pipeline.inputs) == 0


# ============================================================================
# TEST PIPELINE MODEL (EXTENDS NEWPIPELINE)
# ============================================================================

class TestPipelineModel:
    """Test full Pipeline model with all fields"""

    def test_pipeline_creation_with_all_fields(self, real_input, real_output_ipv4):
        """Test creating Pipeline with all fields"""
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
            name="Test Pipeline",
            refresh_rate=NewPipeline.RefreshRate(minutes=1),
            inputs=[real_input],
            outputs=[real_output_ipv4]
        )

        assert pipeline.id == pipeline_id
        assert pipeline.created_at == now
        assert pipeline.updated_at == now
        assert pipeline.next_refresh == now
        assert pipeline.last_refresh is None
        assert pipeline.status == Status.PENDING
        assert pipeline.group == "test"
        assert pipeline.name == "Test Pipeline"

    def test_pipeline_id_is_uuid(self, real_input, real_output_ipv4):
        """Test that pipeline ID is UUID type"""
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

        assert isinstance(pipeline.id, UUID)

    def test_pipeline_status_enum(self, real_input, real_output_ipv4):
        """Test different status values"""
        now = datetime.now(timezone.utc)

        for status in [Status.PENDING, Status.RUNNING, Status.COMPLETED, Status.FAILED]:
            pipeline = Pipeline(
                id=uuid4(),
                created_at=now,
                updated_at=now,
                next_refresh=now,
                last_refresh=None,
                status=status,
                group="test",
                name="Test",
                refresh_rate=NewPipeline.RefreshRate(minutes=1),
                inputs=[real_input],
                outputs=[real_output_ipv4]
            )

            assert pipeline.status == status

    def test_pipeline_last_refresh_optional(self, real_input, real_output_ipv4):
        """Test that last_refresh is optional"""
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

        assert pipeline.last_refresh is None

    def test_pipeline_last_refresh_with_value(self, real_input, real_output_ipv4):
        """Test setting last_refresh"""
        now = datetime.now(timezone.utc)
        last_run = now - timedelta(hours=1)

        pipeline = Pipeline(
            id=uuid4(),
            created_at=now,
            updated_at=now,
            next_refresh=now,
            last_refresh=last_run,
            status=Status.COMPLETED,
            group="test",
            name="Test",
            refresh_rate=NewPipeline.RefreshRate(minutes=1),
            inputs=[real_input],
            outputs=[real_output_ipv4]
        )

        assert pipeline.last_refresh == last_run

    def test_pipeline_output_urls_computed_field(self, real_input, real_output_ipv4):
        """Test output_urls computed field"""
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

        assert isinstance(urls, list)
        assert len(urls) == 1
        assert urls[0] == f"/edl/{pipeline_id}/ipv4"

    def test_pipeline_output_urls_multiple_outputs(self, real_input, real_output_ipv4, real_output_ipv6, real_output_all):
        """Test output_urls with multiple outputs"""
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
            outputs=[real_output_ipv4, real_output_ipv6, real_output_all]
        )

        urls = pipeline.output_urls

        assert len(urls) == 3
        assert f"/edl/{pipeline_id}/ipv4" in urls
        assert f"/edl/{pipeline_id}/ipv6" in urls
        assert f"/edl/{pipeline_id}/all" in urls

    def test_pipeline_serialization(self, real_input, real_output_ipv4):
        """Test pipeline model serialization"""
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

        data = pipeline.model_dump()

        # Check field presence
        assert "id" in data
        assert "created_at" in data
        assert "updated_at" in data
        assert "next_refresh" in data
        assert "last_refresh" in data
        assert "status" in data
        assert "state" in data
        assert "group" in data
        assert "name" in data
        assert "refresh_rate" in data
        assert "inputs" in data
        assert "modifiers" in data
        assert "outputs" in data
        assert "output_urls" in data

        # Check enum serialization (.value)
        assert data["status"] == "PENDING"
        assert data["state"] == "ENABLED"


# ============================================================================
# TEST PIPELINELIST MODEL
# ============================================================================

class TestPipelineListModel:
    """Test PipelineList model for list responses"""

    def test_pipeline_list_creation(self, real_input, real_output_ipv4):
        """Test creating PipelineList"""
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

        pipeline_list = PipelineList(
            count=1,
            total=1,
            pipelines=[pipeline]
        )

        assert pipeline_list.count == 1
        assert pipeline_list.total == 1
        assert len(pipeline_list.pipelines) == 1

    def test_pipeline_list_defaults(self):
        """Test PipelineList default values"""
        pipeline_list = PipelineList()

        assert pipeline_list.count == 0
        assert pipeline_list.total == 0
        assert pipeline_list.pipelines == []

    def test_pipeline_list_empty(self):
        """Test PipelineList with no pipelines"""
        pipeline_list = PipelineList(
            count=0,
            total=0,
            pipelines=[]
        )

        assert pipeline_list.count == 0
        assert pipeline_list.total == 0
        assert len(pipeline_list.pipelines) == 0

    def test_pipeline_list_multiple_pipelines(self, real_input, real_output_ipv4):
        """Test PipelineList with multiple pipelines"""
        now = datetime.now(timezone.utc)

        pipelines = []
        for i in range(5):
            pipeline = Pipeline(
                id=uuid4(),
                created_at=now,
                updated_at=now,
                next_refresh=now,
                last_refresh=None,
                status=Status.PENDING,
                group=f"group_{i}",
                name=f"Pipeline {i}",
                refresh_rate=NewPipeline.RefreshRate(minutes=1),
                inputs=[real_input],
                outputs=[real_output_ipv4]
            )
            pipelines.append(pipeline)

        pipeline_list = PipelineList(
            count=5,
            total=5,
            pipelines=pipelines
        )

        assert pipeline_list.count == 5
        assert pipeline_list.total == 5
        assert len(pipeline_list.pipelines) == 5

    def test_pipeline_list_count_total_mismatch(self, real_input, real_output_ipv4):
        """Test PipelineList where count != total (pagination scenario)"""
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

        # Showing 1 out of 10 total
        pipeline_list = PipelineList(
            count=1,
            total=10,
            pipelines=[pipeline]
        )

        assert pipeline_list.count == 1
        assert pipeline_list.total == 10
        assert len(pipeline_list.pipelines) == 1
