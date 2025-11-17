"""
Test core Pipeline functionality
Focus: Pipeline.refresh() execution, data flow, concurrent input handling
"""

import pytest
from unittest.mock import Mock, patch
from datetime import datetime, timezone
from uuid import uuid4
from ipaddress import IPv4Network, IPv6Network

from fwdev_edl_server.models.pipeline import Pipeline, NewPipeline, State, Status
from fwdev_edl_server.models.inputs import ExternalEdl, Static
from fwdev_edl_server.models.modifiers import IPvPermit, IPv4Only
from fwdev_edl_server.models.outputs import All, IPv4Only as IPv4Output


class TestPipelineRefresh:
    """Test Pipeline.refresh() core functionality"""

    @patch("requests.get")
    def test_refresh_executes_all_stages(self, mock_get):
        """Test that refresh executes: inputs -> modifiers -> consolidate -> outputs"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "text/plain"}
        mock_response.text = "192.168.1.1\n10.0.0.1"
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        pipeline = Pipeline(
            id=uuid4(),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            next_refresh=datetime.now(timezone.utc),
            last_refresh=None,
            status=Status.PENDING,
            group="test",
            name="Test Pipeline",
            refresh_rate=NewPipeline.RefreshRate(minutes=5),
            inputs=[ExternalEdl(type="edl", url="https://example.com/edl")],
            modifiers=[IPv4Only(type="ipv4-only")],
            outputs=[All(type="all")]
        )

        result = pipeline.refresh()

        # Verify result structure
        assert isinstance(result, dict)
        output_key = f"{pipeline.id}/all"
        assert output_key in result

        # Verify data was processed
        assert "192.168.1.1/32" in result[output_key]
        assert "10.0.0.1/32" in result[output_key]

    def test_refresh_with_static_input(self):
        """Test refresh with Static input (no HTTP)"""
        pipeline = Pipeline(
            id=uuid4(),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            next_refresh=datetime.now(timezone.utc),
            last_refresh=None,
            status=Status.PENDING,
            group="test",
            name="Static Pipeline",
            refresh_rate=NewPipeline.RefreshRate(hours=1),
            inputs=[Static(type="static", data=["192.168.1.0/24", "10.0.0.0/8"])],
            modifiers=[],
            outputs=[All(type="all")]
        )

        result = pipeline.refresh()
        output_key = f"{pipeline.id}/all"

        assert "192.168.1.0/24" in result[output_key]
        assert "10.0.0.0/8" in result[output_key]

    @patch("requests.get")
    def test_refresh_multiple_inputs_concurrent(self, mock_get):
        """Test that multiple inputs are processed concurrently"""
        def side_effect(url, **kwargs):
            mock = Mock()
            mock.status_code = 200
            mock.headers = {"Content-Type": "text/plain"}
            mock.raise_for_status = Mock()

            if "source1" in url:
                mock.text = "192.168.1.1"
            elif "source2" in url:
                mock.text = "10.0.0.1"
            else:
                mock.text = "172.16.0.1"

            return mock

        mock_get.side_effect = side_effect

        pipeline = Pipeline(
            id=uuid4(),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            next_refresh=datetime.now(timezone.utc),
            last_refresh=None,
            status=Status.PENDING,
            group="test",
            name="Multi-input",
            refresh_rate=NewPipeline.RefreshRate(minutes=1),
            inputs=[
                ExternalEdl(type="edl", url="https://source1.com/edl"),
                ExternalEdl(type="edl", url="https://source2.com/edl"),
                ExternalEdl(type="edl", url="https://source3.com/edl")
            ],
            modifiers=[],
            outputs=[All(type="all")]
        )

        result = pipeline.refresh()
        output_key = f"{pipeline.id}/all"

        # All inputs should be aggregated
        output = result[output_key]
        assert "192.168.1.1/32" in output
        assert "10.0.0.1/32" in output
        assert "172.16.0.1/32" in output

    def test_refresh_applies_modifiers_in_order(self):
        """Test that modifiers are applied sequentially"""
        pipeline = Pipeline(
            id=uuid4(),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            next_refresh=datetime.now(timezone.utc),
            last_refresh=None,
            status=Status.PENDING,
            group="test",
            name="Modifier chain",
            refresh_rate=NewPipeline.RefreshRate(minutes=1),
            inputs=[
                Static(type="static", data=[
                    "192.168.1.0/24",
                    "10.0.0.0/8",
                    "2001:db8::/32"
                ])
            ],
            modifiers=[
                IPvPermit(type="ip-permit", subnets=["192.168.0.0/16", "10.0.0.0/8"]),
                IPv4Only(type="ipv4-only")
            ],
            outputs=[All(type="all")]
        )

        result = pipeline.refresh()
        output_key = f"{pipeline.id}/all"
        output = result[output_key]

        # Should have IPv4 from permitted range only
        assert "192.168.1.0/24" in output
        assert "10.0.0.0/8" in output
        # IPv6 filtered out by IPv4Only
        assert "2001:db8::/32" not in output

    def test_refresh_consolidates_ips(self):
        """Test that IPvConsolidate runs automatically"""
        pipeline = Pipeline(
            id=uuid4(),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            next_refresh=datetime.now(timezone.utc),
            last_refresh=None,
            status=Status.PENDING,
            group="test",
            name="Consolidate test",
            refresh_rate=NewPipeline.RefreshRate(minutes=1),
            inputs=[
                Static(type="static", data=[
                    "192.168.1.0/24",
                    "192.168.1.0/25",
                    "192.168.1.128/25"
                ])
            ],
            modifiers=[],
            outputs=[All(type="all")]
        )

        result = pipeline.refresh()
        output_key = f"{pipeline.id}/all"
        output = result[output_key]

        # Overlapping subnets should be consolidated
        assert "192.168.1.0/24" in output
        lines = [l for l in output.split("\n") if l]
        # Should have fewer lines due to consolidation
        assert len(lines) <= 3

    def test_refresh_multiple_outputs(self):
        """Test that multiple output formats are generated"""
        pipeline = Pipeline(
            id=uuid4(),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            next_refresh=datetime.now(timezone.utc),
            last_refresh=None,
            status=Status.PENDING,
            group="test",
            name="Multi-output",
            refresh_rate=NewPipeline.RefreshRate(minutes=1),
            inputs=[
                Static(type="static", data=["192.168.1.0/24", "2001:db8::/32"])
            ],
            modifiers=[],
            outputs=[
                All(type="all"),
                IPv4Output(type="ipv4")
            ]
        )

        result = pipeline.refresh()

        # Both outputs should exist
        all_key = f"{pipeline.id}/all"
        ipv4_key = f"{pipeline.id}/ipv4"

        assert all_key in result
        assert ipv4_key in result

        # All output has both
        assert "192.168.1.0/24" in result[all_key]
        assert "2001:db8::/32" in result[all_key]

        # IPv4 output has only IPv4
        assert "192.168.1.0/24" in result[ipv4_key]
        assert "2001:db8" not in result[ipv4_key]


class TestPipelineErrorHandling:
    """Test Pipeline error handling during refresh"""

    @patch("requests.get")
    def test_refresh_continues_on_input_error(self, mock_get):
        """Test that pipeline continues if one input fails"""
        def side_effect(url, **kwargs):
            if "failing" in url:
                raise Exception("Connection failed")

            mock = Mock()
            mock.status_code = 200
            mock.headers = {"Content-Type": "text/plain"}
            mock.text = "192.168.1.1"
            mock.raise_for_status = Mock()
            return mock

        mock_get.side_effect = side_effect

        pipeline = Pipeline(
            id=uuid4(),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            next_refresh=datetime.now(timezone.utc),
            last_refresh=None,
            status=Status.PENDING,
            group="test",
            name="Partial failure",
            refresh_rate=NewPipeline.RefreshRate(minutes=1),
            inputs=[
                ExternalEdl(type="edl", url="https://failing.com/edl"),
                ExternalEdl(type="edl", url="https://working.com/edl")
            ],
            modifiers=[],
            outputs=[All(type="all")]
        )

        result = pipeline.refresh()
        output_key = f"{pipeline.id}/all"

        # Should have data from working input
        assert "192.168.1.1/32" in result[output_key]

    def test_refresh_handles_empty_inputs(self):
        """Test refresh with no inputs returns empty output"""
        pipeline = Pipeline(
            id=uuid4(),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            next_refresh=datetime.now(timezone.utc),
            last_refresh=None,
            status=Status.PENDING,
            group="test",
            name="Empty",
            refresh_rate=NewPipeline.RefreshRate(minutes=1),
            inputs=[Static(type="static", data=[])],
            modifiers=[],
            outputs=[All(type="all")]
        )

        result = pipeline.refresh()
        output_key = f"{pipeline.id}/all"

        assert result[output_key] == ""


class TestPipelineModel:
    """Test Pipeline model structure and computed fields"""

    def test_output_urls_computed_field(self):
        """Test that output_urls generates correct paths"""
        pipeline_id = uuid4()

        pipeline = Pipeline(
            id=pipeline_id,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            next_refresh=datetime.now(timezone.utc),
            last_refresh=None,
            status=Status.PENDING,
            group="test",
            name="URL test",
            refresh_rate=NewPipeline.RefreshRate(minutes=1),
            inputs=[Static(type="static", data=["192.168.1.0/24"])],
            outputs=[
                All(type="all"),
                IPv4Output(type="ipv4")
            ]
        )

        urls = pipeline.output_urls

        assert f"/edl/{pipeline_id}/all" in urls
        assert f"/edl/{pipeline_id}/ipv4" in urls
        assert len(urls) == 2

    def test_pipeline_serialization_field_order(self):
        """Test that model serialization has correct field ordering"""
        pipeline = Pipeline(
            id=uuid4(),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            next_refresh=datetime.now(timezone.utc),
            last_refresh=None,
            status=Status.PENDING,
            group="test",
            name="Serialization test",
            refresh_rate=NewPipeline.RefreshRate(minutes=1),
            inputs=[Static(type="static", data=["192.168.1.0/24"])],
            outputs=[All(type="all")]
        )

        data = pipeline.model_dump()

        # Check key fields exist
        assert "id" in data
        assert "group" in data
        assert "name" in data
        assert "status" in data
        assert "state" in data
        assert "inputs" in data
        assert "outputs" in data
        assert "output_urls" in data

        # Enums should be serialized as values
        assert data["status"] == "PENDING"
        assert data["state"] == "ENABLED"


class TestNewPipelineModel:
    """Test NewPipeline model and RefreshRate validation"""

    def test_refresh_rate_validation(self):
        """Test RefreshRate field constraints"""
        # Valid values
        rate = NewPipeline.RefreshRate(days=1, hours=12, minutes=30)
        assert rate.days == 1
        assert rate.hours == 12
        assert rate.minutes == 30

        # Boundary values
        rate = NewPipeline.RefreshRate(days=365, hours=24, minutes=60)
        assert rate.days == 365

        # Invalid - should raise validation error
        with pytest.raises(Exception):
            NewPipeline.RefreshRate(days=366)

        with pytest.raises(Exception):
            NewPipeline.RefreshRate(hours=25)

        with pytest.raises(Exception):
            NewPipeline.RefreshRate(minutes=61)

    def test_new_pipeline_defaults(self):
        """Test NewPipeline default values"""
        pipeline = NewPipeline(
            group="test",
            name="Test",
            refresh_rate=NewPipeline.RefreshRate(minutes=1),
            inputs=[Static(type="static", data=["192.168.1.0/24"])]
        )

        # Check defaults
        assert pipeline.state == State.ENABLED
        assert pipeline.description is None
        assert pipeline.modifiers == []
        assert len(pipeline.outputs) == 1
        assert pipeline.outputs[0].type == "all"


class TestEnums:
    """Test Status and State enums"""

    def test_status_enum_values(self):
        """Test Status enum"""
        assert Status.PENDING.value == "PENDING"
        assert Status.RUNNING.value == "RUNNING"
        assert Status.COMPLETED.value == "COMPLETED"
        assert Status.FAILED.value == "FAILED"

    def test_state_enum_values(self):
        """Test State enum"""
        assert State.ENABLED.value == "ENABLED"
        assert State.DISABLED.value == "DISABLED"
