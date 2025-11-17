"""
Error handling tests for Pipeline components
Tests exception handling, invalid data, and edge cases using real Pydantic models.
"""

import pytest
from unittest.mock import Mock, patch
from ipaddress import IPv4Network
import requests

from fwdev_edl_server.models.pipeline import Pipeline
from fwdev_edl_server.models.inputs import ExternalEdl, Static
from fwdev_edl_server.models.modifiers import IPvPermit, IPvDeny, IPv4Only
from fwdev_edl_server.models.outputs import All, IPv4Only as IPv4Output


class TestInputErrorHandling:
    """Test error handling in input components"""

    @patch("requests.get")
    def test_external_edl_http_error(self, mock_get):
        """Test ExternalEdl handles HTTP errors gracefully"""
        # Mock HTTP 500 error
        mock_get.side_effect = requests.exceptions.HTTPError("500 Server Error")

        pipeline = Pipeline(
            group="test",
            name="http-error-pipeline",
            inputs=[
                ExternalEdl(type="edl", url="https://failing.example.com/edl"),
                Static(type="static", values=["192.168.1.0/24"])  # Fallback data
            ],
            modifiers=[],
            outputs=[
                All(type="all")
            ]
        )

        # Pipeline should continue with other inputs despite error
        result = pipeline.refresh()
        output_path = f"{pipeline.id}/all"

        # Should contain data from Static input even though ExternalEdl failed
        assert output_path in result
        assert "192.168.1.0/24" in result[output_path]

    @patch("requests.get")
    def test_external_edl_connection_timeout(self, mock_get):
        """Test ExternalEdl handles connection timeouts"""
        mock_get.side_effect = requests.exceptions.Timeout("Connection timeout")

        pipeline = Pipeline(
            group="test",
            name="timeout-pipeline",
            inputs=[
                ExternalEdl(type="edl", url="https://slow.example.com/edl")
            ],
            modifiers=[],
            outputs=[
                All(type="all")
            ]
        )

        # Should not crash, should return empty or handle gracefully
        result = pipeline.refresh()
        assert result is not None

    @patch("requests.get")
    def test_external_edl_invalid_content_type(self, mock_get):
        """Test ExternalEdl rejects non-text/plain content"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "application/json"}
        mock_response.text = '{"ips": ["192.168.1.1"]}'
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        pipeline = Pipeline(
            group="test",
            name="invalid-content-type-pipeline",
            inputs=[
                ExternalEdl(type="edl", url="https://json.example.com/edl")
            ],
            modifiers=[],
            outputs=[
                All(type="all")
            ]
        )

        result = pipeline.refresh()
        output_path = f"{pipeline.id}/all"

        # Should return empty when content-type is wrong
        assert result[output_path] == ""

    @patch("requests.get")
    def test_external_edl_malformed_data(self, mock_get):
        """Test ExternalEdl handles malformed IP data"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "text/plain"}
        mock_response.text = "\n".join([
            "192.168.1.1",           # Valid
            "invalid-ip",            # Invalid
            "999.999.999.999",       # Invalid
            "10.0.0.1",              # Valid
            "not-an-ip-at-all",      # Invalid
            "2001:db8::1"            # Valid
        ])
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        pipeline = Pipeline(
            group="test",
            name="malformed-data-pipeline",
            inputs=[
                ExternalEdl(type="edl", url="https://mixed.example.com/edl")
            ],
            modifiers=[],
            outputs=[
                All(type="all")
            ]
        )

        result = pipeline.refresh()
        output_path = f"{pipeline.id}/all"
        output_lines = result[output_path].split("\n")

        # Should only contain valid IPs, skipping invalid ones
        assert "192.168.1.1/32" in output_lines
        assert "10.0.0.1/32" in output_lines
        assert "2001:db8::1/128" in output_lines

        # Should NOT contain invalid data
        assert "invalid-ip" not in output_lines
        assert "999.999.999.999" not in output_lines
        assert "not-an-ip-at-all" not in output_lines

    def test_static_input_with_invalid_values(self):
        """Test Static input filters out invalid values"""
        pipeline = Pipeline(
            group="test",
            name="static-invalid-pipeline",
            inputs=[
                Static(
                    type="static",
                    values=[
                        "192.168.1.0/24",     # Valid
                        "invalid",            # Invalid
                        "10.0.0.0/8",         # Valid
                        "not-a-network",      # Invalid
                        ""                    # Empty
                    ]
                )
            ],
            modifiers=[],
            outputs=[
                All(type="all")
            ]
        )

        result = pipeline.refresh()
        output_path = f"{pipeline.id}/all"
        output_lines = result[output_path].split("\n")

        # Should only contain valid networks
        assert "192.168.1.0/24" in output_lines
        assert "10.0.0.0/8" in output_lines

        # Should NOT contain invalid entries
        assert "invalid" not in output_lines
        assert "not-a-network" not in output_lines

    def test_static_input_empty_values_list(self):
        """Test Static input with empty values list"""
        pipeline = Pipeline(
            group="test",
            name="empty-static-pipeline",
            inputs=[
                Static(type="static", values=[])
            ],
            modifiers=[],
            outputs=[
                All(type="all")
            ]
        )

        result = pipeline.refresh()
        output_path = f"{pipeline.id}/all"

        # Should return empty output gracefully
        assert result[output_path] == ""


class TestModifierErrorHandling:
    """Test error handling in modifier components"""

    def test_ipv_permit_with_empty_values(self):
        """Test IPvPermit handles empty values list"""
        pipeline = Pipeline(
            group="test",
            name="permit-empty-pipeline",
            inputs=[
                Static(type="static", values=[])
            ],
            modifiers=[
                IPvPermit(type="ip-permit", subnets=["192.168.0.0/16"])
            ],
            outputs=[
                All(type="all")
            ]
        )

        result = pipeline.refresh()
        output_path = f"{pipeline.id}/all"

        # Should handle empty input gracefully
        assert result[output_path] == ""

    def test_ipv_deny_with_empty_values(self):
        """Test IPvDeny handles empty values list"""
        pipeline = Pipeline(
            group="test",
            name="deny-empty-pipeline",
            inputs=[
                Static(type="static", values=[])
            ],
            modifiers=[
                IPvDeny(type="ip-deny", subnets=["192.168.0.0/16"])
            ],
            outputs=[
                All(type="all")
            ]
        )

        result = pipeline.refresh()
        output_path = f"{pipeline.id}/all"

        assert result[output_path] == ""

    def test_modifier_with_mixed_invalid_data(self):
        """Test modifiers handle mixed valid/invalid data"""
        pipeline = Pipeline(
            group="test",
            name="mixed-invalid-pipeline",
            inputs=[
                Static(
                    type="static",
                    values=[
                        "192.168.1.0/24",
                        "invalid-data",
                        "10.0.0.0/8"
                    ]
                )
            ],
            modifiers=[
                IPv4Only(type="ipv4-only")
            ],
            outputs=[
                All(type="all")
            ]
        )

        result = pipeline.refresh()
        output_path = f"{pipeline.id}/all"
        output_lines = result[output_path].split("\n")

        # Should process valid data and skip invalid
        assert "192.168.1.0/24" in output_lines
        assert "10.0.0.0/8" in output_lines

    def test_ipv_permit_no_matches(self):
        """Test IPvPermit when no values match permitted subnets"""
        pipeline = Pipeline(
            group="test",
            name="permit-no-match-pipeline",
            inputs=[
                Static(
                    type="static",
                    values=[
                        "10.0.0.0/8",
                        "172.16.0.0/16"
                    ]
                )
            ],
            modifiers=[
                IPvPermit(
                    type="ip-permit",
                    subnets=["192.168.0.0/16"]  # Permits only 192.168.x.x
                )
            ],
            outputs=[
                All(type="all")
            ]
        )

        result = pipeline.refresh()
        output_path = f"{pipeline.id}/all"

        # Should return empty when nothing matches
        assert result[output_path] == ""

    def test_ipv_deny_all_denied(self):
        """Test IPvDeny when all values are denied"""
        pipeline = Pipeline(
            group="test",
            name="deny-all-pipeline",
            inputs=[
                Static(
                    type="static",
                    values=[
                        "192.168.1.0/24",
                        "192.168.2.0/24"
                    ]
                )
            ],
            modifiers=[
                IPvDeny(
                    type="ip-deny",
                    subnets=["192.168.0.0/16"]  # Denies all 192.168.x.x
                )
            ],
            outputs=[
                All(type="all")
            ]
        )

        result = pipeline.refresh()
        output_path = f"{pipeline.id}/all"

        # Should return empty when everything is denied
        assert result[output_path] == ""


class TestOutputErrorHandling:
    """Test error handling in output components"""

    def test_output_with_empty_values(self):
        """Test outputs handle empty values gracefully"""
        pipeline = Pipeline(
            group="test",
            name="output-empty-pipeline",
            inputs=[
                Static(type="static", values=[])
            ],
            modifiers=[],
            outputs=[
                All(type="all"),
                IPv4Output(type="ipv4")
            ]
        )

        result = pipeline.refresh()

        all_path = f"{pipeline.id}/all"
        ipv4_path = f"{pipeline.id}/ipv4"

        # Should return empty strings without crashing
        assert result[all_path] == ""
        assert result[ipv4_path] == ""

    def test_output_with_no_matching_type(self):
        """Test IPv4Output when no IPv4 addresses exist"""
        pipeline = Pipeline(
            group="test",
            name="output-no-ipv4-pipeline",
            inputs=[
                Static(
                    type="static",
                    values=["2001:db8::/32", "fe80::/10"]  # Only IPv6
                )
            ],
            modifiers=[],
            outputs=[
                IPv4Output(type="ipv4")  # Requesting IPv4 output
            ]
        )

        result = pipeline.refresh()
        output_path = f"{pipeline.id}/ipv4"

        # Should return empty when no matching type
        assert result[output_path] == ""


class TestPipelineRefreshErrorHandling:
    """Test error handling in Pipeline.refresh() method"""

    @patch("requests.get")
    def test_pipeline_partial_input_failure(self, mock_get):
        """Test pipeline continues when some inputs fail"""
        def side_effect(url, **kwargs):
            if "failing" in url:
                raise requests.exceptions.HTTPError("500 Error")
            else:
                mock = Mock()
                mock.status_code = 200
                mock.headers = {"Content-Type": "text/plain"}
                mock.text = "192.168.1.1\n10.0.0.1"
                mock.raise_for_status = Mock()
                return mock

        mock_get.side_effect = side_effect

        pipeline = Pipeline(
            group="test",
            name="partial-failure-pipeline",
            inputs=[
                ExternalEdl(type="edl", url="https://failing.example.com/edl"),
                ExternalEdl(type="edl", url="https://working.example.com/edl")
            ],
            modifiers=[],
            outputs=[
                All(type="all")
            ]
        )

        result = pipeline.refresh()
        output_path = f"{pipeline.id}/all"

        # Should contain data from working input
        assert "192.168.1.1/32" in result[output_path]
        assert "10.0.0.1/32" in result[output_path]

    @patch("requests.get")
    def test_pipeline_all_inputs_fail(self, mock_get):
        """Test pipeline when all inputs fail"""
        mock_get.side_effect = requests.exceptions.HTTPError("500 Error")

        pipeline = Pipeline(
            group="test",
            name="all-fail-pipeline",
            inputs=[
                ExternalEdl(type="edl", url="https://fail1.example.com/edl"),
                ExternalEdl(type="edl", url="https://fail2.example.com/edl")
            ],
            modifiers=[],
            outputs=[
                All(type="all")
            ]
        )

        result = pipeline.refresh()
        output_path = f"{pipeline.id}/all"

        # Should return empty output without crashing
        assert result[output_path] == ""

    def test_pipeline_no_inputs(self):
        """Test pipeline with no inputs defined"""
        pipeline = Pipeline(
            group="test",
            name="no-inputs-pipeline",
            inputs=[],
            modifiers=[],
            outputs=[
                All(type="all")
            ]
        )

        result = pipeline.refresh()
        output_path = f"{pipeline.id}/all"

        # Should handle gracefully
        assert result[output_path] == ""

    def test_pipeline_no_outputs(self):
        """Test pipeline with no outputs defined"""
        pipeline = Pipeline(
            group="test",
            name="no-outputs-pipeline",
            inputs=[
                Static(type="static", values=["192.168.1.0/24"])
            ],
            modifiers=[],
            outputs=[]
        )

        result = pipeline.refresh()

        # Should return empty dict
        assert result == {}


class TestEdgeCases:
    """Test edge cases and boundary conditions"""

    def test_pipeline_with_duplicate_networks(self):
        """Test pipeline handles duplicate networks correctly"""
        pipeline = Pipeline(
            group="test",
            name="duplicate-pipeline",
            inputs=[
                Static(
                    type="static",
                    values=[
                        "192.168.1.0/24",
                        "192.168.1.0/24",
                        "192.168.1.0/24"
                    ]
                )
            ],
            modifiers=[],
            outputs=[
                All(type="all")
            ]
        )

        result = pipeline.refresh()
        output_path = f"{pipeline.id}/all"
        output_lines = [line for line in result[output_path].split("\n") if line]

        # IPvConsolidate should deduplicate
        assert output_lines.count("192.168.1.0/24") == 1

    @patch("requests.get")
    def test_pipeline_with_very_large_dataset(self, mock_get):
        """Test pipeline handles large datasets"""
        # Generate 1000 IP addresses
        large_dataset = "\n".join([f"10.0.{i//256}.{i%256}" for i in range(1000)])

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "text/plain"}
        mock_response.text = large_dataset
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        pipeline = Pipeline(
            group="test",
            name="large-dataset-pipeline",
            inputs=[
                ExternalEdl(type="edl", url="https://large.example.com/edl")
            ],
            modifiers=[],
            outputs=[
                All(type="all")
            ]
        )

        result = pipeline.refresh()
        output_path = f"{pipeline.id}/all"
        output_lines = result[output_path].split("\n")

        # Should process all entries
        assert len(output_lines) == 1000

    def test_pipeline_with_cidr_notation_edge_cases(self):
        """Test pipeline with edge case CIDR notations"""
        pipeline = Pipeline(
            group="test",
            name="cidr-edge-pipeline",
            inputs=[
                Static(
                    type="static",
                    values=[
                        "0.0.0.0/0",          # Entire IPv4 space
                        "255.255.255.255/32", # Single host max
                        "127.0.0.1/32",       # Localhost
                        "::/0",               # Entire IPv6 space
                        "::1/128"             # IPv6 localhost
                    ]
                )
            ],
            modifiers=[],
            outputs=[
                All(type="all")
            ]
        )

        result = pipeline.refresh()
        output_path = f"{pipeline.id}/all"

        # Should handle all edge cases without error
        assert result[output_path] is not None
        assert len(result[output_path]) > 0
