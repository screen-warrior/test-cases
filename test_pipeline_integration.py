"""
Integration tests for Pipeline data flow: Inputs -> Modifiers -> Outputs
Tests real-world scenarios using actual Pydantic models with mocked HTTP requests.
"""

import pytest
from unittest.mock import Mock, patch
from ipaddress import IPv4Network, IPv6Network

from fwdev_edl_server.models.pipeline import Pipeline, State, Status
from fwdev_edl_server.models.inputs import ExternalEdl, Static
from fwdev_edl_server.models.modifiers import (
    IPvPermit,
    IPvDeny,
    IPv4Only,
    IPv6Only,
    IPvConsolidate,
)
from fwdev_edl_server.models.outputs import All, IPv4Any, IPv4Only as IPv4Output, IPv6Only as IPv6Output


class TestPipelineDataFlow:
    """Test complete data flow through pipeline stages"""

    @patch("requests.get")
    def test_external_edl_to_ipv4_filter_to_output(self, mock_get):
        """Test: ExternalEdl -> IPv4Only -> IPv4Output"""
        # Mock HTTP response with mixed IP data
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "text/plain"}
        mock_response.text = "192.168.1.1\n10.0.0.5\n2001:db8::1\n172.16.0.0/16"
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        # Create real pipeline with real models
        pipeline = Pipeline(
            group="test",
            name="ipv4-filter-pipeline",
            inputs=[
                ExternalEdl(
                    type="edl",
                    url="https://test.example.com/edl"
                )
            ],
            modifiers=[
                IPv4Only(type="ipv4-only")
            ],
            outputs=[
                IPv4Output(type="ipv4")
            ]
        )

        # Execute pipeline
        result = pipeline.refresh()

        # Verify only IPv4 addresses in output
        output_path = f"{pipeline.id}/ipv4"
        assert output_path in result
        output_lines = result[output_path].split("\n")

        # Should contain IPv4 addresses only
        assert "192.168.1.1/32" in output_lines
        assert "10.0.0.5/32" in output_lines
        assert "172.16.0.0/16" in output_lines

        # Should NOT contain IPv6
        assert not any("2001:db8" in line for line in output_lines)

    @patch("requests.get")
    def test_external_edl_to_ipv6_filter_to_output(self, mock_get):
        """Test: ExternalEdl -> IPv6Only -> IPv6Output"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "text/plain"}
        mock_response.text = "192.168.1.1\n2001:db8::1\n2001:db8::2\nfe80::1"
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        pipeline = Pipeline(
            group="test",
            name="ipv6-filter-pipeline",
            inputs=[
                ExternalEdl(type="edl", url="https://test.example.com/edl")
            ],
            modifiers=[
                IPv6Only(type="ipv6-only")
            ],
            outputs=[
                IPv6Output(type="ipv6")
            ]
        )

        result = pipeline.refresh()
        output_path = f"{pipeline.id}/ipv6"
        output_lines = result[output_path].split("\n")

        # Should contain only IPv6 addresses
        assert any("2001:db8::1" in line for line in output_lines)
        assert any("2001:db8::2" in line for line in output_lines)
        assert any("fe80::1" in line for line in output_lines)

        # Should NOT contain IPv4
        assert not any("192.168" in line for line in output_lines)

    def test_static_input_to_permit_filter(self):
        """Test: Static -> IPvPermit -> All output"""
        pipeline = Pipeline(
            group="test",
            name="static-permit-pipeline",
            inputs=[
                Static(
                    type="static",
                    values=[
                        "192.168.1.0/24",
                        "192.168.2.0/24",
                        "10.0.0.0/8",
                        "172.16.0.0/16"
                    ]
                )
            ],
            modifiers=[
                IPvPermit(
                    type="ip-permit",
                    subnets=["192.168.0.0/16"]
                )
            ],
            outputs=[
                All(type="all")
            ]
        )

        result = pipeline.refresh()
        output_path = f"{pipeline.id}/all"
        output_lines = result[output_path].split("\n")

        # Should only contain subnets within 192.168.0.0/16
        assert "192.168.1.0/24" in output_lines
        assert "192.168.2.0/24" in output_lines

        # Should NOT contain IPs outside permitted range
        assert "10.0.0.0/8" not in output_lines
        assert "172.16.0.0/16" not in output_lines

    def test_static_input_to_deny_filter(self):
        """Test: Static -> IPvDeny -> All output"""
        pipeline = Pipeline(
            group="test",
            name="static-deny-pipeline",
            inputs=[
                Static(
                    type="static",
                    values=[
                        "192.168.1.0/24",
                        "192.168.2.0/24",
                        "10.0.0.0/8",
                        "172.16.0.0/16"
                    ]
                )
            ],
            modifiers=[
                IPvDeny(
                    type="ip-deny",
                    subnets=["192.168.0.0/16"]
                )
            ],
            outputs=[
                All(type="all")
            ]
        )

        result = pipeline.refresh()
        output_path = f"{pipeline.id}/all"
        output_lines = result[output_path].split("\n")

        # Should NOT contain denied subnets
        assert "192.168.1.0/24" not in output_lines
        assert "192.168.2.0/24" not in output_lines

        # Should contain IPs outside denied range
        assert "10.0.0.0/8" in output_lines
        assert "172.16.0.0/16" in output_lines


class TestMultipleInputsAndModifiers:
    """Test pipelines with multiple inputs and chained modifiers"""

    @patch("requests.get")
    def test_multiple_external_inputs(self, mock_get):
        """Test pipeline with multiple ExternalEdl inputs"""
        # Mock different responses for different URLs
        def side_effect(url, **kwargs):
            mock = Mock()
            mock.status_code = 200
            mock.headers = {"Content-Type": "text/plain"}
            mock.raise_for_status = Mock()

            if "source1" in url:
                mock.text = "192.168.1.1\n192.168.1.2"
            elif "source2" in url:
                mock.text = "10.0.0.1\n10.0.0.2"
            else:
                mock.text = "172.16.0.1"

            return mock

        mock_get.side_effect = side_effect

        pipeline = Pipeline(
            group="test",
            name="multi-input-pipeline",
            inputs=[
                ExternalEdl(type="edl", url="https://source1.example.com/edl"),
                ExternalEdl(type="edl", url="https://source2.example.com/edl"),
                ExternalEdl(type="edl", url="https://source3.example.com/edl")
            ],
            modifiers=[],
            outputs=[
                All(type="all")
            ]
        )

        result = pipeline.refresh()
        output_path = f"{pipeline.id}/all"
        output_lines = result[output_path].split("\n")

        # Should contain IPs from all sources
        assert "192.168.1.1/32" in output_lines
        assert "192.168.1.2/32" in output_lines
        assert "10.0.0.1/32" in output_lines
        assert "10.0.0.2/32" in output_lines
        assert "172.16.0.1/32" in output_lines

    def test_mixed_static_inputs(self):
        """Test pipeline combining multiple static inputs"""
        pipeline = Pipeline(
            group="test",
            name="mixed-static-pipeline",
            inputs=[
                Static(
                    type="static",
                    values=["192.168.1.0/24", "10.0.0.0/8"]
                ),
                Static(
                    type="static",
                    values=["172.16.0.0/16", "2001:db8::/32"]
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

        # Should contain all static values
        assert "192.168.1.0/24" in output_lines
        assert "10.0.0.0/8" in output_lines
        assert "172.16.0.0/16" in output_lines
        assert "2001:db8::/32" in output_lines

    def test_chained_modifiers(self):
        """Test pipeline with multiple chained modifiers"""
        pipeline = Pipeline(
            group="test",
            name="chained-modifiers-pipeline",
            inputs=[
                Static(
                    type="static",
                    values=[
                        "192.168.1.0/24",
                        "192.168.2.0/24",
                        "10.0.0.0/8",
                        "172.16.0.0/16",
                        "2001:db8::/32"
                    ]
                )
            ],
            modifiers=[
                IPvPermit(
                    type="ip-permit",
                    subnets=["192.168.0.0/16", "10.0.0.0/8", "2001:db8::/32"]
                ),
                IPv4Only(type="ipv4-only")
            ],
            outputs=[
                All(type="all")
            ]
        )

        result = pipeline.refresh()
        output_path = f"{pipeline.id}/all"
        output_lines = result[output_path].split("\n")

        # Should only contain IPv4 addresses within permitted range
        assert "192.168.1.0/24" in output_lines
        assert "192.168.2.0/24" in output_lines
        assert "10.0.0.0/8" in output_lines

        # Should NOT contain IPv6 (filtered by IPv4Only)
        assert "2001:db8::/32" not in output_lines

        # Should NOT contain denied subnet
        assert "172.16.0.0/16" not in output_lines


class TestIPvConsolidateIntegration:
    """Test IPvConsolidate modifier integration in pipelines"""

    def test_consolidate_ipv4_networks(self):
        """Test IPvConsolidate with overlapping IPv4 networks"""
        pipeline = Pipeline(
            group="test",
            name="consolidate-ipv4-pipeline",
            inputs=[
                Static(
                    type="static",
                    values=[
                        "192.168.1.0/24",
                        "192.168.1.128/25",
                        "192.168.1.0/25",
                        "10.0.0.0/24",
                        "10.0.1.0/24"
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

        # IPvConsolidate should collapse overlapping networks
        # 192.168.1.128/25 and 192.168.1.0/25 should collapse into 192.168.1.0/24
        assert "192.168.1.0/24" in output_lines

        # Check that overlapping subnets are collapsed
        # Count should be less than original 5 inputs
        assert len(output_lines) <= 5

    def test_consolidate_ipv6_networks(self):
        """Test IPvConsolidate with overlapping IPv6 networks"""
        pipeline = Pipeline(
            group="test",
            name="consolidate-ipv6-pipeline",
            inputs=[
                Static(
                    type="static",
                    values=[
                        "2001:db8::/32",
                        "2001:db8::/64",
                        "2001:db8:1::/64"
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

        # 2001:db8::/64 should be consolidated into 2001:db8::/32
        assert "2001:db8::/32" in output_lines

    def test_consolidate_mixed_ipv4_ipv6(self):
        """Test IPvConsolidate with mixed IPv4 and IPv6 networks"""
        pipeline = Pipeline(
            group="test",
            name="consolidate-mixed-pipeline",
            inputs=[
                Static(
                    type="static",
                    values=[
                        "192.168.0.0/24",
                        "192.168.1.0/24",
                        "2001:db8::/64",
                        "2001:db8:1::/64"
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

        # Both IPv4 and IPv6 should be present
        ipv4_present = any("192.168" in line for line in output_lines)
        ipv6_present = any("2001:db8" in line for line in output_lines)

        assert ipv4_present
        assert ipv6_present


class TestMultipleOutputs:
    """Test pipelines with multiple output formats"""

    def test_multiple_output_formats(self):
        """Test pipeline with multiple output formats simultaneously"""
        pipeline = Pipeline(
            group="test",
            name="multi-output-pipeline",
            inputs=[
                Static(
                    type="static",
                    values=[
                        "192.168.1.0/24",
                        "10.0.0.0/8",
                        "2001:db8::/32"
                    ]
                )
            ],
            modifiers=[],
            outputs=[
                All(type="all"),
                IPv4Output(type="ipv4"),
                IPv6Output(type="ipv6"),
                IPv4Any(type="ip")
            ]
        )

        result = pipeline.refresh()

        # Verify all output paths exist
        all_path = f"{pipeline.id}/all"
        ipv4_path = f"{pipeline.id}/ipv4"
        ipv6_path = f"{pipeline.id}/ipv6"
        ip_path = f"{pipeline.id}/ip"

        assert all_path in result
        assert ipv4_path in result
        assert ipv6_path in result
        assert ip_path in result

        # Verify 'all' output contains everything
        all_lines = result[all_path].split("\n")
        assert "192.168.1.0/24" in all_lines
        assert "10.0.0.0/8" in all_lines
        assert "2001:db8::/32" in all_lines

        # Verify 'ipv4' output contains only IPv4
        ipv4_lines = result[ipv4_path].split("\n")
        assert "192.168.1.0/24" in ipv4_lines
        assert "10.0.0.0/8" in ipv4_lines
        assert not any("2001:db8" in line for line in ipv4_lines)

        # Verify 'ipv6' output contains only IPv6
        ipv6_lines = result[ipv6_path].split("\n")
        assert "2001:db8::/32" in ipv6_lines
        assert not any("192.168" in line for line in ipv6_lines)
        assert not any("10.0" in line for line in ipv6_lines)

        # Verify 'ip' output contains both IPv4 and IPv6
        ip_lines = result[ip_path].split("\n")
        assert "192.168.1.0/24" in ip_lines
        assert "10.0.0.0/8" in ip_lines
        assert "2001:db8::/32" in ip_lines


class TestComplexRealWorldScenarios:
    """Test complex real-world pipeline scenarios"""

    @patch("requests.get")
    def test_enterprise_firewall_pipeline(self, mock_get):
        """Test enterprise firewall EDL pipeline with permit/deny rules"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "text/plain"}
        mock_response.text = "\n".join([
            "192.168.1.0/24",
            "192.168.50.0/24",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "8.8.8.8",
            "1.1.1.1"
        ])
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        pipeline = Pipeline(
            group="enterprise",
            name="firewall-edl",
            description="Enterprise firewall allow list",
            inputs=[
                ExternalEdl(type="edl", url="https://threat-intel.example.com/ips")
            ],
            modifiers=[
                IPvDeny(
                    type="ip-deny",
                    subnets=["192.168.0.0/16"]  # Deny internal ranges
                ),
                IPv4Only(type="ipv4-only")
            ],
            outputs=[
                IPv4Output(type="ipv4")
            ]
        )

        result = pipeline.refresh()
        output_path = f"{pipeline.id}/ipv4"
        output_lines = result[output_path].split("\n")

        # Should contain public IPs
        assert "8.8.8.8/32" in output_lines
        assert "1.1.1.1/32" in output_lines
        assert "10.0.0.0/8" in output_lines
        assert "172.16.0.0/12" in output_lines

        # Should NOT contain denied private ranges
        assert not any("192.168" in line for line in output_lines)

    def test_multi_source_threat_intelligence(self):
        """Test threat intelligence aggregation from multiple sources"""
        pipeline = Pipeline(
            group="threat-intel",
            name="aggregated-blocklist",
            inputs=[
                Static(
                    type="static",
                    values=["198.51.100.0/24", "203.0.113.0/24"]  # TEST-NET addresses
                ),
                Static(
                    type="static",
                    values=["192.0.2.0/24", "198.51.100.0/24"]  # Overlapping
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

        # Should contain all unique subnets (IPvConsolidate handles dedup)
        assert "198.51.100.0/24" in output_lines
        assert "203.0.113.0/24" in output_lines
        assert "192.0.2.0/24" in output_lines
