"""
Copyright (c) 2025, Oracle and/or its affiliates.
Licensed under the Universal Permissive License v1.0 as shown at
https://oss.oracle.com/licenses/upl.
"""

import pytest
from fastmcp import Client

from oracle.oci_recovery_mcp_server.server import (
    CLOUD_PROTECT_ONBOARDING_PROMPT,
    OCI_RECOVERY_SERVICE_DASHBOARD_PROMPT,
    OUT_OF_PLACE_RESTORE_OF_DATABASE_PROMPT,
    mcp,
)


class TestGuidanceTools:
    @pytest.mark.asyncio
    async def test_dashboard_prompt_is_available_as_a_tool(self):
        async with Client(mcp) as client:
            tools = await client.list_tools()
            result = await client.call_tool("oci_recovery_service_dashboard_prompt", {})

        assert "oci_recovery_service_dashboard_prompt" in {tool.name for tool in tools}
        assert result.structured_content["result"] == OCI_RECOVERY_SERVICE_DASHBOARD_PROMPT
        assert "cloud-protected databases" in result.structured_content["result"]

    @pytest.mark.asyncio
    async def test_cloud_protect_onboarding_guidance_is_available_as_a_tool(self):
        async with Client(mcp) as client:
            tools = await client.list_tools()
            result = await client.call_tool("onboard_database_with_cloud_protect", {})

        assert "onboard_database_with_cloud_protect" in {tool.name for tool in tools}
        assert result.structured_content["result"] == CLOUD_PROTECT_ONBOARDING_PROMPT
        assert "Recovery Service subnet OCID" in result.structured_content["result"]

    @pytest.mark.asyncio
    async def test_out_of_place_restore_guidance_substitutes_tool_arguments(self):
        arguments = {
            "source_database_address": "10.0.0.10",
            "source_database_name": "SOURCECDB",
            "target_database_address": "10.0.1.10",
            "protected_database_ocid": "ocid1.protecteddatabase.oc1..example",
            "connection_details": "SSH as oracle; OCI API-key profile DR",
        }

        async with Client(mcp) as client:
            tools = await client.list_tools()
            result = await client.call_tool("OutofplaceRestoreOfDatabase", arguments)

        prompt = result.structured_content["result"]
        assert "OutofplaceRestoreOfDatabase" in {tool.name for tool in tools}
        assert "10.0.0.10" in prompt
        assert "SOURCECDB" in prompt
        assert "10.0.1.10" in prompt
        assert "ocid1.protecteddatabase.oc1..example" in prompt
        assert "SSH as oracle; OCI API-key profile DR" in prompt
        assert "<source database address>" not in prompt
        assert "exactly 8 RMAN SBT channels" in prompt
        assert "Appendix A - Required Input Detail" in prompt
        assert OUT_OF_PLACE_RESTORE_OF_DATABASE_PROMPT != prompt

    @pytest.mark.asyncio
    async def test_out_of_place_restore_guidance_allows_an_unknown_source_address(self):
        arguments = {
            "source_database_name": "SOURCECDB",
            "target_database_address": "10.0.1.10",
            "protected_database_ocid": "ocid1.protecteddatabase.oc1..example",
        }

        async with Client(mcp) as client:
            result = await client.call_tool("OutofplaceRestoreOfDatabase", arguments)

        prompt = result.structured_content["result"]
        assert "Not provided; request the source database address" in prompt
        assert "<source database address>" not in prompt

    @pytest.mark.parametrize(
        ("field", "value", "message"),
        [
            ("source_database_address", "source.example.com", "must be an IP address"),
            ("target_database_address", "target.example.com", "must be an IP address"),
            ("source_database_name", "SOURCE DATABASE", "single string"),
            ("source_database_name", "A" * 32, "fewer than 32 characters"),
            ("protected_database_ocid", "not-an-ocid", "valid OCI OCID"),
        ],
    )
    @pytest.mark.asyncio
    async def test_out_of_place_restore_guidance_reports_invalid_replacement_values(
        self, field, value, message
    ):
        arguments = {
            "source_database_address": "10.0.0.10",
            "source_database_name": "SOURCECDB",
            "target_database_address": "10.0.1.10",
            "protected_database_ocid": "ocid1.protecteddatabase.oc1..example",
        }
        arguments[field] = value

        async with Client(mcp) as client:
            result = await client.call_tool("OutofplaceRestoreOfDatabase", arguments)

        response = result.structured_content["result"]
        assert "Cannot populate the recovery runbook" in response
        assert message in response
        assert "Use RMAN and Recovery Service" not in response
