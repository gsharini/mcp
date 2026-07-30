"""
Copyright (c) 2025, Oracle and/or its affiliates.
Licensed under the Universal Permissive License v1.0 as shown at
https://oss.oracle.com/licenses/upl.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock, create_autospec, patch

import oci
import pytest
from fastmcp import Client
import oracle.oci_recovery_mcp_server.server as server
from oracle.oci_recovery_mcp_server.server import mcp


class TestGetClientFactories:
    @patch("oracle.oci_recovery_mcp_server.server._wrap_oci_client", side_effect=lambda client, **_: client)
    @patch("oracle.oci_recovery_mcp_server.server.oci.recovery.DatabaseRecoveryClient")
    @patch("oracle.oci_recovery_mcp_server.server._effective_auth_method", return_value="apikey")
    @patch("oracle.oci_recovery_mcp_server.server._load_oci_config_for_server")
    def test_get_recovery_client_apikey_uses_regional_config(
        self,
        mock_load_config,
        _mock_auth_method,
        mock_client,
        _mock_wrap,
    ):
        mock_load_config.return_value = {"region": "us-ashburn-1"}

        result = server.get_recovery_client(region="us-phoenix-1", request_id="rid")

        args, kwargs = mock_client.call_args
        assert args[0]["region"] == "us-phoenix-1"
        assert "signer" not in kwargs
        assert kwargs == {}
        assert result is mock_client.return_value

    @patch("oracle.oci_recovery_mcp_server.server._wrap_oci_client", side_effect=lambda client, **_: client)
    @patch("oracle.oci_recovery_mcp_server.server._build_signer_for_session")
    @patch("oracle.oci_recovery_mcp_server.server.oci.monitoring.MonitoringClient")
    @patch("oracle.oci_recovery_mcp_server.server._effective_auth_method", return_value="session")
    @patch("oracle.oci_recovery_mcp_server.server._load_oci_config_for_server")
    def test_get_monitoring_client_session_uses_signer(
        self,
        mock_load_config,
        _mock_auth_method,
        mock_client,
        mock_build_signer,
        _mock_wrap,
    ):
        mock_load_config.return_value = {"region": "us-ashburn-1"}
        signer = object()
        mock_build_signer.return_value = signer

        result = server.get_monitoring_client(region="us-phoenix-1", request_id="rid")

        args, kwargs = mock_client.call_args
        assert args[0]["region"] == "us-phoenix-1"
        assert kwargs["signer"] is signer
        assert len(kwargs) == 1
        assert result is mock_client.return_value


def _oauth_entry(alias="t1", tenancy_id="ocid1.tenancy.oc1..t", region="us-ashburn-1"):
    from oracle.oci_recovery_mcp_server.tenancy_registry import TenancyEntry

    return TenancyEntry(
        alias=alias,
        tenancy_id=tenancy_id,
        idcs_domain="idcs-abc.identity.oraclecloud.com",
        client_id="cid",
        client_secret="csec",
        region=region,
    )


class TestOAuthMode:
    @pytest.fixture(autouse=True)
    def _reset_registry(self):
        server._reset_registry_cache()
        yield
        server._reset_registry_cache()

    def test_effective_auth_method_resolves_oauth_aliases(self, monkeypatch):
        for alias in ("oauth", "token_exchange", "token-exchange", "upst", "OAuth"):
            monkeypatch.setenv("ORACLE_MCP_AUTH_METHOD", alias)
            assert server._effective_auth_method() == "oauth"

    def test_effective_auth_method_defaults_session(self, monkeypatch):
        monkeypatch.delenv("ORACLE_MCP_AUTH_METHOD", raising=False)
        assert server._effective_auth_method() == "session"

    def test_domain_to_url_normalizes_host_or_url(self):
        from oracle.oci_recovery_mcp_server.multitenant_auth import _domain_to_url

        assert _domain_to_url("idcs-abc.identity.oraclecloud.com") == "https://idcs-abc.identity.oraclecloud.com"
        assert _domain_to_url("https://idcs-abc.identity.oraclecloud.com/") == "https://idcs-abc.identity.oraclecloud.com"

    def test_domain_to_url_rejects_http(self):
        from oracle.oci_recovery_mcp_server.multitenant_auth import _domain_to_url

        with pytest.raises(ValueError, match="https"):
            _domain_to_url("http://idcs-abc.identity.oraclecloud.com")

    def test_legacy_env_synthesizes_single_tenant_registry(self, monkeypatch):
        monkeypatch.setenv("ORACLE_MCP_AUTH_METHOD", "oauth")
        monkeypatch.delenv("ORACLE_MCP_TENANCY_REGISTRY", raising=False)
        monkeypatch.setenv("ORACLE_MCP_IDCS_DOMAIN", "idcs-abc.identity.oraclecloud.com")
        monkeypatch.setenv("ORACLE_MCP_IDCS_CLIENT_ID", "cid")
        monkeypatch.setenv("ORACLE_MCP_IDCS_CLIENT_SECRET", "csec")
        monkeypatch.setenv("ORACLE_MCP_TENANCY_ID", "ocid1.tenancy.oc1..t")
        monkeypatch.setenv("ORACLE_MCP_REGION", "us-ashburn-1")
        monkeypatch.setenv("ORACLE_MCP_TENANCY_ALIAS", "acme")

        reg = server._get_registry()
        assert reg.lookup("acme").tenancy_id == "ocid1.tenancy.oc1..t"
        assert reg.lookup("ocid1.tenancy.oc1..t").alias == "acme"

    def test_get_tenancy_oauth_uses_token_claim(self, monkeypatch):
        monkeypatch.setenv("ORACLE_MCP_AUTH_METHOD", "oauth")
        with patch.object(server, "_current_tenancy", return_value=_oauth_entry()):
            assert server.get_tenancy() == "ocid1.tenancy.oc1..t"

    def test_get_tenancy_oauth_requires_authenticated_tenant(self, monkeypatch):
        monkeypatch.setenv("ORACLE_MCP_AUTH_METHOD", "oauth")
        # No token on the request -> no tenant claim -> hard error (never silent).
        with patch("fastmcp.server.dependencies.get_access_token", return_value=None):
            with pytest.raises(ValueError):
                server.get_tenancy()

    @patch(
        "oracle.oci_recovery_mcp_server.server._wrap_oci_client",
        side_effect=lambda client, **_: client,
    )
    @patch("oracle.oci_recovery_mcp_server.server.oci.recovery.DatabaseRecoveryClient")
    @patch("oracle.oci_recovery_mcp_server.server._build_token_exchange_signer")
    @patch("oracle.oci_recovery_mcp_server.server._current_tenancy")
    @patch("oracle.oci_recovery_mcp_server.server._effective_auth_method", return_value="oauth")
    def test_make_client_oauth_uses_token_exchange_signer(
        self,
        _mock_auth,
        mock_current,
        mock_build_signer,
        mock_client,
        _mock_wrap,
    ):
        mock_current.return_value = _oauth_entry()
        signer = object()
        mock_build_signer.return_value = signer

        result = server.get_recovery_client(region="us-phoenix-1", request_id="rid")

        args, kwargs = mock_client.call_args
        assert args[0]["region"] == "us-phoenix-1"
        assert kwargs["signer"] is signer
        # the signer is built for the token's tenancy, not a request header
        mock_build_signer.assert_called_once_with(mock_current.return_value)
        assert result is mock_client.return_value

    def test_signer_cache_keyed_by_alias_and_jti(self, monkeypatch):
        # Two tenancies with the same jti must NOT share a cached signer.
        server._oauth_signer_cache.clear()
        made = []

        class FakeTES:
            def __init__(self, **kwargs):
                made.append(kwargs)

        access = SimpleNamespace(token="tok", claims={"jti": "shared-jti"})
        monkeypatch.setattr(
            "fastmcp.server.dependencies.get_access_token", lambda: access, raising=False
        )
        with patch("oci.auth.signers.TokenExchangeSigner", FakeTES):
            s1 = server._build_token_exchange_signer(_oauth_entry(alias="t1"))
            s2 = server._build_token_exchange_signer(_oauth_entry(alias="t2"))
            s1b = server._build_token_exchange_signer(_oauth_entry(alias="t1"))

        assert s1 is not s2  # different tenancy -> different signer
        assert s1 is s1b  # same (alias, jti) -> cached
        assert {"t1:shared-jti", "t2:shared-jti"} <= set(server._oauth_signer_cache)

    def test_build_auth_provider_none_for_session(self, monkeypatch):
        monkeypatch.setenv("ORACLE_MCP_AUTH_METHOD", "session")
        assert server._build_auth_provider() is None

    def test_build_auth_provider_oauth_returns_multitenant(self, monkeypatch, tmp_path):
        from oracle.oci_recovery_mcp_server.multitenant_auth import MultiTenantOCIAuth

        monkeypatch.setenv("ORACLE_MCP_AUTH_METHOD", "oauth")
        monkeypatch.delenv("ORACLE_MCP_TENANCY_REGISTRY", raising=False)
        monkeypatch.setenv("ORACLE_MCP_IDCS_DOMAIN", "idcs-abc.identity.oraclecloud.com")
        monkeypatch.setenv("ORACLE_MCP_IDCS_CLIENT_ID", "cid")
        monkeypatch.setenv("ORACLE_MCP_IDCS_CLIENT_SECRET", "csec")
        monkeypatch.setenv("ORACLE_MCP_TENANCY_ID", "ocid1.tenancy.oc1..t")
        monkeypatch.setenv("ORACLE_MCP_REGION", "us-ashburn-1")
        monkeypatch.setenv("ORACLE_MCP_BASE_URL", "http://localhost:9000")
        monkeypatch.setenv("ORACLE_MCP_OAUTH_SCOPES", "openid offline_access")
        monkeypatch.setenv("ORACLE_MCP_OAUTH_STORAGE_DIR", str(tmp_path))
        captured = {}

        class FakeOCIProvider:
            def __init__(self, **kwargs):
                captured.update(kwargs)

        with patch("fastmcp.server.auth.providers.oci.OCIProvider", FakeOCIProvider):
            provider = server._build_auth_provider()

        assert isinstance(provider, MultiTenantOCIAuth)
        assert str(provider.base_url).rstrip("/") == "http://localhost:9000"
        # each tenancy's OAuth routes are path-namespaced per alias
        assert captured["base_url"] == "http://localhost:9000/t/default"
        assert captured["require_authorization_consent"] is False
        assert list(provider.required_scopes) == ["openid", "offline_access"]


class TestCachePartitioning:
    """In a single multi-tenant process, in-process caches must never leak across tenants."""

    def test_region_cache_partitioned_by_tenant(self, monkeypatch):
        server._REGION_CACHE["items"].clear()
        calls = []

        def fake_identity(*, request_id=None):
            def list_region_subscriptions(tenancy_id):
                calls.append(tenancy_id)
                name = "us-ashburn-1" if tenancy_id == "tA" else "us-phoenix-1"
                return SimpleNamespace(
                    data=[SimpleNamespace(region_name=name, status="READY")]
                )

            return SimpleNamespace(list_region_subscriptions=list_region_subscriptions)

        monkeypatch.setattr(server, "get_identity_client", fake_identity)

        monkeypatch.setattr(server, "get_tenancy", lambda: "tA")
        a1 = server._iam_subscribed_regions_with_status(request_id="r")
        monkeypatch.setattr(server, "get_tenancy", lambda: "tB")
        b1 = server._iam_subscribed_regions_with_status(request_id="r")
        monkeypatch.setattr(server, "get_tenancy", lambda: "tA")
        a2 = server._iam_subscribed_regions_with_status(request_id="r")

        assert a1 == [{"region": "us-ashburn-1", "status": "READY"}]
        assert b1 == [{"region": "us-phoenix-1", "status": "READY"}]  # no leak from tA
        assert a1 == a2
        assert calls == ["tA", "tB"]  # tA's 2nd lookup served from its own cache

    def test_compartment_cache_partitioned_by_tenant(self, monkeypatch):
        server._COMPARTMENT_CACHE["entries"].clear()
        seq = {"tA": [SimpleNamespace(id="cA")], "tB": [SimpleNamespace(id="cB")]}
        calls = []

        def fake_list(only_one_page, limit=100):
            t = server.get_tenancy()
            calls.append(t)
            return list(seq[t])

        monkeypatch.setattr(server, "list_all_compartments_internal", fake_list)
        monkeypatch.setattr(
            server,
            "get_identity_client",
            lambda **k: SimpleNamespace(
                get_compartment=lambda compartment_id: SimpleNamespace(
                    data=SimpleNamespace(id=compartment_id)
                )
            ),
        )

        monkeypatch.setattr(server, "get_tenancy", lambda: "tA")
        a = server._list_all_compartments_cached(request_id="r")
        monkeypatch.setattr(server, "get_tenancy", lambda: "tB")
        b = server._list_all_compartments_cached(request_id="r")
        monkeypatch.setattr(server, "get_tenancy", lambda: "tA")
        server._list_all_compartments_cached(request_id="r")

        ids_a = [getattr(c, "id", None) for c in a]
        ids_b = [getattr(c, "id", None) for c in b]
        assert "cA" in ids_a and "cB" in ids_b
        assert "cB" not in ids_a  # tenant B never leaks into tenant A
        assert calls == ["tA", "tB"]  # tA's 2nd call served from its own cache


class TestRecoveryTools:
    @pytest.mark.asyncio
    @patch("oracle.oci_recovery_mcp_server.server.get_recovery_client")
    async def test_list_protected_databases(self, mock_get_client):
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client

        # Mock list response with a single ProtectedDatabaseSummary
        mock_list_response = create_autospec(oci.response.Response)
        mock_list_response.data = [
            oci.recovery.models.ProtectedDatabaseSummary(
                id="pd1",
                display_name="Protected DB 1",
                lifecycle_state="ACTIVE",
            )
        ]
        mock_list_response.has_next_page = False
        mock_list_response.next_page = None
        mock_client.list_protected_databases.return_value = mock_list_response
        # attach metrics at summary level to ensure fallback path covers
        mock_list_response.data[0].metrics = {"backup_space_used_in_gbs": 10.5}

        async with Client(mcp) as client:
            call_tool_result = await client.call_tool(
                "list_protected_databases",
                {"compartment_id": "ocid1.compartment.oc1..test"},
            )
            result = call_tool_result.structured_content["result"]

            assert len(result) == 1
            assert result[0]["id"] == "pd1"
            assert result[0]["display_name"] == "Protected DB 1"

    @pytest.mark.asyncio
    @patch("oracle.oci_recovery_mcp_server.server.get_recovery_client")
    async def test_get_protected_database(self, mock_get_client):
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client

        # Mock get response with a ProtectedDatabase
        mock_get_response = create_autospec(oci.response.Response)
        pd = oci.recovery.models.ProtectedDatabase(
            id="pd1",
            display_name="Protected DB 1",
            lifecycle_state="ACTIVE",
            health="PROTECTED",
        )
        # attach minimal metrics for mapping tolerance
        pd.metrics = {"backup_space_used_in_gbs": 12.5}
        mock_get_response.data = pd
        mock_client.get_protected_database.return_value = mock_get_response

        async with Client(mcp) as client:
            call_tool_result = await client.call_tool(
                "get_protected_database", {"protected_database_id": "pd1"}
            )
            result = call_tool_result.structured_content

            assert result["id"] == "pd1"
            assert result["health"] == "PROTECTED"

    @pytest.mark.asyncio
    @patch("oracle.oci_recovery_mcp_server.server.get_recovery_client")
    async def test_list_protection_policies(self, mock_get_client):
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client

        mock_list_response = create_autospec(oci.response.Response)
        mock_list_response.data = [
            oci.recovery.models.ProtectionPolicySummary(
                id="pp1",
                display_name="Policy 1",
                lifecycle_state="ACTIVE",
            )
        ]
        mock_list_response.has_next_page = False
        mock_list_response.next_page = None
        mock_client.list_protection_policies.return_value = mock_list_response

        async with Client(mcp) as client:
            call_tool_result = await client.call_tool(
                "list_protection_policies",
                {"compartment_id": "ocid1.compartment.oc1..test"},
            )
            result = call_tool_result.structured_content["result"]

            assert len(result) == 1
            assert result[0]["id"] == "pp1"
            assert result[0]["display_name"] == "Policy 1"

    @pytest.mark.asyncio
    @patch("oracle.oci_recovery_mcp_server.server.get_recovery_client")
    async def test_get_protection_policy(self, mock_get_client):
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client

        mock_get_response = create_autospec(oci.response.Response)
        mock_get_response.data = oci.recovery.models.ProtectionPolicy(
            id="pp1",
            display_name="Policy 1",
            lifecycle_state="ACTIVE",
        )
        mock_client.get_protection_policy.return_value = mock_get_response

        async with Client(mcp) as client:
            call_tool_result = await client.call_tool(
                "get_protection_policy", {"protection_policy_id": "pp1"}
            )
            result = call_tool_result.structured_content

            assert result["id"] == "pp1"
            assert result["display_name"] == "Policy 1"

    @pytest.mark.asyncio
    @patch("oracle.oci_recovery_mcp_server.server.get_recovery_client")
    async def test_list_recovery_service_subnets(self, mock_get_client):
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client

        mock_list_response = create_autospec(oci.response.Response)
        mock_list_response.data = [
            oci.recovery.models.RecoveryServiceSubnetSummary(
                id="rss1",
                display_name="RSS 1",
                lifecycle_state="ACTIVE",
            )
        ]
        mock_list_response.has_next_page = False
        mock_list_response.next_page = None
        mock_client.list_recovery_service_subnets.return_value = mock_list_response

        async with Client(mcp) as client:
            call_tool_result = await client.call_tool(
                "list_recovery_service_subnets",
                {"compartment_id": "ocid1.compartment.oc1..test"},
            )
            result = call_tool_result.structured_content["result"]

            assert len(result) == 1
            assert result[0]["id"] == "rss1"
            assert result[0]["display_name"] == "RSS 1"

    @pytest.mark.asyncio
    @patch("oracle.oci_recovery_mcp_server.server.get_recovery_client")
    async def test_get_recovery_service_subnet(self, mock_get_client):
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client

        mock_get_response = create_autospec(oci.response.Response)
        mock_get_response.data = oci.recovery.models.RecoveryServiceSubnet(
            id="rss1",
            display_name="RSS 1",
            lifecycle_state="ACTIVE",
        )
        mock_client.get_recovery_service_subnet.return_value = mock_get_response

        async with Client(mcp) as client:
            call_tool_result = await client.call_tool(
                "get_recovery_service_subnet", {"recovery_service_subnet_id": "rss1"}
            )
            result = call_tool_result.structured_content

            assert result["id"] == "rss1"
            assert result["display_name"] == "RSS 1"

    @pytest.mark.asyncio
    @patch("oracle.oci_recovery_mcp_server.server.get_tenancy")
    @patch("oracle.oci_recovery_mcp_server.server.get_recovery_client")
    async def test_summarize_protected_database_health(
        self, mock_get_client, mock_get_tenancy
    ):
        mock_get_tenancy.return_value = "ocid1.compartment.oc1..test"

        mock_client = MagicMock()
        mock_get_client.return_value = mock_client

        # list two PDs
        mock_list_response = create_autospec(oci.response.Response)
        mock_list_response.data = [
            oci.recovery.models.ProtectedDatabaseSummary(id="pd1"),
            oci.recovery.models.ProtectedDatabaseSummary(id="pd2"),
        ]
        mock_list_response.has_next_page = False
        mock_list_response.next_page = None
        mock_client.list_protected_databases.return_value = mock_list_response

        # get each with different health
        mock_get_pd_resp1 = create_autospec(oci.response.Response)
        mock_get_pd_resp1.data = oci.recovery.models.ProtectedDatabase(
            id="pd1", health="PROTECTED"
        )
        mock_get_pd_resp2 = create_autospec(oci.response.Response)
        mock_get_pd_resp2.data = oci.recovery.models.ProtectedDatabase(
            id="pd2", health="WARNING"
        )
        mock_client.get_protected_database.side_effect = [
            mock_get_pd_resp1,
            mock_get_pd_resp2,
        ]

        async with Client(mcp) as client:
            call_tool_result = await client.call_tool(
                "summarize_protected_database_health",
                {"compartment_id": "ocid1.compartment.oc1..test"},
            )
            result = call_tool_result.structured_content

            aggregated = result["aggregated"]
            assert aggregated["protected"] == 1
            assert aggregated["warning"] == 1
            assert aggregated["alert"] == 0
            assert aggregated["total"] == 2

    @pytest.mark.asyncio
    @patch("oracle.oci_recovery_mcp_server.server.get_tenancy")
    @patch("oracle.oci_recovery_mcp_server.server.get_recovery_client")
    async def test_summarize_protected_database_redo_status(
        self, mock_get_client, mock_get_tenancy
    ):
        mock_get_tenancy.return_value = "ocid1.compartment.oc1..test"

        mock_client = MagicMock()
        mock_get_client.return_value = mock_client

        mock_list_response = create_autospec(oci.response.Response)
        mock_list_response.data = [
            oci.recovery.models.ProtectedDatabaseSummary(id="pd1"),
            oci.recovery.models.ProtectedDatabaseSummary(id="pd2"),
        ]
        mock_list_response.has_next_page = False
        mock_list_response.next_page = None
        mock_client.list_protected_databases.return_value = mock_list_response

        # get PDs with redo shipped enabled/disabled
        pd1 = oci.recovery.models.ProtectedDatabase(id="pd1")
        pd1.is_redo_logs_shipped = True
        pd2 = oci.recovery.models.ProtectedDatabase(id="pd2")
        pd2.is_redo_logs_shipped = False
        mock_get_pd_resp1 = create_autospec(oci.response.Response)
        mock_get_pd_resp1.data = pd1
        mock_get_pd_resp2 = create_autospec(oci.response.Response)
        mock_get_pd_resp2.data = pd2
        mock_client.get_protected_database.side_effect = [
            mock_get_pd_resp1,
            mock_get_pd_resp2,
        ]

        async with Client(mcp) as client:
            call_tool_result = await client.call_tool(
                "summarize_protected_database_redo_status",
                {"compartment_id": "ocid1.compartment.oc1..test"},
            )
            result = call_tool_result.structured_content

            aggregated = result["aggregated"]
            assert aggregated["enabled"] == 1
            assert aggregated["disabled"] == 1
            assert aggregated["total"] == 2

    @pytest.mark.asyncio
    @patch("oracle.oci_recovery_mcp_server.server.get_tenancy")
    @patch("oracle.oci_recovery_mcp_server.server.get_recovery_client")
    async def test_summarize_backup_space_used(self, mock_get_client, mock_get_tenancy):
        mock_get_tenancy.return_value = "ocid1.compartment.oc1..test"

        mock_client = MagicMock()
        mock_get_client.return_value = mock_client

        mock_list_response = create_autospec(oci.response.Response)
        pd1_summary = oci.recovery.models.ProtectedDatabaseSummary(
            id="pd1", lifecycle_state="ACTIVE"
        )
        pd2_summary = oci.recovery.models.ProtectedDatabaseSummary(
            id="pd2", lifecycle_state="ACTIVE"
        )
        mock_list_response.data = [pd1_summary, pd2_summary]
        mock_list_response.has_next_page = False
        mock_list_response.next_page = None
        mock_client.list_protected_databases.return_value = mock_list_response
        # Fallback path for metrics at summary level
        pd1_summary.metrics = {"backup_space_used_in_gbs": 10.5}
        pd2_summary.metrics = {"backup_space_used_in_gbs": 4.5}

        # PD1 metrics 10.5 GB, PD2 metrics 4.5 GB
        pd1 = oci.recovery.models.ProtectedDatabase(id="pd1")
        pd1.metrics = {"backup_space_used_in_gbs": 10.5}
        pd2 = oci.recovery.models.ProtectedDatabase(id="pd2")
        pd2.metrics = {"backup_space_used_in_gbs": 4.5}

        mock_get_pd_resp1 = create_autospec(oci.response.Response)
        mock_get_pd_resp1.data = pd1
        mock_get_pd_resp2 = create_autospec(oci.response.Response)
        mock_get_pd_resp2.data = pd2
        mock_client.get_protected_database.side_effect = [
            mock_get_pd_resp1,
            mock_get_pd_resp2,
        ]

        async with Client(mcp) as client:
            call_tool_result = await client.call_tool(
                "summarize_backup_space_used",
                {
                    "compartment_id": "ocid1.compartment.oc1..test",
                    "region": "us-ashburn-1",
                },
            )
            result = call_tool_result.structured_content

        aggregated = result["aggregated"]
        total_scanned = aggregated.get("total_databases_scanned") or aggregated.get(
            "totalDatabasesScanned"
        )
        sum_gb = aggregated.get("sum_backup_space_used_in_gbs") or aggregated.get(
            "sumBackupSpaceUsedInGBs"
        )
        assert abs(sum_gb - 15.0) < 1e-9
        assert total_scanned == 2

    @pytest.mark.asyncio
    @patch("oracle.oci_recovery_mcp_server.server.get_tenancy")
    @patch("oracle.oci_recovery_mcp_server.server._load_oci_config_for_server")
    @patch("oracle.oci_recovery_mcp_server.server.get_limits_client")
    async def test_check_recovery_service_limits(
        self, mock_get_limits_client, mock_load_config, mock_get_tenancy
    ):
        mock_get_tenancy.return_value = "ocid1.tenancy.oc1..tenancy"
        mock_load_config.return_value = {
            "region": "us-ashburn-1",
            "tenancy": "ocid1.tenancy.oc1..tenancy",
        }
        mock_client = MagicMock()
        mock_get_limits_client.return_value = mock_client

        avail_storage = create_autospec(oci.response.Response)
        avail_storage.data = {
            "scope_type": "AD",
            "available": 1000,
            "used": 150,
            "fractional_availability": 0.86,
            "fractional_usage": 0.14,
            "effective_quota_value": 1150,
            "policy_name": "default",
        }
        avail_count = create_autospec(oci.response.Response)
        avail_count.data = {
            "scope_type": "AD",
            "available": 20,
            "used": 7,
            "fractional_availability": 0.74,
            "fractional_usage": 0.26,
            "effective_quota_value": 27,
            "policy_name": "default",
        }
        mock_client.get_resource_availability.side_effect = [avail_storage, avail_count]

        async with Client(mcp) as client:
            call_tool_result = await client.call_tool(
                "check_recovery_service_limits",
                {},
            )
            result = call_tool_result.structured_content

        # compartmentId is always the tenancy OCID from config, not the input
        assert result["compartmentId"] == "ocid1.tenancy.oc1..tenancy"
        assert result["limits"]["protectedDatabaseBackupStorageGb"]["available"] == 1000
        assert result["limits"]["protectedDatabaseCount"]["used"] == 7

    @pytest.mark.asyncio
    @patch("oracle.oci_recovery_mcp_server.server._iam_subscribed_regions_with_status")
    @patch("oracle.oci_recovery_mcp_server.server.get_tenancy")
    async def test_fetch_regions_subscribed(self, mock_get_tenancy, mock_regions):
        mock_get_tenancy.return_value = "ocid1.tenancy.oc1..test"
        mock_regions.return_value = [
            {"region": "us-ashburn-1", "status": "READY"},
            {"region": "us-phoenix-1", "status": "READY"},
        ]

        async with Client(mcp) as client:
            call_tool_result = await client.call_tool("fetch_regions_subscribed", {})
            result = call_tool_result.structured_content

            assert result["tenancyId"] == "ocid1.tenancy.oc1..test"
            assert result["total"] == 2
            assert result["regions"][0]["region"] == "us-ashburn-1"

    @pytest.mark.asyncio
    @patch("oracle.oci_recovery_mcp_server.server.get_monitoring_client")
    async def test_get_recovery_service_metrics(self, mock_get_monitoring_client):
        mock_client = MagicMock()
        mock_get_monitoring_client.return_value = mock_client

        # Prepare a fake series with aggregated datapoints
        dp1 = SimpleNamespace(timestamp="2024-01-01T00:00:00Z", value=1.0)
        dp2 = SimpleNamespace(timestamp="2024-01-01T00:01:00Z", value=2.0)
        series = SimpleNamespace(
            dimensions={"resourceId": "pd1"}, aggregated_datapoints=[dp1, dp2]
        )

        mock_metrics_response = create_autospec(oci.response.Response)
        mock_metrics_response.data = [series]
        mock_client.summarize_metrics_data.return_value = mock_metrics_response

        async with Client(mcp) as client:
            call_tool_result = await client.call_tool(
                "get_recovery_service_metrics",
                {
                    "compartment_id": "ocid1.compartment.oc1..test",
                    "start_time": "2024-01-01T00:00:00Z",
                    "end_time": "2024-01-01T00:05:00Z",
                    "metricName": "SpaceUsedForRecoveryWindow",
                    "resolution": "1m",
                    "aggregation": "mean",
                    "protected_database_id": "pd1",
                },
            )
            result = call_tool_result.structured_content["result"]

            assert isinstance(result, list)
            assert len(result) == 1
            assert result[0]["dimensions"]["resourceId"] == "pd1"
            assert len(result[0]["datapoints"]) == 2
            assert result[0]["datapoints"][0]["value"] == 1.0

    @pytest.mark.asyncio
    @patch("oracle.oci_recovery_mcp_server.server.get_monitoring_client")
    async def test_get_recovery_service_metrics_no_pd_filter(self, mock_get_monitoring_client):
        mock_client = MagicMock()
        mock_get_monitoring_client.return_value = mock_client

        series = SimpleNamespace(
            dimensions={"resourceId": "pd1"}, aggregated_datapoints=[]
        )
        mock_metrics_response = create_autospec(oci.response.Response)
        mock_metrics_response.data = [series]
        mock_client.summarize_metrics_data.return_value = mock_metrics_response

        async with Client(mcp) as client:
            call_tool_result = await client.call_tool(
                "get_recovery_service_metrics",
                {
                    "compartment_id": "ocid1.compartment.oc1..test",
                    "start_time": "2024-01-01T00:00:00Z",
                    "end_time": "2024-01-01T01:00:00Z",
                },
            )
            result = call_tool_result.structured_content["result"]

        assert isinstance(result, list)
        assert len(result) == 1
        # No protected_database_id filter — query must NOT include a resourceId filter clause
        call_args = mock_client.summarize_metrics_data.call_args
        query = call_args.kwargs["summarize_metrics_data_details"].query
        assert "resourceId" not in query

    @pytest.mark.asyncio
    @patch("oracle.oci_recovery_mcp_server.server.get_recovery_client")
    async def test_list_protected_databases_pagination(self, mock_get_client):
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client

        page1 = create_autospec(oci.response.Response)
        page1.data = [oci.recovery.models.ProtectedDatabaseSummary(id="pd1")]
        page1.has_next_page = True
        page1.next_page = "token2"

        page2 = create_autospec(oci.response.Response)
        page2.data = [oci.recovery.models.ProtectedDatabaseSummary(id="pd2")]
        page2.has_next_page = False
        page2.next_page = None

        mock_client.list_protected_databases.side_effect = [page1, page2]
        mock_client.get_protected_database.return_value = create_autospec(oci.response.Response)
        mock_client.get_protected_database.return_value.data = (
            oci.recovery.models.ProtectedDatabase(id="pd1")
        )

        async with Client(mcp) as client:
            call_tool_result = await client.call_tool(
                "list_protected_databases",
                {"compartment_id": "ocid1.compartment.oc1..test"},
            )
            result = call_tool_result.structured_content["result"]

        assert len(result) == 2
        ids = {r["id"] for r in result}
        assert ids == {"pd1", "pd2"}
        assert mock_client.list_protected_databases.call_count == 2

    @pytest.mark.asyncio
    @patch("oracle.oci_recovery_mcp_server.server._compartment_ids_for_tool")
    @patch("oracle.oci_recovery_mcp_server.server.get_recovery_client")
    async def test_list_protected_databases_dedup_child_compartments(
        self, mock_get_client, mock_comp_ids
    ):
        mock_comp_ids.return_value = ["comp1", "comp2"]
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client

        # Both compartments return the same PD OCID -> dedup should yield 1 result
        resp = create_autospec(oci.response.Response)
        resp.data = [oci.recovery.models.ProtectedDatabaseSummary(id="pd1")]
        resp.has_next_page = False
        resp.next_page = None
        mock_client.list_protected_databases.return_value = resp

        get_resp = create_autospec(oci.response.Response)
        get_resp.data = oci.recovery.models.ProtectedDatabase(id="pd1")
        mock_client.get_protected_database.return_value = get_resp

        async with Client(mcp) as client:
            call_tool_result = await client.call_tool(
                "list_protected_databases",
                {
                    "compartment_id": "ocid1.compartment.oc1..test",
                    "fetch_for_child_compartment": True,
                },
            )
            result = call_tool_result.structured_content["result"]

        assert len(result) == 1
        assert result[0]["id"] == "pd1"

    @pytest.mark.asyncio
    @patch("oracle.oci_recovery_mcp_server.server.get_tenancy")
    @patch("oracle.oci_recovery_mcp_server.server.get_recovery_client")
    async def test_summarize_health_alert_and_unknown_states(
        self, mock_get_client, mock_get_tenancy
    ):
        mock_get_tenancy.return_value = "ocid1.compartment.oc1..test"
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client

        mock_list = create_autospec(oci.response.Response)
        mock_list.data = [
            oci.recovery.models.ProtectedDatabaseSummary(id="pd1"),
            oci.recovery.models.ProtectedDatabaseSummary(id="pd2"),
        ]
        mock_list.has_next_page = False
        mock_list.next_page = None
        mock_client.list_protected_databases.return_value = mock_list

        r1 = create_autospec(oci.response.Response)
        r1.data = oci.recovery.models.ProtectedDatabase(id="pd1", health="ALERT")
        r2 = create_autospec(oci.response.Response)
        # health=None triggers unknown counter
        r2.data = oci.recovery.models.ProtectedDatabase(id="pd2", health=None)
        mock_client.get_protected_database.side_effect = [r1, r2]

        async with Client(mcp) as client:
            call_tool_result = await client.call_tool(
                "summarize_protected_database_health",
                {"compartment_id": "ocid1.compartment.oc1..test"},
            )
            result = call_tool_result.structured_content

        agg = result["aggregated"]
        assert agg["alert"] == 1
        assert agg["unknown"] == 1
        assert agg["protected"] == 0
        assert agg["warning"] == 0
        assert agg["total"] == 2

    @pytest.mark.asyncio
    @patch("oracle.oci_recovery_mcp_server.server.get_tenancy")
    @patch("oracle.oci_recovery_mcp_server.server.get_recovery_client")
    async def test_summarize_redo_none_not_counted(
        self, mock_get_client, mock_get_tenancy
    ):
        mock_get_tenancy.return_value = "ocid1.compartment.oc1..test"
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client

        mock_list = create_autospec(oci.response.Response)
        mock_list.data = [oci.recovery.models.ProtectedDatabaseSummary(id="pd1")]
        mock_list.has_next_page = False
        mock_list.next_page = None
        mock_client.list_protected_databases.return_value = mock_list

        pd = oci.recovery.models.ProtectedDatabase(id="pd1")
        pd.is_redo_logs_shipped = None  # unknown -> must not count
        r = create_autospec(oci.response.Response)
        r.data = pd
        mock_client.get_protected_database.return_value = r

        async with Client(mcp) as client:
            call_tool_result = await client.call_tool(
                "summarize_protected_database_redo_status",
                {"compartment_id": "ocid1.compartment.oc1..test"},
            )
            result = call_tool_result.structured_content

        agg = result["aggregated"]
        assert agg["enabled"] == 0
        assert agg["disabled"] == 0
        assert agg["total"] == 0

    @pytest.mark.asyncio
    @patch("oracle.oci_recovery_mcp_server.server.get_tenancy")
    @patch("oracle.oci_recovery_mcp_server.server.get_recovery_client")
    async def test_summarize_redo_get_failure_is_non_fatal(
        self, mock_get_client, mock_get_tenancy
    ):
        """A single GET failure must not abort the whole tool."""
        mock_get_tenancy.return_value = "ocid1.compartment.oc1..test"
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client

        mock_list = create_autospec(oci.response.Response)
        mock_list.data = [
            oci.recovery.models.ProtectedDatabaseSummary(id="pd1"),
            oci.recovery.models.ProtectedDatabaseSummary(id="pd2"),
        ]
        mock_list.has_next_page = False
        mock_list.next_page = None
        mock_client.list_protected_databases.return_value = mock_list

        pd2_resp = create_autospec(oci.response.Response)
        pd2 = oci.recovery.models.ProtectedDatabase(id="pd2")
        pd2.is_redo_logs_shipped = True
        pd2_resp.data = pd2

        # pd1 GET raises; pd2 succeeds
        mock_client.get_protected_database.side_effect = [
            Exception("transient error"),
            pd2_resp,
        ]

        async with Client(mcp) as client:
            call_tool_result = await client.call_tool(
                "summarize_protected_database_redo_status",
                {"compartment_id": "ocid1.compartment.oc1..test"},
            )
            result = call_tool_result.structured_content

        agg = result["aggregated"]
        assert agg["enabled"] == 1
        assert agg["disabled"] == 0

    @pytest.mark.asyncio
    @patch("oracle.oci_recovery_mcp_server.server.get_tenancy")
    @patch("oracle.oci_recovery_mcp_server.server.get_recovery_client")
    async def test_summarize_backup_space_skips_deleted_lifecycle(
        self, mock_get_client, mock_get_tenancy
    ):
        mock_get_tenancy.return_value = "ocid1.compartment.oc1..test"
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client

        active_pd = oci.recovery.models.ProtectedDatabaseSummary(
            id="pd1", lifecycle_state="ACTIVE"
        )
        deleted_pd = oci.recovery.models.ProtectedDatabaseSummary(
            id="pd2", lifecycle_state="DELETED"
        )
        mock_list = create_autospec(oci.response.Response)
        mock_list.data = [active_pd, deleted_pd]
        mock_list.has_next_page = False
        mock_list.next_page = None
        mock_client.list_protected_databases.return_value = mock_list

        pd1 = oci.recovery.models.ProtectedDatabase(id="pd1")
        pd1.metrics = {"backup_space_used_in_gbs": 20.0}
        r1 = create_autospec(oci.response.Response)
        r1.data = pd1
        mock_client.get_protected_database.return_value = r1

        async with Client(mcp) as client:
            call_tool_result = await client.call_tool(
                "summarize_backup_space_used",
                {"compartment_id": "ocid1.compartment.oc1..test"},
            )
            result = call_tool_result.structured_content

        agg = result["aggregated"]
        total = agg.get("total_databases_scanned") or agg.get("totalDatabasesScanned")
        sum_gb = agg.get("sum_backup_space_used_in_gbs") or agg.get("sumBackupSpaceUsedInGBs")
        assert total == 1  # DELETED is excluded
        assert abs(sum_gb - 20.0) < 1e-9
        # GET must only be called for ACTIVE PD, not for DELETED
        assert mock_client.get_protected_database.call_count == 1

    @pytest.mark.asyncio
    @patch("oracle.oci_recovery_mcp_server.server.get_recovery_client")
    async def test_list_protection_policies_with_lifecycle_filter(self, mock_get_client):
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client

        mock_list = create_autospec(oci.response.Response)
        mock_list.data = [
            oci.recovery.models.ProtectionPolicySummary(
                id="pp1", display_name="Policy 1", lifecycle_state="ACTIVE"
            )
        ]
        mock_list.has_next_page = False
        mock_list.next_page = None
        mock_client.list_protection_policies.return_value = mock_list

        async with Client(mcp) as client:
            call_tool_result = await client.call_tool(
                "list_protection_policies",
                {
                    "compartment_id": "ocid1.compartment.oc1..test",
                    "lifecycle_state": "ACTIVE",
                },
            )
            result = call_tool_result.structured_content["result"]

        assert len(result) == 1
        call_kwargs = mock_client.list_protection_policies.call_args.kwargs
        assert call_kwargs.get("lifecycle_state") == "ACTIVE"


class TestServer:
    @patch("oracle.oci_recovery_mcp_server.server.mcp.run")
    @patch("os.getenv")
    def test_main_with_host_and_port(self, mock_getenv, mock_mcp_run):
        mock_env = {
            "ORACLE_MCP_HOST": "127.0.0.1",
            "ORACLE_MCP_PORT": "8080",
        }
        # Return configured values for known keys, and default for others
        mock_getenv.side_effect = lambda k, d=None: mock_env.get(k, d)

        import oracle.oci_recovery_mcp_server.server as server

        server.main()
        mock_mcp_run.assert_called_once_with(
            transport="http",
            host=mock_env["ORACLE_MCP_HOST"],
            port=int(mock_env["ORACLE_MCP_PORT"]),
        )

    @patch("oracle.oci_recovery_mcp_server.server.mcp.run")
    @patch("os.getenv")
    def test_main_without_host_and_port(self, mock_getenv, mock_mcp_run):
        # Return None for host/port keys, otherwise pass through default (for log dir/file)
        mock_getenv.side_effect = lambda k, d=None: (
            None if k in ("ORACLE_MCP_HOST", "ORACLE_MCP_PORT") else d
        )

        import oracle.oci_recovery_mcp_server.server as server

        server.main()
        mock_mcp_run.assert_called_once_with()

    @patch("oracle.oci_recovery_mcp_server.server.mcp.run")
    @patch("os.getenv")
    def test_main_with_only_host(self, mock_getenv, mock_mcp_run):
        mock_env = {"ORACLE_MCP_HOST": "127.0.0.1"}
        mock_getenv.side_effect = lambda k, d=None: mock_env.get(k, d)

        import oracle.oci_recovery_mcp_server.server as server

        server.main()
        mock_mcp_run.assert_called_once_with()

    @patch("oracle.oci_recovery_mcp_server.server.mcp.run")
    @patch("os.getenv")
    def test_main_with_only_port(self, mock_getenv, mock_mcp_run):
        mock_env = {"ORACLE_MCP_PORT": "8080"}
        mock_getenv.side_effect = lambda k, d=None: mock_env.get(k, d)

        import oracle.oci_recovery_mcp_server.server as server

        server.main()
        mock_mcp_run.assert_called_once_with()

    @patch("oracle.oci_recovery_mcp_server.server.mcp.run")
    @patch("os.getenv")
    def test_main_oauth_runs_streamable_http_default_host_port(self, mock_getenv, mock_mcp_run):
        # oauth implies the streamable HTTP transport even without host/port set.
        mock_env = {"ORACLE_MCP_AUTH_METHOD": "oauth"}
        mock_getenv.side_effect = lambda k, d=None: mock_env.get(k, d)

        import oracle.oci_recovery_mcp_server.server as server

        server.main()
        mock_mcp_run.assert_called_once_with(transport="http", host="127.0.0.1", port=8000)

    @patch("oracle.oci_recovery_mcp_server.server.mcp.run")
    @patch("os.getenv")
    def test_main_oauth_honors_host_and_port(self, mock_getenv, mock_mcp_run):
        mock_env = {
            "ORACLE_MCP_AUTH_METHOD": "oauth",
            "ORACLE_MCP_HOST": "0.0.0.0",
            "ORACLE_MCP_PORT": "9001",
        }
        mock_getenv.side_effect = lambda k, d=None: mock_env.get(k, d)

        import oracle.oci_recovery_mcp_server.server as server

        server.main()
        mock_mcp_run.assert_called_once_with(transport="http", host="0.0.0.0", port=9001)
