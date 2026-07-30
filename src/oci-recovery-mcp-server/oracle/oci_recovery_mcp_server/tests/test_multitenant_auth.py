"""
Copyright (c) 2025, Oracle and/or its affiliates.
Licensed under the Universal Permissive License v1.0 as shown at
https://oss.oracle.com/licenses/upl.
"""

import os
import stat
from unittest.mock import patch

import pytest
from fastmcp.server.auth.auth import AccessToken
from fastmcp.server.auth.oidc_proxy import OIDCConfiguration
from starlette.applications import Starlette
from starlette.testclient import TestClient

from oracle.oci_recovery_mcp_server.multitenant_auth import (
    TENANT_CLAIM,
    MultiTenantOCIAuth,
    load_or_create_signing_key,
)
from oracle.oci_recovery_mcp_server.tenancy_registry import TenancyRegistry

HOST = "https://mcp.example.com"

_REG = {
    "t1": {
        "tenancy_id": "ocid1.tenancy.oc1..aaaa",
        "idcs_domain": "idcs-aaaa.identity.oraclecloud.com",
        "client_id": "client-one",
        "client_secret": "secret-one",
        "region": "us-ashburn-1",
    },
    "t2": {
        "tenancy_id": "ocid1.tenancy.oc1..bbbb",
        "idcs_domain": "idcs-bbbb.identity.oraclecloud.com",
        "client_id": "client-two",
        "client_secret": "secret-two",
        "region": "us-phoenix-1",
    },
}


def _fake_oidc(cls, config_url, *, strict=None, timeout_seconds=None):
    host = str(config_url).split("/.well-known")[0]
    return OIDCConfiguration(
        strict=False,
        issuer=host,
        authorization_endpoint=f"{host}/oauth2/v1/authorize",
        token_endpoint=f"{host}/oauth2/v1/token",
        jwks_uri=f"{host}/admin/v1/SigningCert/jwk",
        registration_endpoint=f"{host}/oauth2/v1/register",
        response_types_supported=["code"],
        subject_types_supported=["public"],
        id_token_signing_alg_values_supported=["RS256"],
    )


@pytest.fixture
def auth(tmp_path):
    reg = TenancyRegistry.from_mapping(_REG)
    with patch.object(OIDCConfiguration, "get_oidc_configuration", classmethod(_fake_oidc)):
        yield MultiTenantOCIAuth(
            reg,
            base_url=HOST,
            storage_root=str(tmp_path),
            required_scopes=["openid", "offline_access"],
        )


class TestSigningKey:
    def test_persisted_once_with_0600(self, tmp_path):
        k1 = load_or_create_signing_key(str(tmp_path), "t1")
        k2 = load_or_create_signing_key(str(tmp_path), "t1")
        assert k1 == k2 and len(k1) == 32  # stable, never regenerated
        key_path = tmp_path / "t1" / "signing.key"
        mode = stat.S_IMODE(os.stat(key_path).st_mode)
        assert mode == 0o600


class TestRoutes:
    def test_metadata_and_routes_resolve(self, auth):
        app = Starlette(routes=auth.get_routes(mcp_path="/mcp"))
        client = TestClient(app)

        for alias in ("t1", "t2"):
            r = client.get(f"/.well-known/oauth-authorization-server/t/{alias}")
            assert r.status_code == 200
            assert r.json()["authorization_endpoint"] == f"{HOST}/t/{alias}/authorize"

        # header present -> routes to that tenancy's authorization server
        r = client.get(
            "/.well-known/oauth-protected-resource/mcp",
            headers={"X-OCI-Tenancy": "t2"},
        )
        assert r.status_code == 200
        assert r.json()["authorization_servers"] == [f"{HOST}/t/t2"]
        assert r.json()["resource"] == f"{HOST}/mcp"

        # OCID also accepted
        r = client.get(
            "/.well-known/oauth-protected-resource/mcp",
            headers={"X-OCI-Tenancy": "ocid1.tenancy.oc1..aaaa"},
        )
        assert r.json()["authorization_servers"] == [f"{HOST}/t/t1"]

        # header absent -> actionable 400 listing aliases, never secrets
        r = client.get("/.well-known/oauth-protected-resource/mcp")
        assert r.status_code == 400
        body = r.json()
        assert body["error"] == "tenancy_required"
        assert sorted(body["valid_tenancies"]) == ["t1", "t2"]
        assert "secret-one" not in r.text

    def test_operational_routes_mounted(self, auth):
        app = Starlette(routes=auth.get_routes(mcp_path="/mcp"))
        client = TestClient(app)
        # empty body -> handler runs (400-ish), but NOT 404 (route resolves)
        r = client.post("/t/t1/register", json={})
        assert r.status_code != 404
        r = client.get("/tenancies")
        assert r.status_code == 200 and "t1" in r.text and "t2" in r.text


class TestVerifyTokenStamping:
    @pytest.mark.asyncio
    async def test_stamps_alias_of_matching_provider(self, auth):
        token = AccessToken(token="tok", client_id="c", scopes=[], claims={"jti": "j1"})

        async def t1_load(_tok):
            return None  # t1 doesn't own this token

        async def t2_load(_tok):
            return token  # t2's signing key verifies it

        with patch.object(auth._providers["t1"], "load_access_token", side_effect=t1_load), \
             patch.object(auth._providers["t2"], "load_access_token", side_effect=t2_load):
            result = await auth.verify_token("tok")

        assert result is not None
        assert result.claims[TENANT_CLAIM] == "t2"
        assert result.claims["jti"] == "j1"  # original claims preserved

    @pytest.mark.asyncio
    async def test_returns_none_when_no_provider_matches(self, auth):
        async def none_load(_tok):
            return None

        with patch.object(auth._providers["t1"], "load_access_token", side_effect=none_load), \
             patch.object(auth._providers["t2"], "load_access_token", side_effect=none_load):
            assert await auth.verify_token("tok") is None

    @pytest.mark.asyncio
    async def test_header_narrows_verification_rejecting_mismatched_token(self, auth):
        # A t2 token presented with X-OCI-Tenancy: t1 must be REJECTED (-> 401 ->
        # client re-auths for t1), not silently served as t2.
        token = AccessToken(token="tok", client_id="c", scopes=[], claims={"jti": "j"})

        async def t1_load(_tok):
            return None  # token is not t1's

        async def t2_load(_tok):
            return token  # token is t2's

        with patch("fastmcp.server.dependencies.get_http_headers",
                   return_value={"x-oci-tenancy": "t1"}), \
             patch.object(auth._providers["t1"], "load_access_token", side_effect=t1_load), \
             patch.object(auth._providers["t2"], "load_access_token", side_effect=t2_load):
            # only t1 is consulted because the header asked for t1
            assert await auth.verify_token("tok") is None

    @pytest.mark.asyncio
    async def test_unknown_header_rejected_even_if_token_valid(self, auth):
        # A typo'd / decommissioned X-OCI-Tenancy must be rejected, NOT silently
        # served via try-all, even if a cached token would otherwise verify.
        token = AccessToken(token="tok", client_id="c", scopes=[], claims={"jti": "j"})

        async def valid(_tok):
            return token

        with patch("fastmcp.server.dependencies.get_http_headers",
                   return_value={"x-oci-tenancy": "typo-not-a-tenant"}), \
             patch.object(auth._providers["t1"], "load_access_token", side_effect=valid), \
             patch.object(auth._providers["t2"], "load_access_token", side_effect=valid):
            assert await auth.verify_token("tok") is None

    @pytest.mark.asyncio
    async def test_header_match_verifies(self, auth):
        token = AccessToken(token="tok", client_id="c", scopes=[], claims={"jti": "j"})

        async def t1_load(_tok):
            return token

        with patch("fastmcp.server.dependencies.get_http_headers",
                   return_value={"x-oci-tenancy": "t1"}), \
             patch.object(auth._providers["t1"], "load_access_token", side_effect=t1_load):
            result = await auth.verify_token("tok")
        assert result is not None and result.claims[TENANT_CLAIM] == "t1"
