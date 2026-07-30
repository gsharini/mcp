"""
Copyright (c) 2025, Oracle and/or its affiliates.
Licensed under the Universal Permissive License v1.0 as shown at
https://oss.oracle.com/licenses/upl.
"""

# Multi-tenant OCI IAM (IDCS) OAuth provider for the single-hosted deployment.
#
# One process serves many tenancies behind a single MCP URL (https://host/mcp).
# A user selects their tenancy with the `X-OCI-Tenancy` HTTP header (alias or OCID).
#
# How it works
# ------------
# FastMCP binds ONE auth provider per server and mounts its routes once. We build
# one self-contained `OCIProvider` per tenancy (each is an OIDC proxy to that
# tenancy's IDCS) and compose them under one app:
#
#   * Operational OAuth routes for each tenancy are mounted under /t/<alias>/...
#     (/authorize, /token, /register, /auth/callback, /consent), so the upstream
#     redirect URL is https://host/t/<alias>/auth/callback.
#   * Each tenancy's authorization-server metadata is served (path-aware, per
#     RFC 8414) at /.well-known/oauth-authorization-server/t/<alias>.
#   * A single protected-resource metadata endpoint (/.well-known/oauth-protected-
#     resource/mcp) reads the X-OCI-Tenancy header and points the client at that
#     tenancy's authorization server, so the browser login auto-routes. If the
#     header is missing/unknown it returns an actionable 400 listing valid aliases.
#   * Token verification tries each tenancy's verifier; the one whose signing key
#     matches wins (verification never trusts the header). The verified token is
#     stamped with the `oracle_mcp_tenant_alias` claim so tool routing is bound to
#     the proven identity, not a mutable request header.
#
# Per-tenancy isolation (matching the old one-process-per-tenancy deployment):
#   * a dedicated DiskStore for OAuth state under <storage_root>/<alias>/oauth
#   * a dedicated JWT signing key (from the registry, else generated + persisted
#     atomically with 0600 perms under <storage_root>/<alias>/signing.key)

from __future__ import annotations

import os
import secrets
from typing import Optional
from urllib.parse import urlparse

from mcp.server.auth.routes import build_resource_metadata_url, cors_middleware
from pydantic import AnyHttpUrl
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Mount, Route

from fastmcp.server.auth.auth import AccessToken, AuthProvider
from fastmcp.utilities.logging import get_logger

from .tenancy_registry import TenancyRegistry

logger = get_logger(__name__)

TENANT_CLAIM = "oracle_mcp_tenant_alias"


def _domain_to_url(domain: str) -> str:
    """Normalize an IAM domain host or URL into an https base URL (no trailing slash).

    HTTPS-only: the IAM domain carries the OAuth/token-exchange flows, so an explicit
    http:// scheme is rejected rather than silently used.
    """
    d = (domain or "").strip()
    if d.startswith("http://"):
        raise ValueError(
            f"idcs_domain must use https, not http: {d!r}. Use the bare host "
            "(idcs-xxxx.identity.oraclecloud.com) or an https:// URL."
        )
    if d.startswith("https://"):
        return d.rstrip("/")
    return f"https://{d}"


def load_or_create_signing_key(storage_root: str, alias: str) -> bytes:
    """Return a stable 32-byte signing key for a tenancy, persisted on disk.

    The key is created exactly once (O_CREAT|O_EXCL, mode 0600) and never
    overwritten, so restarts don't invalidate already-issued tokens and a race
    between workers can't clobber an existing key.
    """
    key_dir = os.path.join(storage_root, alias)
    os.makedirs(key_dir, exist_ok=True)
    key_path = os.path.join(key_dir, "signing.key")
    if not os.path.exists(key_path):
        try:
            fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.fchmod(fd, 0o600)  # guarantee perms regardless of umask
                os.write(fd, secrets.token_bytes(32))
            finally:
                os.close(fd)
        except FileExistsError:
            pass  # another worker created it first; read theirs below
    with open(key_path, "rb") as f:
        return f.read()


class MultiTenantOCIAuth(AuthProvider):
    """Compose one OCIProvider per tenancy behind a single MCP URL, header-routed."""

    def __init__(
        self,
        registry: TenancyRegistry,
        *,
        base_url: str,
        storage_root: str,
        required_scopes: Optional[list[str]] = None,
        require_authorization_consent: bool = False,
        redirect_path: str = "/auth/callback",
    ):
        super().__init__(base_url=base_url, required_scopes=required_scopes or ["openid"])
        self._registry = registry
        self._root = str(self.base_url).rstrip("/")
        self._storage_root = storage_root
        self._require_consent = require_authorization_consent
        self._redirect_path = redirect_path
        self._real_resource: Optional[AnyHttpUrl] = None

        os.makedirs(storage_root, exist_ok=True)
        self._providers = {e.alias: self._build_provider(e) for e in registry.entries}
        logger.info(
            "Multi-tenant OCI OAuth initialized for %d tenancies: %s",
            len(self._providers),
            ", ".join(sorted(self._providers)),
        )

    # -- construction ---------------------------------------------------------

    def _build_provider(self, entry):
        from fastmcp.server.auth.providers.oci import OCIProvider
        from key_value.aio.stores.disk import DiskStore

        alias = entry.alias
        storage_dir = os.path.join(self._storage_root, alias, "oauth")
        os.makedirs(storage_dir, exist_ok=True)
        signing_key = entry.jwt_signing_key or load_or_create_signing_key(
            self._storage_root, alias
        )
        domain_url = _domain_to_url(entry.idcs_domain)
        return OCIProvider(
            config_url=f"{domain_url}/.well-known/openid-configuration",
            client_id=entry.client_id,
            client_secret=entry.client_secret,
            base_url=f"{self._root}/t/{alias}",
            redirect_path=self._redirect_path,
            required_scopes=list(self.required_scopes),
            require_authorization_consent=self._require_consent,
            jwt_signing_key=signing_key,
            client_storage=DiskStore(directory=storage_dir),
        )

    # -- token verification (token-authoritative tenant binding) --------------

    async def verify_token(self, token: str) -> Optional[AccessToken]:
        """Verify the bearer token and stamp the proven tenant alias as a claim.

        The X-OCI-Tenancy header drives which tenancy may verify the token:
          * known tenancy  -> only that provider may verify (a token for a
            *different* tenancy then fails -> 401 -> client re-authenticates for
            the requested tenancy, instead of being silently served the old one);
          * present but unknown (e.g. a typo or a decommissioned alias) -> reject
            (-> 401), mirroring the `tenancy_required` behavior at OAuth discovery,
            so a stale cached token can't quietly authenticate under the wrong name;
          * absent -> fall back to trying every provider (the token itself is proof
            of a prior valid login).
        Security is unchanged in all cases: a token is only ever accepted for the
        tenancy whose signing key actually verifies it.
        """
        candidates = list(self._providers.items())

        try:
            from fastmcp.server.dependencies import get_http_headers

            hint = (get_http_headers() or {}).get("x-oci-tenancy")
        except Exception:
            hint = None
        hint = hint.strip() if hint else ""

        if hint:
            hinted = self._registry.lookup(hint)
            if hinted is None or hinted.alias not in self._providers:
                logger.info(
                    "Bearer auth rejected: X-OCI-Tenancy header names an unknown tenancy."
                )
                return None
            candidates = [(hinted.alias, self._providers[hinted.alias])]

        for alias, provider in candidates:
            try:
                validated = await provider.load_access_token(token)
            except Exception:
                validated = None
            if validated is not None:
                claims = {**(validated.claims or {}), TENANT_CLAIM: alias}
                return validated.model_copy(update={"claims": claims})
        return None

    # -- routes ---------------------------------------------------------------

    def get_routes(self, mcp_path: Optional[str] = None) -> list:
        self._real_resource = self._get_resource_url(mcp_path)
        routes: list = []

        for alias, provider in self._providers.items():
            all_routes = provider.get_routes(mcp_path=mcp_path)

            # Path-aware authorization-server metadata stays at the root level.
            for wk in provider.get_well_known_routes(mcp_path=mcp_path):
                if isinstance(wk, Route) and "oauth-authorization-server" in wk.path:
                    routes.append(wk)

            # Operational routes (/authorize, /token, /register, /auth/callback,
            # /consent) get mounted under /t/<alias>/... so their advertised URLs
            # resolve. (get_routes also emits a per-provider protected-resource
            # route pointing at /t/<alias>/mcp which we intentionally drop in
            # favor of the single header-aware endpoint below.)
            op = [
                r
                for r in all_routes
                if isinstance(r, Route) and not r.path.startswith("/.well-known/")
            ]
            routes.append(Mount(f"/t/{alias}", routes=op))

            # The real protected resource is the single /mcp endpoint, not
            # /t/<alias>/mcp; fix it so OCIProvider.authorize()'s resource check
            # accepts the client's resource indicator.
            provider._resource_url = self._real_resource

        # Single, header-aware protected-resource metadata (RFC 9728).
        pr_path = urlparse(str(build_resource_metadata_url(self._real_resource))).path
        routes.append(
            Route(
                pr_path,
                endpoint=cors_middleware(self._protected_resource_metadata, ["GET", "OPTIONS"]),
                methods=["GET", "OPTIONS"],
            )
        )

        # Human-facing helper page (lists tenancy aliases; no secrets).
        routes.append(Route("/tenancies", endpoint=self._tenancies_page, methods=["GET"]))
        return routes

    # -- handlers -------------------------------------------------------------

    async def _protected_resource_metadata(self, request: Request) -> Response:
        if request.method == "OPTIONS":
            return Response(status_code=204)

        hint = request.headers.get("x-oci-tenancy")
        entry = self._registry.lookup(hint)
        if entry is None:
            # No usable tenancy: tell the client exactly what to set (aliases only).
            logger.info(
                "protected-resource discovery without a valid X-OCI-Tenancy header "
                "(value present=%s); returning tenancy_required",
                bool(hint),
            )
            return JSONResponse(
                {
                    "error": "tenancy_required",
                    "error_description": (
                        "Set the 'X-OCI-Tenancy' header (tenancy OCID or alias) to one of: "
                        + ", ".join(sorted(self._registry.aliases))
                    ),
                    "valid_tenancies": sorted(self._registry.aliases),
                },
                status_code=400,
            )

        return JSONResponse(
            {
                "resource": str(self._real_resource),
                "authorization_servers": [f"{self._root}/t/{entry.alias}"],
                "scopes_supported": list(self.required_scopes),
                "bearer_methods_supported": ["header"],
            }
        )

    async def _tenancies_page(self, request: Request) -> HTMLResponse:
        rows = "".join(f"<li><code>{a}</code></li>" for a in sorted(self._registry.aliases))
        html = (
            "<!doctype html><html><head><meta charset='utf-8'>"
            "<title>OCI Recovery MCP - tenancies</title></head><body>"
            "<h2>OCI Recovery MCP server</h2>"
            "<p>This is a multi-tenancy MCP server. In your MCP client config, set the "
            "<code>X-OCI-Tenancy</code> header to your tenancy OCID or one of these aliases:</p>"
            f"<ul>{rows}</ul>"
            "</body></html>"
        )
        return HTMLResponse(html)
