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
#     One URL answering differently per header is only safe if nothing caches it
#     under the URL alone, so every response from it is marked Vary + no-store
#     (see _NO_SHARED_CACHE).
#   * Token verification tries each tenancy's verifier; the one whose signing key
#     matches wins (verification never trusts the header). The verified token is
#     stamped with the `oracle_mcp_tenant_alias` claim so tool routing is bound to
#     the proven identity, not a mutable request header.
#
# Authentication itself is not implemented here. Each tenancy's provider and
# request-scoped OCI credentials come from oracle-mcp-common's
# build_idcs_http_auth() / IDCSHttpAuth.context_for(); this module only decides
# which tenancy a request belongs to and composes the per-tenancy routes.
#
# Per-tenancy isolation (matching the old one-process-per-tenancy deployment) is
# preserved by the shared builder rather than configured here: FastMCP derives both
# the token signing key and the encrypted OAuth-state directory from the upstream
# client secret, which differs per tenancy, so no tenancy can read another's state
# and keys stay stable across restarts and workers.

from __future__ import annotations

from typing import Optional
from urllib.parse import urlparse

from mcp.server.auth.routes import build_resource_metadata_url, cors_middleware
from oracle_mcp_common import IDCSHttpAuth, IDCSHttpAuthOptions, build_idcs_http_auth
from pydantic import AnyHttpUrl
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Mount, Route

from fastmcp.server.auth.auth import AccessToken, AuthProvider
from fastmcp.utilities.logging import get_logger

from .tenancy_registry import RegistryError, TenancyEntry, TenancyRegistry

logger = get_logger(__name__)

TENANT_CLAIM = "oracle_mcp_tenant_alias"

# The name of the routing header, in one place: it is read on two paths (OAuth
# discovery and token verification) and must be declared to caches on the first.
TENANCY_HEADER = "X-OCI-Tenancy"

# Protected-resource metadata is one URL whose body is chosen by a request header,
# which makes an unqualified cache entry a cross-tenancy fault: the second caller
# is handed the first caller's authorization server and is walked through login
# against a tenancy that is not theirs. No token is forged that way -- verification
# still only accepts a token the tenancy's own signing key validates -- but the
# user lands in the wrong place with an unexplainable error, or authenticates
# somewhere they did not intend to.
#
# `Vary` states the dependency for caches that honor it. `no-store` and `private`
# cover the ones that cannot: an intermediary that strips or never forwards an
# unknown request header has no way to key on it correctly no matter what `Vary`
# says. Nothing is lost by refusing storage -- the body is a few hundred bytes and
# a client fetches it once per session -- and `Pragma` is the HTTP/1.0 spelling,
# sent for the same reason RFC 6749 sends it on the token endpoint.
_NO_SHARED_CACHE = {
    "Vary": TENANCY_HEADER,
    "Cache-Control": "no-store, private",
    "Pragma": "no-cache",
}

# Scopes IDCS defines itself, which are never namespaced by a resource application.
# Everything else in ORACLE_MCP_OAUTH_SCOPES belongs to this server's resource
# application and must be qualified with that application's primary audience.
_IDCS_RESERVED_SCOPES = frozenset(
    {"openid", "profile", "email", "address", "phone", "groups", "offline_access"}
)


def _qualify(audience: str, scopes: list[str]) -> list[str]:
    """Name each resource scope the way IDCS does: audience + scope, no separator."""
    return [
        s if (s in _IDCS_RESERVED_SCOPES or "://" in s) else f"{audience}{s}"
        for s in scopes
    ]


def _qualify_upstream_scopes(
    provider, *, alias: str, audience: str, scopes: list[str]
) -> list[str]:
    """Request resource scopes from IDCS in the fully-qualified form it requires.

    IDCS names a resource application's scopes by concatenating the application's
    primary audience with the scope, without a separator -- the `fqs` value that
    onboard.sh grants to the confidential client. `/authorize` only recognizes that
    form, so a bare `oci_mcp.recovery.invoke` is rejected with `invalid_scope` and
    sign-in never completes.

    The access token IDCS issues, however, carries the scope *bare* in its `scope`
    claim, with the audience in `aud`. That token is what gets re-validated on every
    request (OAuthProxy.load_access_token swaps the FastMCP JWT for it), and the
    verifier requires `required_scopes` to be a subset of that claim. So the same
    setting is needed in two incompatible forms: qualified going out, bare coming
    back. Configuring either one alone breaks the other half of the flow.

    We therefore keep `required_scopes` bare -- it is what verification and the
    bearer-scope check compare against -- and qualify only the scopes advertised to
    clients, which is what a client requests and what the upstream authorize URL is
    built from. Reserved OIDC scopes and anything already absolute are left alone.

    Returns the qualified list so every surface that advertises scopes to clients
    can use it. All of them must agree: a client takes the scopes it requests from
    what we advertise, and the proxy rejects an authorize request whose scopes are
    not in this list ("Requested scopes are not valid").

    Three separate places build an upstream request, and each reads the scopes from
    somewhere different, so all three have to be qualified:

      * `update_default_scopes` covers DCR registration defaults, `valid_scopes`,
        and the metadata clients read to decide what to request.
      * `required_scopes` on the *proxy* is what `_build_upstream_authorize_url`
        falls back to when the client sends no `scope` parameter at all -- which
        clients do, and which no amount of correct advertising prevents. Leaving it
        bare sends `oci_mcp.recovery.invoke` to /authorize and fails sign-in with
        `invalid_scope`. This is safe to overwrite because the proxy's own
        `required_scopes` is read *only* there; scope verification compares against
        `token_verifier.required_scopes`, a different object that stays bare.
      * `_prepare_scopes_for_upstream_refresh` builds the refresh request from the
        scopes stored on the refresh token, and those were parsed from the IDCS
        token response -- so they are bare. Left alone, sign-in succeeds and then
        the session dies at the first refresh, an hour later, with the same
        `invalid_scope` far from any change that would explain it.

    FastMCP's own AzureProvider solves the same audience-qualification problem the
    same way, which is why these are the hooks that exist to override.
    """
    for attr in (
        "update_default_scopes",
        "required_scopes",
        "_prepare_scopes_for_upstream_refresh",
    ):
        if not hasattr(provider, attr):
            raise RegistryError(
                f"Registry entry [{alias}] cannot be used for OAuth: this FastMCP release "
                f"does not expose '{attr}', so this tenancy's resource scopes cannot be "
                "qualified with its audience and IDCS would reject sign-in with "
                "'invalid_scope'."
            )

    if getattr(provider, "_verify_id_token", False) is True:
        # OIDCProxy strips scopes off the verifier when it validates the id_token
        # instead of the access token, and moves enforcement onto the provider's
        # own required_scopes -- the field qualified just below. Under that mode
        # the two uses collide again and qualifying would reject every request,
        # so refuse rather than reintroduce the 401 loop silently.
        raise RegistryError(
            f"Registry entry [{alias}] cannot be used for OAuth: its provider verifies "
            "the id_token, which makes 'required_scopes' the scope-enforcement point as "
            "well as the upstream authorize fallback. Those need opposite forms, so the "
            "resource scopes cannot be qualified safely."
        )

    qualified = _qualify(audience, scopes)
    provider.update_default_scopes(qualified)
    provider.required_scopes = qualified
    # Bound per tenancy: the audience is this entry's, never another's. Falls back
    # to the configured scopes when a refresh token carries none, mirroring what
    # the authorize path does with an empty transaction.
    provider._prepare_scopes_for_upstream_refresh = (
        lambda stored, _aud=audience, _default=qualified: _qualify(
            _aud, list(stored) or list(_default)
        )
    )
    return qualified


def _disable_cimd(provider, *, alias: str) -> None:
    """Turn off CIMD client registration on one tenancy's provider.

    CIMD (Client ID Metadata Document) lets a client present an HTTPS URL as its
    `client_id`, which the server then fetches to learn that client's metadata.
    FastMCP enables it by default, but the fetch is an outbound internet request
    made from this process with pinned DNS and redirects disabled -- so it fails
    on exactly the deployment this server is built for: a VM reachable only over
    a VPN, whose egress is either absent or through a CONNECT proxy that a
    pinned-DNS request cannot traverse. The failure surfaces to the user as
    "The client ID ... was not found in the server's client registry", which
    reads like a client bug rather than the network problem it is.

    Clearing the manager both stops that lookup and stops advertising
    `client_id_metadata_document_supported` in the authorization-server
    metadata, so clients register with DCR against /t/<alias>/register instead --
    an exchange that never leaves this host and works on every deployment.

    `_cimd_manager` is private FastMCP API and there is no public alternative:
    OCIProvider does not forward `enable_cimd` to the underlying proxy. The
    attribute is therefore checked rather than assumed, so an upstream rename
    fails at startup instead of silently restoring the outbound fetch.
    """
    if not hasattr(provider, "_cimd_manager"):
        raise RegistryError(
            f"Registry entry [{alias}] cannot be used for OAuth: this FastMCP release "
            "does not expose '_cimd_manager', so CIMD client registration cannot be "
            "disabled and client registration would depend on this host being able to "
            "fetch the client's metadata URL. Check whether OCIProvider now accepts "
            "enable_cimd=False and use that instead."
        )
    provider._cimd_manager = None


class MultiTenantOCIAuth(AuthProvider):
    """Compose one OCIProvider per tenancy behind a single MCP URL, header-routed."""

    def __init__(
        self,
        registry: TenancyRegistry,
        *,
        base_url: str,
        required_scopes: Optional[list[str]] = None,
    ):
        super().__init__(base_url=base_url, required_scopes=required_scopes or ["openid"])
        self._registry = registry
        self._root = str(self.base_url).rstrip("/")
        self._real_resource: Optional[AnyHttpUrl] = None
        # Per-tenancy client-facing scopes, qualified with that tenancy's audience.
        # Populated by _build_http_auth; see _qualify_upstream_scopes.
        self._client_scopes: dict[str, list[str]] = {}

        self._http_auth = {e.alias: self._build_http_auth(e) for e in registry.entries}
        self._providers = {alias: h.provider for alias, h in self._http_auth.items()}
        logger.info(
            "Multi-tenant OCI OAuth initialized for %d tenancies: %s",
            len(self._providers),
            ", ".join(sorted(self._providers)),
        )

    # -- construction ---------------------------------------------------------

    def _build_http_auth(self, entry: TenancyEntry) -> IDCSHttpAuth:
        """Build one tenancy's shared IDCS HTTP auth via oracle-mcp-common.

        Every authentication input is passed explicitly per tenancy, so the shared
        builder never falls back to a process-wide IDCS_* environment variable and
        one tenancy's domain, client, or audience can never be applied to another.
        `base_url` is this tenancy's own mount, which is what makes the resulting
        provider advertise (and accept) /t/<alias>/authorize and
        /t/<alias>/auth/callback.

        The token signing key and the encrypted OAuth-state directory are derived by
        FastMCP from this tenancy's client secret, and consent and the /auth/callback
        redirect path take the shared library's defaults. Two things the shared
        builder cannot express are then applied to the provider: CIMD is turned off,
        and this tenancy's resource scopes are qualified with its own audience.
        """
        alias = entry.alias
        try:
            http_auth = build_idcs_http_auth(
                list(self.required_scopes),
                IDCSHttpAuthOptions(
                    domain=entry.idcs_domain,
                    client_id=entry.client_id,
                    client_secret=entry.client_secret,
                    audience=entry.audience,
                    base_url=f"{self._root}/t/{alias}",
                    region=entry.region,
                ),
            )
        except ValueError as e:
            # Name the tenancy: with many entries the shared message alone doesn't
            # say which registry table is at fault.
            raise RegistryError(f"Registry entry [{alias}] cannot be used for OAuth: {e}") from e

        _disable_cimd(http_auth.provider, alias=alias)
        self._client_scopes[alias] = _qualify_upstream_scopes(
            http_auth.provider,
            alias=alias,
            audience=entry.audience,
            scopes=list(self.required_scopes),
        )
        return http_auth

    def http_auth_for(self, alias: Optional[str]) -> Optional[IDCSHttpAuth]:
        """Return a tenancy's shared IDCS HTTP auth policy (None if unknown).

        Callers exchange the current request's access token through
        IDCSHttpAuth.context_for(); the returned signer is request-scoped and must
        never be cached. Only the policy itself -- provider plus this tenancy's own
        server-side credentials -- is long-lived, exactly like the provider it wraps.
        """
        return self._http_auth.get(alias) if alias else None

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

            hint = (get_http_headers() or {}).get(TENANCY_HEADER.lower())
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
            # Every tenancy protects the same single resource, the /mcp endpoint --
            # not /t/<alias>/mcp, which is only where that tenancy's OAuth routes are
            # mounted. Declaring it before get_routes() lets the provider derive its
            # own resource URL (and the audience of the tokens it issues) from it,
            # so the resource indicator a client sends is the one it validates.
            provider.resource_base_url = self.base_url

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
        """Answer discovery for the tenancy named by the header, uncacheably.

        Which tenancy this describes -- and whether it describes one at all -- is
        decided by a request header, so every exit from this handler must carry
        _NO_SHARED_CACHE. That includes the 400 and the OPTIONS reply: a stored
        "no valid tenancy" answer is as wrong for the next caller as a stored
        answer naming the wrong one.
        """
        if request.method == "OPTIONS":
            return Response(status_code=204, headers=_NO_SHARED_CACHE)

        hint = request.headers.get(TENANCY_HEADER)
        entry = self._registry.lookup(hint)

        if entry is None and not hint and len(self._registry) == 1:
            # OAuth discovery carries no custom headers: a client fetches
            # /.well-known/... before it has any MCP session, and X-OCI-Tenancy
            # rides only on requests to the MCP URL itself. Demanding the header
            # here makes discovery unanswerable, and clients respond by falling
            # back to root well-known paths this server does not serve -- a 404
            # that surfaces as an unparseable OAuth error rather than as the
            # missing-tenancy problem it is.
            #
            # With exactly one tenancy configured there is nothing to disambiguate,
            # so answer for it. This grants no access on its own: the token is
            # still only accepted by the tenancy whose signing key verifies it.
            # With several tenancies the request stays ambiguous and is rejected
            # below; such a deployment needs clients that can reach a per-tenancy
            # URL, not a guess about which tenancy was meant.
            entry = self._registry.entries[0]
            logger.info(
                "protected-resource discovery without X-OCI-Tenancy; answering for the "
                "only configured tenancy [%s]",
                entry.alias,
            )

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
                        f"Set the '{TENANCY_HEADER}' header (tenancy OCID or alias) to one of: "
                        + ", ".join(sorted(self._registry.aliases))
                    ),
                    "valid_tenancies": sorted(self._registry.aliases),
                },
                status_code=400,
                headers=_NO_SHARED_CACHE,
            )

        return JSONResponse(
            {
                "resource": str(self._real_resource),
                "authorization_servers": [f"{self._root}/t/{entry.alias}"],
                # The qualified form, matching what this tenancy's authorization
                # server will accept: a client requests what we advertise here, and
                # bare resource scopes are rejected at /authorize.
                "scopes_supported": self._client_scopes[entry.alias],
                "bearer_methods_supported": ["header"],
            },
            headers=_NO_SHARED_CACHE,
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
