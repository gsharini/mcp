# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 3.1.0

Hosted OAuth moves onto the shared `oracle-mcp-common` authentication path. The
server no longer configures OAuth providers or builds token-exchange signers
itself, which removes four local settings and requires one new one.

### Breaking Changes

- **Hosted `oauth` authentication now goes through `oracle-mcp-common` end to
  end.** Each tenancy's provider is built by
  `oracle_mcp_common.build_idcs_http_auth()`, and every request's OCI signer comes
  from that tenancy's `IDCSHttpAuth.context_for()`. 3.0.0 used the shared library
  only for `apikey`/`session` credential resolution and configured its own OAuth
  providers and `TokenExchangeSigner`s; those local paths are gone.
- **Tenancy registry entries now require `audience`.** Each entry must carry the
  primary audience of that tenancy's IAM resource application (single-tenant
  fallback: `ORACLE_MCP_IDCS_AUDIENCE`). Access tokens are now verified against
  this `aud` claim and the value is sent to `/authorize` and `/token`, so it must
  match the IAM domain's configuration or sign-in for that tenancy fails.
- **Registry `jwt_signing_key` and `ORACLE_MCP_JWT_SIGNING_KEY` removed.** FastMCP
  derives each tenancy's token-signing key from that tenancy's `client_secret`, so
  it is stable across restarts and workers and distinct per tenancy without being
  configured. A registry entry that still sets `jwt_signing_key` fails startup
  rather than having the value silently ignored. Rotating a `client_secret` now
  also invalidates that tenancy's issued tokens.
- **`ORACLE_MCP_OAUTH_STORAGE_DIR` removed.** Per-tenancy OAuth state now lives
  under FastMCP's home directory (`~/.fastmcp/oauth-proxy/`, relocatable with
  `FASTMCP_HOME`), encrypted at rest, in a per-tenancy directory. Deployments that
  mounted the old `.oauth_state` directory must persist the new location instead;
  an ephemeral home directory forces clients to re-register after a restart.
  `FASTMCP_HOME` is resolved when FastMCP is imported, before the server reads its
  env file, so it must be exported rather than set in that file.
- **`ORACLE_MCP_OAUTH_REQUIRE_CONSENT` removed and consent is now on.** The first
  authorization for a tenancy shows a consent screen; later tool calls reuse the
  granted session.
- **`ORACLE_MCP_OAUTH_REDIRECT_PATH` removed.** The callback path is `/auth/callback`
  under each tenancy's mount, so the registered redirect URI
  `<base_url>/t/<alias>/auth/callback` is unchanged.

### Added

- **New `diagnose_recovery_service_issue` guidance tool.** Returns an
  evidence-driven, access-first diagnostic workflow for investigating Oracle
  Database backup, protection, and recoverability problems in a Recovery Service
  environment. Like the other guidance tools, it exposes the prompt text as an
  ordinary tool so clients without prompt support can call it.

### Changed

- **CIMD client registration is disabled.** FastMCP enables Client ID Metadata
  Documents by default, which lets a client send an HTTPS URL as its `client_id`
  and requires this server to fetch that URL to learn the client's metadata. That
  fetch is an outbound internet request made with pinned DNS and redirects
  disabled, so it fails on a host with no egress, and also on one whose egress is
  a CONNECT proxy. The failure reached the user as "The client ID ... was not
  found in the server's client registry" at `/authorize`, which reads like a
  client bug. Clients now register with DCR against `/t/<alias>/register`, which
  never leaves the host. Startup fails loudly if a future FastMCP release renames
  the private attribute this relies on.

### Fixed

- **Sign-in failed with `invalid_scope` because resource scopes were sent to IDCS
  unqualified.** IDCS names a resource application's scopes by concatenating the
  application's primary audience with the scope name, and `/authorize` accepts
  only that form, so `oci_mcp.recovery.invoke` was rejected and no tenancy could
  complete a login. The access token IDCS issues carries the scope *bare*,
  though, and that token is re-validated on every request — so qualifying the
  configured value instead simply moved the failure to `401 invalid_token` on
  the first tool call. `ORACLE_MCP_OAUTH_SCOPES` is now bare, as verification
  requires, and each tenancy's provider qualifies the resource scopes it
  advertises to clients with that tenancy's own audience — in DCR defaults and
  in protected-resource metadata alike, since a client requests whatever it is
  told is supported and the proxy refuses an authorize request carrying anything
  else. Startup fails loudly if a future FastMCP release drops the method this
  relies on.
- **Sign-in still failed with `invalid_scope` for clients that omit `scope`.**
  Qualifying the scopes a client is *told* about only helps a client that asks
  for them. `/authorize` may arrive with no `scope` parameter at all, and the
  proxy then falls back to its own `required_scopes` — which stayed bare, so the
  upstream request carried an unqualified resource scope and IDCS rejected it.
  A third path had the same gap: the refresh request is built from the scopes
  stored on the refresh token, and those were parsed bare out of the IDCS token
  response, so a session would have died at its first refresh an hour after a
  sign-in that looked completely successful. Both fallbacks are now qualified
  with the tenancy's audience, alongside the advertised scopes. Verification is
  unaffected — it compares against the token verifier's own bare scopes — and
  startup now refuses any provider that verifies the id_token, since that mode
  makes `required_scopes` the enforcement point as well and the two uses need
  opposite forms.
- **OAuth discovery required a header no client can send there.** Protected-resource
  metadata is fetched before any MCP session exists, and `X-OCI-Tenancy` rides only
  on requests to the MCP URL itself, so discovery always arrived without it and was
  answered with `tenancy_required`. Clients then retried root well-known paths this
  server does not serve, and the resulting `404 Not Found` body reached the user as
  an unparseable OAuth error. When exactly one tenancy is configured there is nothing
  to disambiguate, so discovery is now answered for it. An unknown tenancy name is
  still rejected, and a multi-tenancy registry still requires the header.
- **Compartment cache could serve one caller's compartments to another.** The
  compartment listing is fetched with `access_level="ACCESSIBLE"`, so it contains
  exactly what the calling identity may see, but it was cached per tenancy only. In
  the hosted multi-tenant deployment two users of the same tenancy shared that
  entry, so a broadly-permissioned user's compartment tree could be served to a
  restricted one. The cache is now keyed by tenancy **and** caller identity; in
  `session`/`apikey` mode, where the whole process shares one credential, the key is
  unchanged.
- Per-tenancy OAuth providers now derive their protected-resource URL from the
  server's public base URL rather than their own `/t/<alias>` mount, so the resource
  indicator a client sends is the one the provider validates and the one the tokens
  it issues are bound to. Tokens issued by 3.0.0 carry the old audience and are
  rejected; affected clients sign in again.
- **Multi-tenant OAuth discovery is no longer cacheable across tenancies.** The
  single `/.well-known/oauth-protected-resource/mcp` endpoint selects its answer
  from the `X-OCI-Tenancy` request header but declared no `Vary` and no cache
  directives, so a shared cache could serve one tenancy the authorization server
  of another. Every response from that endpoint -- including the `400` and the
  CORS preflight -- now carries `Vary: X-OCI-Tenancy`, `Cache-Control: no-store,
  private`, and `Pragma: no-cache`.

## 3.0.0

### Breaking Changes

- **Hosted OAuth requires explicit configuration.** `ORACLE_MCP_AUTH_METHOD=oauth`
  now requires either `ORACLE_MCP_TENANCY_REGISTRY` (a `tenancies.toml` file) or
  the legacy single-tenant `ORACLE_MCP_IDCS_*`/`ORACLE_MCP_TENANCY_ID`/`ORACLE_MCP_REGION`
  env vars, **and** an absolute `https://` `ORACLE_MCP_BASE_URL`. A missing or
  plain-HTTP base URL now fails startup instead of silently advertising
  `http://localhost:8000` authorization/callback URLs. Set
  `ORACLE_MCP_OAUTH_ALLOW_INSECURE_LOCAL=true` to keep using an
  `http://localhost` base URL for local development.
- **Default OAuth scopes include `oci_mcp.recovery.invoke` again.** Deployments
  that pin `ORACLE_MCP_OAUTH_SCOPES` explicitly must add `oci_mcp.recovery.invoke`
  back to that list themselves, or authenticated-but-unentitled identities will
  regain access to Recovery tools.
- **`ORACLE_MCP_HOST`/`ORACLE_MCP_PORT` (plain HTTP) no longer work with
  `session`/`apikey` auth.** Those auth methods carry the operator's own OCI
  credentials and have no per-caller authentication story, so they now only run
  over stdio; setting host/port without `ORACLE_MCP_AUTH_METHOD=oauth` is a
  startup error. Use `oauth` mode for any HTTP-reachable deployment.
- **Per-tenant OAuth callback route** moved to `/t/<alias>/auth/callback`
  (previously a single `/auth/callback`), to support the multi-tenant hosted
  model. Update any registered IAM confidential-application redirect URIs.
- **New `oracle-mcp-common` dependency.** `apikey`/`session` credential
  resolution now goes through `oracle_mcp_common.build_auth_context()` instead
  of server-local profile/signer code; no functional change to supported
  profile configurations.
- OAuth-mode UPST signers are no longer cached process-wide; a fresh signer is
  built for every tool call from the caller's own request-scoped token.

### Added

- Multi-tenant OAuth (`ORACLE_MCP_AUTH_METHOD=oauth`): one hosted server can now
  serve multiple tenancies behind a single MCP URL, selected via the
  `X-OCI-Tenancy` header.
- `onboard_database_to_recovery_service` guidance tool for non-destructive Cloud
  Protect onboarding assistance, bringing the tool count to 24.
- `list_protected_databases` now reports retention-lock status and
  Cloud-Protect-managed vs. Database-Service-managed classification.
- `.env` file support (`ORACLE_MCP_ENV_FILE`) so local configuration can live in
  one file instead of exported environment variables.

### Changed

- Updated dependency locks for FastMCP 3.4.5, OCI SDK 2.182.1, and Pydantic
  2.13.4.
- README now documents all supported environment variables and the tenancy
  registry format inline.

### Fixed

- Tenancy and region lookups now read the same OCI config file the credentials
  were resolved from. The OCI SDK only falls back to `OCI_CONFIG_FILE` when
  `~/.oci/config` is absent, so with both present these lookups could resolve a
  different profile than the request signer.
## 2.1.2

### Changed

- Excluded development artifacts, local configuration, and container build files from source-distribution packages.

## 2.1.1

### Changed

- Updated dependency locks for FastMCP 3.4.5, OCI SDK 2.182.1, and refreshed authentication-related transitive packages.

## 2.1.0

### Added

- Added `list_restore` for retrieving database restore work requests, with filters, paging, and optional child-compartment aggregation.
- Added `check_recovery_service_limits` to report available protected-database backup storage and protected-database-count limits.
- Added `fetch_regions_subscribed` to list the tenancy's subscribed regions and their statuses.

### Changed

- Updated dependency locks for FastMCP 3.4.2, OCI SDK 2.179.0, and refreshed authentication-related transitive packages.
- Added optional child-compartment aggregation to existing compartment-scoped list and summary tools.
- Improved response models with explicit optional-field defaults and descriptions, including the new `WorkRequest` restore-job model.

## 2.0.0

### Breaking Changes

- HTTP transport now requires OCI IAM/IDCS authentication and no longer uses local OCI CLI profile credentials for request authentication.
- HTTP deployments must set `ORACLE_MCP_BASE_URL`, `OCI_REGION`, `IDCS_DOMAIN`, `IDCS_CLIENT_ID`, `IDCS_CLIENT_SECRET`, and `IDCS_AUDIENCE`, and register `${ORACLE_MCP_BASE_URL}/auth/callback`.
- The default required scopes are `openid profile email oci_mcp.recovery.invoke`; set `IDCS_REQUIRED_SCOPES` to override.