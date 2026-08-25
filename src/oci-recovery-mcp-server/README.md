# OCI Recovery Service MCP Server

An Oracle Cloud Infrastructure (OCI) Model Context Protocol (MCP) server for read-oriented Autonomous Recovery Service and Database Service operations. It maps OCI SDK responses to Pydantic models suitable for MCP clients.

## What it provides

- Browse protected databases, protection policies, Recovery Service subnets, restore work requests, DB homes, DB systems, databases, and backups.
- Summarize protected-database health, redo-shipping status, backup-space consumption, and backup destinations.
- Query Recovery Service metrics, service limits, and tenancy region subscriptions.
- Aggregate supported list and summary operations across a compartment subtree.
- Provide non-destructive Recovery Service dashboard and Cloud Protect onboarding guidance.
- Run locally with OCI API-key or session-token authentication, or as a hosted single-tenant or multi-tenant HTTP OAuth service.

The server exposes 24 MCP tools. It does not create, update, or delete OCI resources.

## Requirements

- Python 3.13 or later
- [`uv`](https://docs.astral.sh/uv/)
- OCI credentials appropriate to the selected authentication mode

## Install and run locally

From this project directory (`src/oci-recovery-mcp-server`), `uv` resolves and installs
the dependencies into a project virtual environment on first run:

```sh
uv sync
```

Choose an authentication method. Configuration comes from environment variables, which
may also be placed in a `.env` file next to the server.

For a session-token profile, authenticate once and set the corresponding profile:

```dotenv
ORACLE_MCP_AUTH_METHOD=session
ORACLE_MCP_AUTH_PROFILE=DEFAULT
```

```sh
oci session authenticate --profile-name DEFAULT
```

For API-key authentication, use `ORACLE_MCP_AUTH_METHOD=apikey`; the selected OCI profile must contain the normal API-key fields. The `session` and `apikey` methods run over stdio only:

```sh
uv run oracle.oci-recovery-mcp-server
```

The server loads `.env` from the working directory or a parent directory. Set `ORACLE_MCP_ENV_FILE` to use a specific configuration file; explicitly exported variables take precedence.

### Local MCP client configuration (from source)

Configure an MCP client to start the server with `uv`. `--directory` points at this
project so `uv` uses its lockfile and `.env`, and works regardless of the client's own
working directory:

```json
{
  "mcpServers": {
    "oci-recovery-local": {
      "type": "stdio",
      "command": "uv",
      "args": [
        "--directory",
        "/ABS/PATH/mcp/src/oci-recovery-mcp-server",
        "run",
        "oracle.oci-recovery-mcp-server"
      ],
      "env": {
        "ORACLE_MCP_AUTH_METHOD": "session",
        "ORACLE_MCP_AUTH_PROFILE": "DEFAULT"
      }
    }
  }
}
```

If `uv` is not on the MCP client's `PATH` (common for GUI clients that do not load your
shell profile), use its absolute path — `which uv` — as `command`.

### Local MCP client configuration (published PyPI package)

The server is published as
[`oracle.oci-recovery-mcp-server`](https://pypi.org/project/oracle.oci-recovery-mcp-server/).
No clone or checkout is needed: `uvx` downloads the package into a cached, isolated
environment and runs its entry point.

```sh
uvx oracle.oci-recovery-mcp-server
```

To pin a version, use `uvx oracle.oci-recovery-mcp-server@3.1.0`.

```json
{
  "mcpServers": {
    "oci-recovery": {
      "type": "stdio",
      "command": "uvx",
      "args": ["oracle.oci-recovery-mcp-server"],
      "env": {
        "ORACLE_MCP_AUTH_METHOD": "session",
        "ORACLE_MCP_AUTH_PROFILE": "DEFAULT"
      }
    }
  }
}
```

`uvx` runs from the client's working directory, which may not be where your `.env` lives.
Either set the variables in the `env` block above, as shown, or point
`ORACLE_MCP_ENV_FILE` at an absolute path.

Installing the package into a persistent tool environment instead of the `uvx` cache also
works:

```sh
uv tool install oracle.oci-recovery-mcp-server
```

That puts `oracle.oci-recovery-mcp-server` on `PATH`, which can then be used directly as
the client's `command`.

`session` and `apikey` mode cannot be served over a network listener: they carry the
operator's own OCI credentials and have no per-caller authentication. Setting
`ORACLE_MCP_HOST` and `ORACLE_MCP_PORT` in these modes fails startup; both variables are
reserved for `oauth` mode. To expose this server over HTTP, see
[HTTP (Streamable HTTP) deployment](#http-streamable-http-deployment) below.

## HTTP (Streamable HTTP) deployment

Serving this server over HTTP requires `ORACLE_MCP_AUTH_METHOD=oauth`. The `session` and
`apikey` methods carry the operator's own OCI credentials and have no per-caller
authentication, so they run over stdio only; setting `ORACLE_MCP_HOST`/`ORACLE_MCP_PORT`
in those modes fails startup.

In OAuth mode each caller signs in to an OCI IAM (IDCS) domain, and the server exchanges
that caller's access token for caller-specific OCI credentials. Tenancy configuration,
OAuth client secrets, signing keys, and OAuth state all remain server-side.

One process can serve **one tenancy** or **many**. The mechanism is the same in both
cases — the server always builds an internal tenancy registry, keyed by a URL-safe
tenancy alias — the two setups differ only in how that registry is supplied and whether
clients must name their tenancy:

| | Single-tenant | Multi-tenant |
| --- | --- | --- |
| Configuration | Env vars, or a registry file with one table | Registry file with one table per tenancy |
| IAM domains / OAuth apps | One | One per tenancy |
| `X-OCI-Tenancy` client header | Optional | Required |
| MCP URL | `https://MCP_HOST/mcp` | `https://MCP_HOST/mcp` (same URL for all tenancies) |
| OAuth callback | `<base_url>/t/<alias>/auth/callback` | `<base_url>/t/<alias>/auth/callback`, per tenancy |

### Common prerequisites (both modes)

For each tenancy you serve, create in its OCI IAM domain:

1. A **resource application** with a **primary audience** and a scope named
   `oci_mcp.recovery.invoke`.
2. A **confidential application** (client ID + secret) authorized for that resource
   application, with `<base_url>/t/<alias>/auth/callback` registered as a redirect URI.
   `<alias>` is the tenancy alias described below.

The primary audience is both the `aud` claim that issued access tokens are verified
against and the audience requested at `/authorize` and `/token`, so a value that does not
match the domain's configuration makes every sign-in for that tenancy fail.

`ORACLE_MCP_BASE_URL` is required and must be an absolute `https://` URL: authorize,
callback, and well-known URLs are built from it, so a missing or plain-HTTP value fails
startup rather than silently advertising `http://localhost:8000`. Set
`ORACLE_MCP_OAUTH_ALLOW_INSECURE_LOCAL=true` to allow an `http://localhost` base URL for
local development only.

Run the HTTP listener behind a TLS-terminating reverse proxy and bind it to `127.0.0.1`
(the default). `ORACLE_MCP_BASE_URL` must be the public `https://` URL clients reach.

The default `ORACLE_MCP_OAUTH_SCOPES` includes `oci_mcp.recovery.invoke`, which gates
access to this server's Recovery tools beyond a bare authenticated identity. If you
override `ORACLE_MCP_OAUTH_SCOPES`, keep `oci_mcp.recovery.invoke` in the list.

Write those scopes **bare**, not qualified with the audience. IDCS recognizes a resource
scope at `/authorize` only in its fully-qualified form — the audience and the scope name
concatenated without a separator — but returns it bare in the access token it issues, and
that token is re-validated against this setting on every request. The server handles both
forms for you: it keeps the configured value for verification and qualifies each tenancy's
resource scopes with that tenancy's own audience on every path that reaches IDCS — the
scopes advertised to clients, the fallback used when a client sends no `scope` at all, and
token refresh. Qualifying them yourself makes every tool call fail with
`401 invalid_token`.

### Single-tenant HTTP server

Use this when the server front-ends exactly one tenancy. Clients need no custom header:
with one tenancy configured there is nothing to disambiguate, so OAuth discovery is
answered for it.

The simplest configuration is environment variables only — no registry file:

```dotenv
ORACLE_MCP_AUTH_METHOD=oauth
ORACLE_MCP_BASE_URL=https://MCP_HOST
ORACLE_MCP_HOST=127.0.0.1
ORACLE_MCP_PORT=8000

ORACLE_MCP_TENANCY_ID=ocid1.tenancy.oc1..aaaa
ORACLE_MCP_REGION=us-ashburn-1
ORACLE_MCP_IDCS_DOMAIN=idcs-aaaa.identity.oraclecloud.com
ORACLE_MCP_IDCS_CLIENT_ID=REPLACE_ME
ORACLE_MCP_IDCS_CLIENT_SECRET=REPLACE_ME
ORACLE_MCP_IDCS_AUDIENCE=REPLACE_ME
# Optional; defaults to "default". Used in the OAuth callback path.
ORACLE_MCP_TENANCY_ALIAS=default
```

All six of `ORACLE_MCP_TENANCY_ID`, `ORACLE_MCP_REGION`, `ORACLE_MCP_IDCS_DOMAIN`,
`ORACLE_MCP_IDCS_CLIENT_ID`, `ORACLE_MCP_IDCS_CLIENT_SECRET`, and
`ORACLE_MCP_IDCS_AUDIENCE` must be present; the server synthesizes a one-entry registry
from them and fails startup with an actionable message if any is missing. The redirect
URI to register on the confidential application is
`<base_url>/t/<ORACLE_MCP_TENANCY_ALIAS>/auth/callback` — with the default alias, that is
`https://MCP_HOST/t/default/auth/callback`.

Start it:

```sh
uv run oracle.oci-recovery-mcp-server
```

Client configuration needs only the URL:

```json
{
  "mcpServers": {
    "oci-recovery": {
      "type": "streamableHttp",
      "url": "https://MCP_HOST/mcp"
    }
  }
}
```

A single-tenant deployment can equally use a one-table registry file (next section);
setting `ORACLE_MCP_TENANCY_REGISTRY` takes precedence over these environment variables
and makes a later move to multi-tenant a matter of appending tables.

### Multi-tenant HTTP server

Use this when one process serves several tenancies behind one MCP URL. Each tenancy keeps
its own IAM domain, OAuth application, and secrets, and clients select their tenancy with
the `X-OCI-Tenancy` header (tenancy alias or tenancy OCID).

Point `ORACLE_MCP_TENANCY_REGISTRY` at a server-side TOML file with one table per
tenancy. The table name is the tenancy alias: it must be URL-safe (letters, digits, `-`,
`_`), and it appears both in the `X-OCI-Tenancy` header and in that tenancy's OAuth
callback path `<base_url>/t/ALIAS/auth/callback`, which must be registered as a redirect
URI on the corresponding IAM confidential application.

```toml
[TENANCY_NAME]
tenancy_id    = "ocid1.tenancy.oc1..aaaa"
idcs_domain   = "idcs-aaaa.identity.oraclecloud.com"   # host or full https URL
client_id     = "REPLACE_ME"
client_secret = "REPLACE_ME"
audience      = "REPLACE_ME"                           # resource app primary audience
region        = "us-ashburn-1"

[ANOTHER_TENANCY]
tenancy_id    = "ocid1.tenancy.oc1..bbbb"
idcs_domain   = "idcs-bbbb.identity.oraclecloud.com"
client_id     = "REPLACE_ME"
client_secret = "REPLACE_ME"
audience      = "REPLACE_ME"
region        = "eu-frankfurt-1"
```

Every field is required for every tenancy, `audience` is never defaulted from another
tenancy's value, and two tables may not share a `tenancy_id`. The alias `_select` is
reserved.

This file holds OAuth client secrets and must never be committed or served. Restrict it
to the service user (mode `640`).

```dotenv
ORACLE_MCP_AUTH_METHOD=oauth
ORACLE_MCP_BASE_URL=https://MCP_HOST
ORACLE_MCP_HOST=127.0.0.1
ORACLE_MCP_PORT=8000
ORACLE_MCP_TENANCY_REGISTRY=/etc/oci-recovery-mcp/tenancies.toml
```

```sh
uv run oracle.oci-recovery-mcp-server
```

Every tenancy is reached at the same MCP URL; the header selects the sign-in and OCI
request-routing context:

```json
{
  "mcpServers": {
    "oci-recovery": {
      "type": "streamableHttp",
      "url": "https://MCP_HOST/mcp",
      "headers": {
        "X-OCI-Tenancy": "TENANCY_NAME"
      }
    }
  }
}
```

The header is mandatory here. OAuth discovery cannot carry `X-OCI-Tenancy` in every
client — the well-known metadata is fetched before there is an MCP session, and the
header rides only on requests to the MCP URL — so a multi-tenancy registry requires a
client able to send it; without a usable value the discovery endpoint returns a `400
tenancy_required` listing the valid aliases. `GET https://MCP_HOST/tenancies` serves a
plain page listing the configured aliases (no secrets) for users configuring a client.

Token verification never trusts the header: each tenancy's verifier is tried and the one
whose signing key matches wins, and the verified token is stamped with the tenancy it
proved, so tool routing is bound to the proven identity rather than a mutable request
header.

### Operational notes (both modes)

Per-tenancy OAuth state (client registrations and authorization state) is persisted and
encrypted at rest by FastMCP under its home directory, `~/.fastmcp/oauth-proxy/` by
default and relocatable with `FASTMCP_HOME`. The storage directory and the token-signing
key are both derived from each tenancy's client secret, so tenancies stay isolated from
one another and keys survive restarts and multiple workers without being stored in the
registry. Treat that directory as secret material, exclude it from images, and give it
persistent storage in a container deployment — a fresh directory on every restart forces
all clients to re-register. Rotating a tenancy's client secret invalidates its
already-issued tokens, and its clients sign in again.

The first authorization for a tenancy shows a consent screen; subsequent tool calls reuse
the granted session.

Clients register through Dynamic Client Registration at `/t/ALIAS/register`, an exchange
that never leaves the host, so authentication needs no outbound internet access. CIMD
(Client ID Metadata Document) registration is deliberately disabled: it would let a client
present an HTTPS URL as its `client_id` and require this server to fetch that URL, which
fails on a network-restricted host and surfaces as `The client ID ... was not found in the
server's client registry`.

Keep client secrets out of source control; supply them from a secret manager or the
deployment environment.

For a VPN-only deployment whose proxy uses an internal CA, clients must trust that CA's
public root certificate. Distribute only the public root certificate, never the private key.

## Environment variables

| Variable | Modes | Description |
| --- | --- | --- |
| `ORACLE_MCP_AUTH_METHOD` | all | `session`, `apikey`, or `oauth`. Defaults to `session`. |
| `ORACLE_MCP_AUTH_PROFILE` | session, apikey | Profile in `~/.oci/config`. Falls back to `OCI_CONFIG_PROFILE`, then `DEFAULT`. |
| `ORACLE_MCP_ENV_FILE` | all | Path to a specific `.env` file instead of directory discovery. |
| `ORACLE_MCP_HOST`, `ORACLE_MCP_PORT` | oauth | Bind address for the Streamable HTTP listener. Defaults to `127.0.0.1:8000`. Rejected in `session`/`apikey` mode, which run over stdio only. |
| `ORACLE_MCP_TENANCY_REGISTRY` | oauth | Path to the server-side tenancy registry TOML. |
| `ORACLE_MCP_BASE_URL` | oauth | Required. Absolute `https://` public URL used to build authorize, callback, and well-known URLs. |
| `ORACLE_MCP_OAUTH_ALLOW_INSECURE_LOCAL` | oauth | Allows an unset or `http://localhost` base URL. Local development only. |
| `ORACLE_MCP_OAUTH_SCOPES` | oauth | Requested scopes. Default includes `oci_mcp.recovery.invoke` and `offline_access`. |
| `FASTMCP_HOME` | oauth | FastMCP's home directory, where per-tenancy OAuth state is persisted. Contains secret material. |
| `ORACLE_MCP_TENANCY_ALIAS`, `ORACLE_MCP_IDCS_DOMAIN`, `ORACLE_MCP_IDCS_CLIENT_ID`, `ORACLE_MCP_IDCS_CLIENT_SECRET`, `ORACLE_MCP_IDCS_AUDIENCE`, `ORACLE_MCP_TENANCY_ID`, `ORACLE_MCP_REGION` | oauth | Single-tenant fallback used when `ORACLE_MCP_TENANCY_REGISTRY` is unset. |
| `ORACLE_MCP_INSTALLATION_ID`, `ORACLE_MCP_INSTALLATION_ID_FILE` | all | Stable installation identifier for telemetry. Set explicitly on shared deployments. |
| `ORACLE_MCP_LOG_LEVEL`, `ORACLE_MCP_LOG_TO_STDOUT`, `ORACLE_MCP_LOG_DIR`, `ORACLE_MCP_LOG_FILE`, `ORACLE_SDK_LOG_LEVEL` | all | Logging configuration. |

## Tools

Most resource tools accept `region` where the OCI API supports it. The supported list and summary tools accept `fetch_for_child_compartment=true` to include the requested compartment and its descendants.

| Area | Tools |
| --- | --- |
| Protected databases | `list_protected_databases`, `get_protected_database`, `summarize_protected_database_health`, `summarize_protected_database_redo_status`, `summarize_backup_space_used` |
| Recovery Service | `check_recovery_service_limits`, `fetch_regions_subscribed`, `list_protection_policies`, `get_protection_policy`, `list_recovery_service_subnets`, `get_recovery_service_subnet`, `get_recovery_service_metrics`, `list_restore` |
| Database Service and backups | `list_databases`, `get_database`, `list_backups`, `get_backup`, `summarize_protected_database_backup_destination`, `list_db_homes`, `get_db_home`, `list_db_systems`, `get_db_system` |
| Guidance | `oci_recovery_service_dashboard_prompt`, `onboard_database_to_recovery_service`, `diagnose_recovery_service_issue` |

Use the MCP tool descriptions as the authoritative parameter reference. Some list tools can resolve a compartment display name; OCI resource retrieval tools require the corresponding OCID.

## Development and validation

Install the development dependencies before running tests:

```sh
uv sync --group dev
uv run pytest
```

The test suite is offline: OCI clients are mocked, so no credentials or live resources
are required.

## License

Copyright (c) 2025, 2026 Oracle and/or its affiliates.
Licensed under the Universal Permissive License v1.0 as shown at <https://oss.oracle.com/licenses/upl>.
