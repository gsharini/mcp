# OCI Recovery Service MCP Server

OCI Model Context Protocol (MCP) server exposing read-oriented Oracle Cloud Recovery Service and Database Service operations as MCP tools.

## Features

- Browse protected databases, protection policies, Recovery Service subnets, restore work requests, Database Service resources, and backups.
- Summarize protected-database health, redo-shipping status, backup space, and backup destinations.
- Optionally traverse child compartments for supported list and summary tools.
- Use multi-tenant OAuth for hosted deployments, with tenancy selection and per-tenant OCI request routing.
- Retrieve non-destructive guidance for Recovery Service dashboards, Cloud Protect onboarding, and CDB out-of-place restore planning.
- Map OCI SDK models to Pydantic models for safe, serializable responses.

## MCP client configuration (recommended)

Most users should configure their MCP client to launch the server, rather than starting it manually.

Add a stanza like this to your MCP client config (often called `mcp.json`; example shown is **stdio**):

```json
{
  "mcpServers": {
    "oci-recovery": {
      "type": "stdio",
      "command": "uvx",
      "args": [
        "oracle.oci-recovery-mcp-server"
      ],
      "env": {
        "OCI_CONFIG_PROFILE": "DEFAULT"
      }
    }
  }
}
```

For local API-key or session-token HTTP transport, start the server with:

```sh
ORACLE_MCP_HOST=<bind_host> \
ORACLE_MCP_PORT=<port> \
ORACLE_MCP_BASE_URL=<public_base_url> \
ORACLE_MCP_AUTH_METHOD=session \
uvx oracle.oci-recovery-mcp-server
```

`stdio` uses the configured OCI CLI profile. Set `ORACLE_MCP_AUTH_METHOD=apikey` to use API-key authentication from that profile.

### Hosted multi-tenant OAuth

Set `ORACLE_MCP_AUTH_METHOD=oauth` and provide a server-side tenancy registry through `ORACLE_MCP_TENANCY_REGISTRY`. Each tenancy entry supplies its tenancy OCID, IAM domain, confidential-client credentials, and region. Configure clients to send `X-OCI-Tenancy` with a registered tenancy alias or OCID; this header selects the tenancy for sign-in and requests.

The registry, client secrets, and OAuth state remain server-side. The legacy single-tenant variables (`ORACLE_MCP_IDCS_DOMAIN`, `ORACLE_MCP_IDCS_CLIENT_ID`, `ORACLE_MCP_IDCS_CLIENT_SECRET`, `ORACLE_MCP_TENANCY_ID`, and `ORACLE_MCP_REGION`) remain supported when no registry is configured.

The server optionally loads a `.env` file before reading configuration. Set `ORACLE_MCP_ENV_FILE` to select a specific file; explicitly exported environment variables take precedence.

## Install

From this repository root:

```
make build
uv pip install ./src/oci-recovery-mcp-server
```

Or directly inside the package directory:

```
cd src/oci-recovery-mcp-server
uv build
uv pip install .
```

## Tools

All tools support an optional `region` parameter where applicable. Tools marked with **child-compartment support** accept `fetch_for_child_compartment=true` to aggregate results across the requested compartment subtree.

### Tenancy and compartments

- `get_compartment_by_name_tool(name)` — resolve an accessible compartment by display name.
- `fetch_regions_subscribed(tenancy_id=None)` — list the tenancy's subscribed OCI regions and status.

### Recovery Service

- `list_protected_databases(...)` — list protected databases with filters, subnet details, metrics, retention-lock status, and redo-shipping status. **Child-compartment support.**
- `get_protected_database(protected_database_id, ...)` — retrieve one protected database.
- `summarize_protected_database_health(...)` — summarize protected-database health states. **Child-compartment support.**
- `summarize_protected_database_redo_status(...)` — summarize real-time redo shipping status. **Child-compartment support.**
- `summarize_backup_space_used(...)` — summarize backup space used by eligible protected databases. **Child-compartment support.**
- `check_recovery_service_limits(...)` — retrieve Recovery Service quota availability for the authenticated tenancy.
- `list_protection_policies(...)` and `get_protection_policy(protection_policy_id, ...)` — browse protection policies. `list_protection_policies` supports child compartments.
- `list_recovery_service_subnets(...)` and `get_recovery_service_subnet(recovery_service_subnet_id, ...)` — browse Recovery Service subnets. `list_recovery_service_subnets` supports child compartments.
- `get_recovery_service_metrics(compartment_id, start_time, end_time, ...)` — retrieve Recovery Service metric time series. **Child-compartment support.**
- `list_restore(compartment_id, ...)` — list active and historical database restore work requests. **Child-compartment support.**

### Database Service and backups

- `list_databases(...)` and `get_database(database_id, ...)` — browse databases and their backup configuration. `list_databases` supports child compartments.
- `list_db_homes(...)` and `get_db_home(db_home_id, ...)` — browse database homes. `list_db_homes` supports child compartments.
- `list_db_systems(...)` and `get_db_system(db_system_id, ...)` — browse database systems. `list_db_systems` supports child compartments.
- `list_backups(...)` and `get_backup(backup_id, ...)` — browse manual, automatic, and long-term backups. `list_backups` supports child compartments.
- `summarize_protected_database_backup_destination(...)` — summarize backup destinations and configuration status. **Child-compartment support.**

### Guidance

- `oci_recovery_service_dashboard_prompt()` — return dashboard-generation guidance for Recovery Service data.
- `onboard_database_with_cloud_protect()` — return non-destructive Cloud Protect onboarding readiness guidance.
- `OutofplaceRestoreOfDatabase(source_database_name, target_database_address, protected_database_ocid, ...)` — return a populated CDB out-of-place restore runbook without performing recovery operations.

## Development

- Code style/format/lint/test tasks are managed via Makefile:
  - `make build` — builds all sub-packages
  - `make install` — installs all sub-packages into current environment
  - `make test` — runs unit tests
  - `make lint` — runs linters
  - `make format` — formats code

## License

Copyright (c) 2025, Oracle and/or its affiliates.
Licensed under the Universal Permissive License v1.0 as shown at https://oss.oracle.com/licenses/upl.
