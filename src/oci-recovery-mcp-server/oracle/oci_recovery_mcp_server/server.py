"""
Copyright (c) 2025, Oracle and/or its affiliates.
Licensed under the Universal Permissive License v1.0 as shown at
https://oss.oracle.com/licenses/upl.
"""

# Module overview:
# This file defines the FastMCP server for Oracle Recovery Service related tools.
# It wires up:
# - Logging (file + optional console with rotation)
# - OCI client factories (Recovery, Identity, Database, Monitoring, Limits)
# - Helper utilities (tenancy/compartment discovery, DB Home discovery)
# - A set of MCP tools (decorated functions) that call OCI SDKs, paginate responses,
#   and map SDK models into server-specific dataclasses found in models.py.
#
# The general flow for most tools:
# 1) Resolve region/config/signer and create an OCI client (get_*_client).
# 2) Build an argument set from the tool parameters (including optional filters).
# 3) Call the appropriate OCI API, handling pagination where required.
# 4) Map SDK responses to the server's typed models (map_* functions).
# 5) Return typed results (summaries/objects) or computed aggregations.
#
# Main() chooses the transport:
# - If ORACLE_MCP_HOST and ORACLE_MCP_PORT are set: run HTTP transport.
# - Otherwise run stdio transport (default for MCP).
#
# Important robustness choices:
# - We add an "additional_user_agent" string to all OCI client configs for traceability.
# - We sign requests with a SecurityTokenSigner using the configured security token file.
# - We try to be resilient to SDK shape differences by using getattr/__dict__/to_dict
#   wherever possible, especially for pagination and nested model fields.
# - We log key milestones and counts for better operability and diagnostics.

import ipaddress
import json
import logging
import os
import re
import threading
import time
import traceback
import uuid
from logging.handlers import RotatingFileHandler
from typing import Annotated, Any, Callable, Literal, Optional

import oci
from dotenv import find_dotenv, load_dotenv
from fastmcp import FastMCP
from oci.monitoring.models import SummarizeMetricsDataDetails

# Database Service models and mappers
from oracle.oci_recovery_mcp_server.models import (
    Backup,
    BackupSummary,
    Database,
    DatabaseHome,
    DatabaseHomeSummary,
    DatabaseSummary,
    DbSystem,
    DbSystemSummary,
    ProtectedDatabase,
    ProtectedDatabaseBackupDestinationItem,
    ProtectedDatabaseBackupDestinationSummary,
    ProtectedDatabaseBackupSpaceSum,
    ProtectedDatabaseHealthCounts,
    ProtectedDatabaseRedoCounts,
    ProtectedDatabaseSummary,
    ProtectionPolicy,
    RecoveryServiceSubnet,
    WorkRequest,
    map_backup,
    map_backup_summary,
    map_database,
    map_database_home,
    map_database_home_summary,
    map_database_summary,
    map_db_backup_config,
    map_db_system,
    map_db_system_summary,
    map_protected_database,
    map_protected_database_summary,
    map_protection_policy,
    map_recovery_service_subnet,
    map_recovery_service_subnet_details,
    map_work_request,
)

from . import __project__, __version__
from .multitenant_auth import TENANT_CLAIM, MultiTenantOCIAuth, _domain_to_url
from .tenancy_registry import (
    RegistryError,
    TenancyEntry,
    TenancyRegistry,
    load_registry,
)

# Load configuration from a .env file (if present) so all settings can live in one
# config file instead of being exported as environment variables. This runs before
# any module-level env reads below. Precedence: real environment variables win over
# the file (override=False). Point ORACLE_MCP_ENV_FILE at a specific file to override
# the default ".env" discovery (which walks up from the current working directory).
_ENV_FILE = os.getenv("ORACLE_MCP_ENV_FILE") or find_dotenv(usecwd=True)
if _ENV_FILE:
    load_dotenv(_ENV_FILE, override=False)

"""MCP tools available in this server:
- list_subscribed_regions
- list_protected_databases
- get_protected_database
- summarize_protected_database_health
- summarize_protected_database_redo_status
- summarize_backup_space_used
- check_recovery_service_limits
- list_protection_policies
- get_protection_policy
- get_recovery_service_metrics
- list_databases
- get_database
- list_backups
- get_backup
- list_restore
- summarize_protected_database_backup_destination
- get_db_home
- list_db_systems
- get_db_system
"""

OCI_RECOVERY_SERVICE_DASHBOARD_PROMPT = """
You are an expert dashboard generator.
You very well know how to generate a presentable charts for the executives.
Make sure the chart is loadable and there are no errors while loading chart.

Visualise OCI Recovery - Dashboard charts in one html document with below metrics in the given compartment.
Include both OCI Database Service resources and all cloud-protected databases returned by the Recovery Service tools.
Display the Title - OCI Recovery - Dashboard
Under the Title, mention the compartment name.
Under this compartment name add a note: Generated using Recovery Service MCP Server
Add the date of report generation

Main page (Overview)
In first row, summarise base db systems based on backup destination - DBRS, OBJECT_STORE or UNCONFIGURED
using donut chart.
Use tool summarise_protected_database_backup_destination.
Use title - Databases categorised by backup destination.
Replace DBRS with "RecoveryService" while generating the report.
In another frame, first row, second column, With title Protected Database Space:
Report total backup space used by protected databases - using tool summarize_backup_space_used.
Note: Space used by ACTIVE/DELETE SCHEDULED protected databases.
In Second Row first column, Summarise protected database based on lifecycle status using donut chart.
Title - protected databases by lifecycle state.
Make sure the values are based on actual data.
Double check this.
In Second row, summarise protected databases on health status - PROTECTED, WARNING, ALERT using donut chart.
Use tool summarize_protected_database_health.
Title - ACTIVE protected databases by health state.
In Second row, summarise protected databases on realtime redo status - ENABLED, DISABLED using donut chart.
Use tool summarize_protected_database_redo_status.
Title - ACTIVE protected databases by real time redo.

In the Fourth row, report the protected databases with OCID, database db unique name, health status,
lifecycle state,
redo status, backup space used in tabular format.
Include every cloud-protected database returned by list_protected_databases in this table.
Filterable columns - Health status, Redo status, life cycle state.
This data is very important.
Extract details carefully from list protecetd datbase output and map the columns to the OCIDs.
Be diligent while filling up this table.
Don't miss the filters.

In another tab named - Backup Details
Tool to use list backups with compartment id as argument.
You are an expert dashboard generator.
You very well know how to generate a presentable charts for the executives.
Make sure the chart is loadable and there are no errors while loading chart.
The lines in graph are clearly visible and well positioned.

Generate a line chart showing backup creation timelines for databases in the mentioned compartment.
Each database is represented by a distinct line, with points marking individual backup events
based on 'time_started'
The chart is styled for executive presentation, with a clean layout, legend, and tooltips
X axis - Creation date/ Start date
Y axis - db_unique_name

Generate a line chart showing time taken by each backup for databases in the mentioned compartment.
Each database is represented by a distinct line, with points marking individual backup events
based on 'duration'
If user hovers over individual points then they should get details such as exact duration and type of backup
(FULL or INCREMENTAL).
- X axis: Creation date / Start date
- Y axis: duration_minutes.

Give your insight on:
- If any backup has taken more time or less time than usual pattern
- Is there any backup missing in the pattern
- If backup is manually taken or LTR call that out separately

IMPORTANT:
Make sure charts are loadable and renderable clearly in html.
Double check this condition.
There should be no missing line charts.
Do not add date/time on the points unless user hovers over that point.

In another tab named - Backup space usage
Tool to use get_recovery_service_metrics and resolution used 1 day.

Generate a line chart of backup space used by each protected databases in last 5 days - using tool
get_recovery_service_metrics and metricName SpaceUsedForRecoveryWindow.
Each protected database is represented by a distinct line with points marking individual space.

Give your insight on:
- If there are any anomalies in the space usage pattern.
- Any other space anomaly you can think of

Add an executive KPI summary row directly below the dashboard title.

Create 4 KPI cards displayed horizontally using Bootstrap grid:
1. Total Protected Databases
2. Healthy Databases (%)
3. Redo Shipping Enabled (%)
4. Total Backup Space Used (GB)

Rules:
- Use existing dashboard data to calculate KPI values.
- KPI cards must be visually compact and equal height.
- Each KPI card should contain:
    - Small uppercase label
    - Large bold metric value
    - Optional subtext (e.g. "of 3 databases")

Styling:
- Use soft card backgrounds with rounded corners.
- Center-align KPI content.
- Use large font (2–2.5rem) for KPI numbers.
- Use subtle shadows.
- Maintain spacing with Bootstrap g-4.

Layout:
- KPI row must appear ABOVE all charts.
- Dashboard width remains 75vw.
- On mobile, stack KPI cards vertically.

Data logic:
- Total Protected Databases = count of protected databases.
- Healthy % = (PROTECTED / total) * 100.
- Redo Enabled % = (ENABLED / total) * 100.
- Total Backup Space = sum of space used.

After KPIs, keep charts as secondary visual detail.

IMPORTANT

Layout rules for HTML dashboard:
- Wrap all content in a .dashboard-container:
    width: 75vw;
    max-width: 1200px;
    margin: 0 auto;
- Center the dashboard horizontally.
- Do NOT use full screen width.
- On mobile (<768px), expand dashboard to 95vw.

Chart container sizing:
- Do NOT use a single default height for all charts.
- Overview donut charts MUST be compact:
    height: 260px.
- Timeline / line charts:
    height: 360px.
- Space usage charts:
    height: 300px.
- Apply CSS classes per chart type (overview-donut, timeline-chart, space-chart).
- Ensure donuts appear compact and not vertically stretched.

When using Chart.js:
- NEVER use custom HTML legends.
- NEVER use absolute positioning over canvas.
- Always use native Chart.js legend positioned on the right.
- Add layout.padding = 20 to every chart.
- For doughnut charts:
    cutout: '65%'
    radius: '85%'
- Ensure charts fit inside containers without clipping.
- Avoid overlapping elements.
- Maintain clean spacing between panels.
- Optimize layout for presentation-quality visuals.
Make sure chart sizes are equal and fit well inside demarcation.
Make sure there are no rendering issues.
Don't generate truncated html file.
Make sure its a complete file without any syntax issues.
Make sure legends are written on the rightside of donut chart and within frame.
Show all the legends and next to legends mention the count as well in brackets.
Make sure titles are on the top of the donut chart.
Make sure title, donut chart and legends fit within the frame.

Always render charts for every tab.
Include required JS adapters.
Initialize charts after tab activation.

Use soft colors in the chart - executive appealing colors.
Demarcate between the rows.
Since this is a dashboard make sure user gets the visibility of most charts without scrolling.
Create a responsive layout minimizing scrolling.
"""


CLOUD_PROTECT_ONBOARDING_PROMPT = """
You are an Oracle Database Cloud Protect onboarding assistant.

Your task is to assess readiness and guide the onboarding of an on-premises Oracle Database to OCI Zero Data Loss Autonomous Recovery Service using Cloud Protect.

AUTHORITATIVE GUIDANCE

Before making recommendations or generating commands, retrieve and use the latest applicable Oracle documentation, including:

* Mandatory Requirements Checklist for Recovery Service
* Cloud Protect prerequisites
* Protecting on-premises databases using Cloud Protect
* Adding an on-premises database to Recovery Service
* Relevant networking, IAM, authentication, protection policy, and service-limit documentation

The documentation may change. Treat the retrieved documentation as authoritative over remembered procedures, commands, requirements, or examples.

Apply only requirements relevant to an on-premises Cloud Protect deployment. Do not apply OCI Database or multicloud-specific requirements unless they are explicitly relevant to the target environment.

State which documentation was consulted and identify any required documentation that could not be retrieved.

EXECUTION CONTEXT

This prompt does not itself inspect, modify, or onboard the target environment.

The MCP server provides this prompt as guidance only. Any discovery, validation, or onboarding operation must be performed by the model through authorized capabilities made available by the invoking client.

Before performing prerequisite validation or onboarding:

* inspect the capabilities exposed by the invoking client;
* identify which capabilities are authorized and appropriate for the target environment;
* determine whether those capabilities provide sufficient access to verify the applicable prerequisites;
* use only authorized capabilities suitable for the requested operation;
* do not assume that a particular remote shell, database connection, OCI tool, or execution mechanism is available.

If the available capabilities and their authorization scope cannot be determined automatically, ask the operator which authorized capabilities are available for prerequisite verification.

The question should be concise and may ask whether the model is authorized to use capabilities such as:

* remote inspection of the target database host;
* read-only access to the target database;
* OCI and Recovery Service resource inspection;
* DNS and network testing from the target environment;
* SQLcl and Cloud Protect operations on the target database host;
* access to all relevant nodes and instances in a RAC or clustered deployment.
* Oracle software owner is a member of the OSBACKUPDBA group (typically backupdba)

Ask only about capabilities that are necessary for the applicable prerequisites and are not already exposed or described. Do not ask the operator for passwords, private keys, wallet contents, tokens, or other secret values.

Appropriate capabilities may include:

* remote target-host inspection;
* database access on or to the target host;
* OCI and Recovery Service inspection;
* DNS and network validation from the target environment;
* SQLcl and Cloud Protect operations on the target database host.

When such capabilities are available, use them to inspect the actual target host, database, and OCI environment.

If required capabilities are unavailable, unauthorized, or provide insufficient access:

* do not claim that the associated requirement has been verified;
* classify it as not verified;
* explain what capability or authorization is missing;
* provide concise instructions that an authorized operator can use to complete the verification.

For RAC or clustered deployments, consider all relevant nodes and instances where the current Oracle documentation requires node-specific or instance-specific validation or execution.

ONBOARDING OBJECTIVE

Determine whether the target database satisfies the current mandatory requirements for onboarding to Recovery Service using Cloud Protect.

Use your judgment to identify and perform the checks necessary to evaluate:

* database and platform support;
* Cloud Protect and SQLcl readiness;
* Recovery Service connectivity;
* OCI resources, limits, IAM, and policies;
* encryption and wallet readiness;
* required Oracle libraries and configuration;
* DNS and network readiness;
* Oracle software owner is a member of the OSBACKUPDBA group (typically backupdba)
* conflicts with existing backup arrangements;
* any additional mandatory requirement stated in the current documentation.

The listed areas are guidance, not an exhaustive checklist. Adapt the assessment to the current documentation, target architecture, database release, deployment topology, and authorized capabilities available.

Do not rely solely on user-provided values when they can be safely and independently verified through authorized capabilities.

SQLCL AND CLOUD PROTECT VALIDATION

Before confirming that SQLcl is available and suitable for Cloud Protect onboarding, verify more than the presence of the SQLcl executable.

Confirm that the installed SQLcl and its Cloud Protect functionality can recognize, validate, or otherwise operate with the given Recovery Service subnet OCID


Use a read-only or non-destructive capability check where possible.

Do not mark SQLcl readiness as satisfied solely because:

* the `sql` executable exists;
* SQLcl returns a version;
* the `rcv` command is present;
* a database connection can be established.

Treat SQLcl readiness as satisfied only when the installed SQLcl and Cloud Protect command set support the required onboarding syntax and can accept or validate the applicable subnet resource identifier.

If the capability cannot be safely tested, classify it as not verified and explain what operator validation is required.

SUBNET INPUT GUIDANCE

When preparing the `rcv add database` operation, account for the fact that the command may accept a subnet as well as a Recovery Service subnet.

Do not assume that the input must always be a Recovery Service subnet OCID.

Determine from the latest documentation, command help, and available environment context which subnet resource type is valid and appropriate for the target onboarding operation.

Before generating the command:

* identify whether the supplied identifier refers to a subnet or a Recovery Service subnet;
* validate that the resource exists and belongs to the intended region, compartment, and network context;
* use the correct argument and syntax supported by the installed SQLcl and current Cloud Protect command;
* do not silently convert, substitute, or invent a subnet identifier;
* explain which subnet resource type is being used and why.

OPERATING PRINCIPLES

* Begin with discovery and read-only validation.
* Use the least-privileged available mechanism.
* Prefer structured, purpose-specific capabilities over arbitrary shell execution.
* Perform host-dependent checks from the target host or an equivalent target-context capability.
* Verify that a capability is authorized for the target and intended operation before using it.
* Do not attempt to bypass unavailable capabilities or insufficient authorization.
* Do not invent commands, parameters, OCIDs, paths, endpoints, or configuration values.
* Do not expose passwords, wallet contents, private keys, tokens, or other secrets.
* Distinguish confirmed facts from assumptions, inferences, and recommendations.
* Treat inaccessible or unverifiable requirements as not verified rather than satisfied.
* Stop and explain when the documentation, requested configuration, and observed environment conflict.
* Ask only for information or authorization details that cannot be safely discovered.
* Require explicit approval before making changes to the database, database host, OCI resources, network, wallets, backup configuration, or protection settings.
* Limit an approval to the clearly described next phase unless the user explicitly authorizes a broader scope.

READINESS DECISION

For each applicable mandatory requirement, determine whether it is:

* satisfied;
* not satisfied;
* not verified;
* not applicable.

Use evidence from the target database host, database, OCI, and Recovery Service as appropriate.

The database is ready for onboarding only when all applicable mandatory requirements have been verified as satisfied.

If the database is not ready:

* identify the requirements that are blocking readiness;
* distinguish failed requirements from requirements that could not be verified;
* identify any missing capability or authorization responsible for an unverified result;
* recommend the minimum set of actions needed to make the environment ready.

Do not produce an overly detailed checklist unless the operator requests one. Summarize the important findings and retain enough evidence to support each conclusion.

ONBOARDING EXECUTION

When all applicable mandatory requirements are satisfied:

1. Present a concise onboarding plan based on the current documentation.
2. Explain the intended changes, affected resources, and expected outcome.
3. Confirm that the required execution capabilities are available and authorized.
4. Request approval before state-changing operations.
5. Use authorized capabilities exposed by the invoking client to perform the approved onboarding operations.
6. Execute the onboarding in logical, verifiable phases.
7. Verify the outcome using evidence from both the target database environment and Recovery Service.

If the available capabilities support assessment but not execution, provide the approved operations or commands for an authorized operator rather than claiming to have executed them.

Do not claim success merely because a command or operation completed. Confirm, as applicable, that:

* the protected database resource exists and is healthy;
* database registration completed;
* Cloud Protect configuration completed;
* the intended protection policy is assigned;
* the expected protection status is active.

OUTPUT

Return:

1. Documentation consulted
2. Target environment summary
3. Available and authorized capabilities
4. Missing capabilities or authorization
5. Readiness assessment
6. Blocking or unverified requirements
7. Recommended actions
8. Proposed onboarding plan
9. Operations or commands for the next approved phase
10. Final verification, when execution has occurred

Keep the response concise, but include enough evidence for an operator to understand and trust each conclusion.

Never state that the environment was inspected, a requirement was verified, onboarding was performed, or protection was enabled unless the available authorized capabilities or operator-provided evidence directly support that conclusion.
"""


OUT_OF_PLACE_RESTORE_OF_DATABASE_PROMPT = """
Use RMAN and Recovery Service to restore and recover database <source database name>

You are guiding a CDB out-of-place recovery to an alternate location using RMAN and Recovery Service
Use this guidance only for recovery of an Oracle Multitenant CDB. The restored database retains the source DBID. Use only these resources:

* Cloud Protect instructions: https://docs.oracle.com/en/cloud/paas/recovery-service/dbrsu/protecting-premises-databases-using-recovery-service.html
* The OCI Recovery MCP server
* The local CDB out-of-place disaster recovery runbook (annexed below)

Gather the source database identity, DB_UNIQUE_NAME, DBID, Oracle and Grid release/patch levels, ASM/FRA layout, TDE keystore and password-file recovery locations, recovery objective, RCV metadata, and network/wallet material. Store the necessary files only in the approved working directory.

If the user provides a source database host name or IP address, collect the required source database details directly from that host using approved access methods. Otherwise, ask the user to provide the source database address or supply the required details manually. Never invent missing source database information.

TARGET ENVIRONMENT

* Source database name: <source database name>
* Target database address: <target database address>
* Recovery Service protected database OCID of the source database: <ocid of recovery service protected databases>
* Source database address(if provided): <source database address>
* Approved connection details: <connection details>

RECOVERY AUTHORIZATION AND SAFETY

Ask approval from user to copy and stage sensitive restore material previously collected from source database to <target database address>. Existing databases on <target database address> can be destroyed.

Before any destructive action, identify the exact target host, target database/Clusterware resources, and files that will be affected. Use the supplied connection details only. Do not invent connection details, database identifiers, paths, OCIDs, passwords, wallet contents, or recovery targets. Stop and request the missing information when it cannot be discovered through the supplied connections, approved working directory, OCI Recovery MCP server, or Cloud Protect instructions.

Prerequisites on the Target Database Host
1. Verify SQLcl installation and confirm that SQLcl is installed and that the installed version supports the required rcv commands.If SQLcl is not installed, download the latest SQLcl RPM and install it on <target database host> using:export RPM_SQLCL_INSTALL_AS_ORACLE=true rpm -Uvh <sqlcl-rpm-file>
2. Verify OSBACKUPDBA group membership Confirm that the Oracle software owner is a member of the OSBACKUPDBA operating system group, typically named backupdba.If the Oracle software owner is not a member, add the user to the appropriate group.
3. Verify OCI profile configuration Confirm that an OCI CLI profile is configured for the Oracle software owner. If no OCI profile is configured, ask the user to configure it before proceeding.


REQUIRED RECOVERY FLOW

Use the protected database OCID above to import or recover destination-local RCV metadata for the lost source protected database. Validate the RCV restore range and Recovery Service catalog identity from the destination before restoring. The catalog must resolve to the intended source database name and DBID.

1. Confirm the recovery objective and source identity from the approved working directory, RCV metadata, and Recovery Service inventory.
2. Validate destination Oracle/Grid compatibility, ASM/FRA capacity, DNS/network access to Recovery Service, OCI authentication, and availability of required TDE keystore and password-file material.
3. If sqlcl doesnot support rcv commands then download the latest SQLcl. Install it on <target database address> with:

   export RPM_SQLCL_INSTALL_AS_ORACLE=true
   rpm -Uvh <sqlcl rpm>

4. Use SQLcl only for Cloud Protect `rcv` commands and named RCV connections; use sqlplus for local OS-authenticated `/ as sysdba` checks.
5. Configure or validate destination Cloud Protect authentication and Recovery Service subnet connectivity. Import the protected database by OCID when supported; otherwise restore the preserved RCV network and wallet metadata from the working directory with restrictive permissions.
6. Run `rcv show restore_range` for the source DB_UNIQUE_NAME. Stop unless the selected timestamp, SCN, or restore point is within that range.
7. Generate the destination RMAN environment with Cloud Protect, source it, and validate the Recovery Service catalog alias before continuing.
8. Restore the TDE keystore and create or restore the password file on the target. Build a destination-safe PFILE using destination ASM/FRA paths; start the replacement instance in NOMOUNT with `cluster_database=FALSE`.
9. Restore and mount the control file using the source DBID. Validate the mounted database name and DBID, then disable block change tracking.
10. Preview the restore and determine all datafile, tempfile, and online redo relocation requirements before the full restore.
11. Restore and recover the database using exactly 8 RMAN SBT channels. Use the validated recovery target and destination-specific RCV wallet/SBT-library settings. Do not open the database until recovery evidence shows no unresolved datafile recovery errors.
12. Relocate source-only redo members as needed, open with RESETLOGS, open and save state for all PDBs, validate TDE wallet status, recreate missing tempfiles, and validate block-change tracking and corruption views.
13. Convert the recovered instance back to RAC only after successful single-instance recovery. Register the recovered database with Cloud Protect and run the required initial level 0 backup.

Use the local runbook for exact command syntax and destination-specific paths. Present the planned commands for review before each destructive phase, and report the evidence gathered after every phase. Never claim restore, recovery, RESETLOGS, Cloud Protect registration, or the level 0 backup succeeded unless the authorized connections or command results directly prove it.

CDB out-of-place recovery runbook :

Runbook:  CDB Out-of-Place Recovery to alternate location with RMAN and Recovery Service
This cookbook describes how to recover an Oracle Multitenant CDB to a different on-premises cluster after the source cluster has been lost or deleted due to a disaster
or when an alternate database needs to be created for testing, reporting or auditing purposes.
* The source database was protected by Cloud Protect / OCI Recovery Cloud Service (RCV).
* The restore is performed to a separate destination cluster.
* The restored database keeps the source DBID.

Required Inputs
Capture the following information before starting. Appendix A provides additional detail and example commands for collecting these inputs.
If its not available ask for the inputs from the user.
Input Group	Required Values
Recovery decision	Production disaster replacement or test/drill restore; target recovery time, SCN, restore point, or “latest available”; approved data-loss objective
Source identity	DB_NAME, DB_UNIQUE_NAME, DBID, CDB/PDB names, database incarnation, platform, Oracle Database release, patch level, COMPATIBLE value
Cloud Protect / RCV	Protected database OCID, RCV connection name, DBRS catalog alias, recovery service endpoint, compartment OCID, VCN/subnet OCIDs, protection policy, restore range, control file autobackup or backup piece handle, preserved RCV network/wallet archive for the protected source database
Destination cluster	Hostnames, Oracle owner, Grid home, Oracle home, SQLcl path, ASM disk groups, FRA disk group and size, listener/SCAN details
Restore file placement	Destination DB_UNIQUE_NAME, destination ORACLE_SID, db_create_file_dest, db_recovery_file_dest, control_files, online redo log placement, tempfile placement
Security material	TDE keystore or wallet backup, wallet password if password-based, wallet_root, tde_configuration, password file backup or secured SYS / SYSBACKUP password source
Source configuration backup	Saved pfile/spfile text, srvctl config database, service definitions, redo thread/log group layout, undo tablespaces, PDB open/save-state requirements
Operational cutover	Application/service DNS targets, client connection strings, monitoring changes, Cloud Protect re-registration plan, post-recovery level 0 backup window
Recovery Process Outline
* Validate Cloud Protect restore range and Recovery Service catalog access from the destination cluster.
* Import, recreate, or restore preserved destination-local RCV metadata for the lost source protected database.
* Restore required TDE keystore material and create or restore the password file on the destination.
* Restore or create an PFILE
* Restore the control file
* Restore and recover the database
* Open database with RESETLOGS
* Register the recovered database with Cloud Protect and run the initial level 0 backup


Pre-requisites
1. The latest version of SQLcl must be installed on the destination cluster. Check if sqlcl supports rcv commands.  Use SQLcl for Cloud Protect rcv commands and named RCV connections only. For local OS-authenticated database checks such as / as sysdba, use sqlplus.
2. Oracle Grid Infrastructure and Oracle Database software must be installed on the destination cluster at a compatible release and patch level. Use the same database release and patch level as the source whenever possible. Confirm DB COMPATIBLE <= ASM COMPATIBLE.RDBMS.
3. The destination cluster must have network connectivity to OCI Recovery Service through the appropriate recovery service subnet, DNS/hosts configuration, and OCI authentication method.
4. The required TDE keystore material must be available outside the destroyed source cluster. If the source database used TDE and the keystore was lost with the source cluster, encrypted tablespaces cannot be recovered.
5. The source database must have been backed up successfully through Cloud Protect / RCV, and the selected recovery point must be inside the validated restore range.
6. The destination cluster must have enough ASM/FRA capacity for restored datafiles, archived redo required for recovery, online redo logs, tempfiles, control files, and post-RESETLOGS backup activity.



GENERIC PLACEHOLDER CONVENTION
Values in braces, for example {source_dbid}, must be supplied for the target environment before execution.
Preserve the source DB_NAME from the backup/control file; use a distinct destination DB_UNIQUE_NAME for drills or coexistence scenarios.

Use the original DB_UNIQUE_NAME only when this recovery is the production replacement and the old source database is permanently gone from Clusterware, Cloud Protect scheduling, monitoring, and operational DNS.


Phase 1 - Validate Cloud Protect Backups and Destination RCV Connectivity
Step 1 - Confirm recovery objective and source identity
Record the recovery point and database identity before running restore commands.
Recovery objective: latest available | timestamp | SCN | restore point
Source DB_NAME: {source_db_name}
Source DB_UNIQUE_NAME:{source_db_unique_name}
Source DBID: {source_dbid}
Destination DB name: {destination_db_name}
Destination unique: {destination_db_unique_name}
Destination SID: {destination_oracle_sid}
The source DBID is required when restoring a server parameter file or control file from autobackup. Obtain it from pre-disaster runbooks, prior RMAN logs, Cloud Protect inventory, rcv show database, or any preserved control file autobackup naming information.
Step 2 - Establish OCI connectivity to RCV from the destination host
Run these commands on the destination host as oracle.
export ORACLE_BASE
export ORACLE_HOME
export PATH=${SQLCL_HOME}/bin:${ORACLE_HOME}/bin:${PATH}

If Cloud Protect has not already been setup, configure OCI authentication if this destination has not yet been configured for Cloud Protect:
sql /nolog
SQL> rcv configure authentication -method api_key -oci_config {path_to_oci_config}
SQL> exit
Configure or validate the recovery service subnet that allows this destination cluster to reach Recovery Service:
sql /nolog
SQL> rcv add recovery_service_subnet \
 -vcn_id {vcn_ocid} \
 -compartment_id {compartment_ocid} \
 -subnet_id {subnet_ocid}
SQL> exit
Run the host configuration schedule as root to auto-manage DNS/host entries for the RCV catalog endpoints:
${SQLCL_HOME}/bin/sql /nolog
SQL> rcv add schedule -job_type CONFIGURE_HOST
SQL> exit

To recover Cloud Protect metadata for the lost protected database, import by protected database OCID:
sql /nolog
SQL> rcv import database -id {existing_protected_database_ocid}
SQL> exit
If rcv import database is not available, fails, or cannot be completed during the disaster window, restore the pre-collected RCV metadata archive for the protected source database. This archive must contain the network and wallet directories from {oracle_base}/rcv/dbs/{source_db_unique_name} and must have been saved outside the destroyed source cluster.
# Run on the destination host as oracle.
mkdir -p ${ORACLE_BASE}/rcv/dbs/{destination_db_unique_name_lower}

tar xpf {secure_dr_root}/{source_db_unique_name}/rcv_network_wallet_{backup_date}.tar \
 -C ${ORACLE_BASE}/rcv/dbs/{destination_db_unique_name_lower}

chmod 755 ${ORACLE_BASE}/rcv/dbs/{destination_db_unique_name_lower}/network
chmod 700 ${ORACLE_BASE}/rcv/dbs/{destination_db_unique_name_lower}/wallet
chmod 600 ${ORACLE_BASE}/rcv/dbs/{destination_db_unique_name_lower}/wallet/*

Step 3 - Validate restore range from Cloud Protect
Use the destination host's Cloud Protect metadata and identify the protected source database explicitly.
sql /nolog
SQL> rcv show restore_range -db_unique_name {source_db_unique_name}

DB Unique Name: {source_db_unique_name}
Low Time High Time Restore Point Name
-------- --------- ------------------
{restore_range_low_time} {restore_range_high_time}
SQL> exit
RCV database import/configuration enables rcv show restore_range -db_unique_name {source_db_unique_name} to provide the available restore range. The restore range confirms the database is recoverable.
If Cloud Protect cannot return the range because destination-local DBRS metadata or wallet authentication is broken, use RMAN catalog-only checks as the fallback. After repairing DBRS connectivity, the RMAN connection should be to the Recovery Service catalog, not to the lost source database:
export TNS_ADMIN=${ORACLE_BASE}/rcv/dbs/{source_db_unique_name_lower}/network

rman catalog '/@{source_dbrs_catalog_alias}'

SET DBID {source_dbid};
LIST INCARNATION;
LIST BACKUP SUMMARY;
LIST BACKUP OF ARCHIVELOG ALL COMPLETED AFTER "SYSDATE-7";

Step 4 - Generate destination-local RMAN / RCV environment files
Generate rman_env.sh and rcv_restore_template.rman on the destination host so SBT library and wallet references match the destination Oracle home.
sql /nolog
SQL> rcv show restore_range -db_unique_name {source_db_unique_name}
SQL> rcv configure rman_env \
 -db_unique_name {source_db_unique_name} \
 -oracle_sid {destination_oracle_sid}
SQL> exit
Expected output:
Generated a template backup script
${ORACLE_BASE}/rcv/dbs/{source_db_unique_name_lower}/rman_env/rcv_restore_template.rman
RMAN Env script ${ORACLE_BASE}/rcv/dbs/{source_db_unique_name_lower}/rman_env/rman_env.sh
Source the generated environment and validate the DBRS catalog alias:
source ${ORACLE_BASE}/rcv/dbs/{source_db_unique_name_lower}/rman_env/rman_env.sh

rman catalog '/@{source_dbrs_catalog_alias}' <<'EOF'
LIST INCARNATION;
EXIT
EOF
The catalog output must refer to the source DB_NAME and expected DBID. Stop if the catalog alias points to a different database.


Phase 2 - Prepare the Destination Replacement Instance
Step 1 - Restore required security material
Restore the TDE keystore from the pre-disaster secure copy.
# Run on destination host as oracle
mkdir -p {destination_wallet_root}/{source_db_unique_name_lower}/tde

# Replace {secure_wallet_backup_dir} with the wallet backup location
cp -p {secure_wallet_backup_dir}/tde/* {destination_wallet_root}/{source_db_unique_name_lower}/tde/

chmod 700 {destination_wallet_root}/{source_db_unique_name_lower}
chmod 700 {destination_wallet_root}/{source_db_unique_name_lower}/tde
chmod 600 {destination_wallet_root}/{source_db_unique_name_lower}/tde/*
Create an auto-login keystore:
sqlplus / as sysdba
ADMINISTER KEY MANAGEMENT CREATE AUTO_LOGIN KEYSTORE
 FROM KEYSTORE '{destination_wallet_root}/{source_db_unique_name_lower}/tde/'
 IDENTIFIED BY '{wallet_password}';
EXIT;
Step 2 - Create the password file
Create password file using the secured SYS password source. Use the same SYS / SYSBACKUP credentials.
orapwd file=${ORACLE_HOME}/dbs/orapw${ORACLE_SID} \
 password='{SYS_password}' \
 force=y \
 format=12
Step 3 - Create a destination-safe pfile
Use a minimal pfile. Update clusterware settings, archive destinations, and/or filesystem references for your environment.
cat > ${ORACLE_HOME}/dbs/init${ORACLE_SID}.ora << 'EOF'
*.db_name='{source_db_name}'
*.db_unique_name='{destination_db_unique_name}'

# Restore to destination ASM diskgroups using Oracle Managed Files.
*.db_create_file_dest='{destination_data_diskgroup}'
*.db_recovery_file_dest='{destination_recovery_diskgroup}'
*.db_recovery_file_dest_size={fra_size}
*.control_files='{destination_data_diskgroup}'

*.diagnostic_dest='{oracle_base}'
*.enable_pluggable_database=TRUE

# TDE. Use the source wallet root path only if that path exists on destination.
*.wallet_root='{destination_wallet_root}/{source_db_unique_name_lower}'
*.tde_configuration='KEYSTORE_CONFIGURATION=FILE'

*.remote_login_passwordfile='EXCLUSIVE'
*.db_files={db_files_limit}
*.compatible='{database_compatible_version}'

# Start as single instance for restore/recovery. Convert to RAC after recovery.
*.cluster_database=FALSE
EOF
Parameter notes:
* db_name must match the source database name stored in the backup and control file.
* db_unique_name may match the source only for the production replacement. Use a distinct name for drills.
* db_create_file_dest and db_recovery_file_dest must point to destination ASM diskgroups.
* Keep cluster_database=FALSE during restore/recovery. Register and start RAC instances after recovery is complete.
* wallet_root and tde_configuration must point to the restored destination keystore before media recovery reads encrypted tablespaces.
Step 4 - Start the replacement instance in NOMOUNT
sqlplus /nolog
conn / as sysdba
STARTUP NOMOUNT PFILE='{destination_oracle_home}/dbs/init{destination_oracle_sid}.ora';
EXIT;
Validate the instance state:
sqlplus / as sysdba
SELECT instance_name, status FROM v$instance;
SHOW PARAMETER db_name;
SHOW PARAMETER db_unique_name;
SHOW PARAMETER wallet_root;
EXIT;


Phase 3 - Restore the Control File, Database, and Recover
Step 1 - Restore the control file from Cloud Protect / RCV
Connect to the destination instance as the RMAN target and to the DBRS recovery catalog. Use the source DBID only for the control file restore while the target is in NOMOUNT.
rman target / catalog '/@{source_dbrs_catalog_alias}'
SET DBID {source_dbid};

RUN {
 ALLOCATE CHANNEL ch01 DEVICE TYPE SBT_TAPE
 PARMS "SBT_LIBRARY={destination_oracle_home}/lib/libra.so,
 ENV=(RA_WALLET='location=file:${ORACLE_BASE}/rcv/dbs/{source_db_unique_name_lower}/wallet credential_alias={source_dbrs_catalog_alias}',
 RA_FORMAT=TRUE)";

 RESTORE CONTROLFILE FROM AUTOBACKUP;
 ALTER DATABASE MOUNT;

 RELEASE CHANNEL ch01;
}
If RESTORE CONTROLFILE FROM AUTOBACKUP cannot locate the needed backup, list the cataloged control file backups and restore the selected handle explicitly. Example of using explicit handle {controlfile_autobackup_handle_example} to restore successfully.
SET DBID {source_dbid};
LIST BACKUP OF CONTROLFILE;

RUN {
 ALLOCATE CHANNEL ch01 DEVICE TYPE SBT_TAPE
 PARMS "SBT_LIBRARY={destination_oracle_home}/lib/libra.so,
 ENV=(RA_WALLET='location=file:${ORACLE_BASE}/rcv/dbs/{source_db_unique_name_lower}/wallet credential_alias={source_dbrs_catalog_alias}',
 RA_FORMAT=TRUE)";

 RESTORE CONTROLFILE FROM '{controlfile_backup_piece_or_handle}';
 ALTER DATABASE MOUNT;

 RELEASE CHANNEL ch01;
}
Validate the mounted control file identity:
sqlplus / as sysdba
SELECT name, dbid, db_unique_name, open_mode, database_role FROM v$database;
SELECT resetlogs_change#, resetlogs_time, status FROM v$database_incarnation ORDER BY resetlogs_time;
EXIT;
Stop if the dbid or db name does not match the intended source database.
BCT should be disabled following controlfile restore to prevent warnings and potential failure of the subsequent restore. To disable:
sqlplus /nolog
sql> conn / as sysdba
alter database disable block change tracking;
exit;
Step 2 - Inspect original file names and determine relocation needs
The restored control file records the original source file names. Query them before restore.
sqlplus / as sysdba
SET LINES 220
COLUMN name FORMAT a120

SELECT file#, name FROM v$datafile ORDER BY file#;
SELECT group#, member FROM v$logfile ORDER BY group#, member;
SELECT file#, name FROM v$tempfile ORDER BY file#;
EXIT;
If the destination has the same ASM diskgroup names and no storage overlap with the old source cluster, restoring to original ASM-style names may be acceptable. If destination diskgroup names differ, use SET NEWNAME commands for affected datafiles.
Keep online redo log relocation separate with ALTER DATABASE RENAME FILE when the restored control file points to source-only redo locations.
Step 3 - Preview and validate restore metadata
Preview restore requirements before running the full restore. Include the selected recovery target, and include the same SET NEWNAME pattern planned for the actual restore.
rman target / catalog '/@{source_dbrs_catalog_alias}'

RUN {
 SET UNTIL TIME "TO_DATE('{recovery_timestamp}','YYYY-MM-DD HH24:MI:SS')";
 SET NEWNAME FOR DATABASE TO '{destination_data_diskgroup}';

 ALLOCATE CHANNEL ch01 DEVICE TYPE SBT_TAPE
 PARMS "SBT_LIBRARY={destination_oracle_home}/lib/libra.so,
 ENV=(RA_WALLET='location=file:${ORACLE_BASE}/rcv/dbs/{source_db_unique_name_lower}/wallet credential_alias={source_dbrs_catalog_alias}',
 RA_FORMAT=TRUE)";

 RESTORE DATABASE PREVIEW SUMMARY;
 -- Optional when time allows:
 -- RESTORE DATABASE VALIDATE;

 RELEASE CHANNEL ch01;
}
For very large databases, run RESTORE DATABASE PREVIEW SUMMARY first and decide whether a full RESTORE DATABASE VALIDATE is practical during the disaster window.
Step 4 - Build the restore and recovery script
Create {restore_script_path} from the destination-generated RCV template and edit it for disaster restore.
Use a timestamp, SCN, or restore point inside the restore range validated in Phase 1.
# {restore_script_path}
# Run from destination host as oracle:
# rman target / catalog '/@{source_dbrs_catalog_alias}' \
# cmdfile={restore_script_path} \
# log={restore_log_path}

# SET DBID is intentionally omitted after the restored controlfile is mounted.

# Required only when using a password-based software keystore.
# SET DECRYPTION WALLET OPEN IDENTIFIED BY '{wallet_password}';

RUN {
 # Choose one recovery target and keep it inside the validated restore range.
 SET UNTIL TIME "TO_DATE('{recovery_timestamp}','YYYY-MM-DD HH24:MI:SS')";
 # SET UNTIL SCN {recovery_scn};
 # SET UNTIL RESTORE POINT {restore_point_name};

 ALLOCATE CHANNEL ch01 DEVICE TYPE SBT_TAPE
 PARMS "SBT_LIBRARY={destination_oracle_home}/lib/libra.so,
 ENV=(RA_WALLET='location=file:${ORACLE_BASE}/rcv/dbs/{source_db_unique_name_lower}/wallet credential_alias={source_dbrs_catalog_alias}',
 RA_FORMAT=TRUE)";

 ALLOCATE CHANNEL ch02 DEVICE TYPE SBT_TAPE
 PARMS "SBT_LIBRARY={destination_oracle_home}/lib/libra.so,
 ENV=(RA_WALLET='location=file:${ORACLE_BASE}/rcv/dbs/{source_db_unique_name_lower}/wallet credential_alias={source_dbrs_catalog_alias}',
 RA_FORMAT=TRUE)";

 SET NEWNAME FOR DATABASE TO '{destination_data_diskgroup}';

 RESTORE DATABASE;
 SWITCH DATAFILE ALL;
 RECOVER DATABASE;

}
If online redo log member names in the restored control file point to source-only locations, rename them before opening:
sqlplus / as sysdba

ALTER DATABASE RENAME FILE '{source_data_diskgroup}/{source_db_unique_name}/ONLINELOG/{source_redo_member_1}'
 TO '{destination_data_diskgroup}';

ALTER DATABASE RENAME FILE '{source_recovery_diskgroup}/{source_db_unique_name}/ONLINELOG/{source_redo_member_2}'
 TO '{destination_recovery_diskgroup}';

EXIT;
For ASM/OMF redo logs, changing only diskgroup names with destination DB_CREATE_FILE_DEST and DB_RECOVERY_FILE_DEST is usually preferred over hard-coding full OMF names.

Step 5 - Execute restore and recovery
rman target / catalog '/@{source_dbrs_catalog_alias}' \
 cmdfile={restore_script_path} \
 log={restore_log_path}
Review the RMAN log before proceeding:
grep -E "RMAN-|ORA-" {restore_log_path}
Some RMAN-06054 / missing archived log messages may be expected at the end of incomplete recovery when RMAN reaches the selected recovery boundary.

Step 6 - Validate recovery before opening RESETLOGS
sqlplus / as sysdba

SELECT name, dbid, open_mode, database_role, log_mode FROM v$database;
SELECT instance_name, status FROM v$instance;

SELECT file#, error, online_status, change#, time FROM v$recover_file;

SELECT file#, name, error, recover
FROM v$datafile_header
WHERE recover = 'YES'
OR error IS NOT NULL;

SELECT name, open_mode, recovery_status FROM v$pdbs ORDER BY name;

EXIT;
Proceed only when the database is mounted, recovery reached the approved stopping point, and no datafiles show unresolved recovery errors in v$datafile_header. Treat v$recover_file rows with no error text as secondary information that should be reviewed by DBA, the results of v$datafile_header are more conclusive.

Step 7 - Open the recovered database with RESETLOGS
Opening with RESETLOGS is required after incomplete recovery and after recovery using a backup control file. This creates the new incarnation of the database.
sqlplus / as sysdba

ALTER DATABASE OPEN RESETLOGS;
ALTER PLUGGABLE DATABASE ALL OPEN;
EXIT;
Step 8 - Validate CDB, PDBs, TDE wallet, and tempfiles
sqlplus / as sysdba

SELECT db_unique_name, name, dbid, open_mode, database_role, log_mode
FROM v$database;

SELECT name, open_mode, restricted, recovery_status
FROM v$pdbs
ORDER BY name;

ALTER PLUGGABLE DATABASE ALL OPEN;
ALTER PLUGGABLE DATABASE ALL SAVE STATE;

SELECT con_id,
 (SELECT name FROM v$containers c WHERE c.con_id = w.con_id) AS container_name,
 status,
 wallet_type,
 keystore_mode
FROM v$encryption_wallet w
ORDER BY con_id;

SELECT tablespace_name, file_name FROM dba_temp_files ORDER BY tablespace_name, file_name;

EXIT;
Recreate missing tempfiles as needed:
sqlplus / as sysdba
ALTER TABLESPACE TEMP ADD TEMPFILE '{destination_data_diskgroup}' SIZE {tempfile_initial_size} AUTOEXTEND ON NEXT {tempfile_autoextend_next} MAXSIZE {tempfile_max_size};
EXIT;
Step 9 - Validate block change tracking and post-recovery health
sqlplus / as sysdba

SELECT status, filename FROM v$block_change_tracking;

-- Enable BCT.
ALTER DATABASE ENABLE BLOCK CHANGE TRACKING USING FILE '{destination_data_diskgroup}';

SELECT * FROM v$backup_corruption;
SELECT * FROM v$copy_corruption;
SELECT * FROM v$database_block_corruption;

EXIT;


Phase 4 - Post-restore clusterware options
Apply this phase only if its RAC system. Skip this phase for Single instance database.

Step 1 - Create a RAC-ready pfile/spfile
Shut down the single-instance restored database:
sqlplus / as sysdba
SHUTDOWN IMMEDIATE;
EXIT;
Create {rac_pfile_path} with destination RAC settings:
*.db_name='{source_db_name}'
*.db_unique_name='{destination_db_unique_name}'
*.control_files='{destination_data_diskgroup}/{destination_db_unique_name}/CONTROLFILE/{current_controlfile_name}'
*.db_create_file_dest='{destination_data_diskgroup}'
*.db_recovery_file_dest='{destination_recovery_diskgroup}'
*.db_recovery_file_dest_size={fra_size}
*.wallet_root='{destination_wallet_root}/{source_db_unique_name_lower}'
*.tde_configuration='KEYSTORE_CONFIGURATION=FILE'
*.compatible='{database_compatible_version}'
*.cluster_database=TRUE
*.remote_login_passwordfile='EXCLUSIVE'

{destination_instance_1}.instance_number={instance_number_1}
{destination_instance_1}.thread={redo_thread_1}
{destination_instance_1}.undo_tablespace='{undo_tablespace_1}'

{destination_instance_2}.instance_number={instance_number_2}
{destination_instance_2}.thread={additional_redo_thread_number}
{destination_instance_2}.undo_tablespace='{undo_tablespace_2}'
Identify the restored control file name in ASM:
asmcmd ls {destination_data_diskgroup}/{destination_db_unique_name}/CONTROLFILE
Create the spfile in ASM:
sqlplus / as sysdba
STARTUP NOMOUNT PFILE='{rac_pfile_path}';
CREATE SPFILE='{destination_data_diskgroup}/{destination_db_unique_name}/PARAMETERFILE/spfile{source_db_unique_name_lower}.ora'
FROM PFILE='{rac_pfile_path}';
SHUTDOWN IMMEDIATE;
EXIT;
Step 2 - Add redo threads for additional RAC instances
Start one instance in mount/open mode with the RAC-ready spfile, then add redo for additional threads when needed.
sqlplus / as sysdba
STARTUP MOUNT;

SELECT thread#, status, enabled FROM v$thread ORDER BY thread#;
SELECT group#, thread#, bytes/1024/1024 AS mb, status FROM v$log ORDER BY thread#, group#;

ALTER DATABASE ADD LOGFILE THREAD {additional_redo_thread_number}
 GROUP {redo_group_1} ('{destination_data_diskgroup}', '{destination_recovery_diskgroup}') SIZE {redo_log_size} REUSE;

ALTER DATABASE ADD LOGFILE THREAD {additional_redo_thread_number}
 GROUP {redo_group_2} ('{destination_data_diskgroup}', '{destination_recovery_diskgroup}') SIZE {redo_log_size} REUSE;

ALTER DATABASE ENABLE PUBLIC THREAD {additional_redo_thread_number};

ALTER DATABASE OPEN;
ALTER PLUGGABLE DATABASE ALL OPEN;
ALTER PLUGGABLE DATABASE ALL SAVE STATE;
SHUTDOWN IMMEDIATE;
EXIT;
Skip the add-logfile commands for any thread that already exists with adequate redo log groups and sizes.
Step 3 - Register the recovered database with Oracle Clusterware
Use the database-home srvctl for the database resource version.

command -v asmcmd || {
 export GRID_HOME={destination_grid_home}
 export PATH=${GRID_HOME}/bin:${PATH}
 command -v asmcmd
}

asmcmd mkdir {destination_data_diskgroup}/{destination_db_unique_name}/PASSWORD
asmcmd cp ${ORACLE_HOME}/dbs/orapw{source_db_unique_name_lower} {destination_data_diskgroup}/{destination_db_unique_name}/PASSWORD/orapw{source_db_unique_name_lower}

srvctl add database \
 -db {destination_db_unique_name} \
 -dbname {source_db_name} \
 -oraclehome {destination_oracle_home} \
 -spfile {destination_data_diskgroup}/{destination_db_unique_name}/PARAMETERFILE/spfile{source_db_unique_name_lower}.ora \
 -pwfile {destination_data_diskgroup}/{destination_db_unique_name}/PASSWORD/orapw{source_db_unique_name_lower} \
 -role PRIMARY \
 -startoption open \
 -stopoption immediate \
 -diskgroup {destination_data_diskgroup_name},{destination_recovery_diskgroup_name}

srvctl add instance -db {destination_db_unique_name} -instance {destination_instance_1} -node {destination_node_1}
srvctl add instance -db {destination_db_unique_name} -instance {destination_instance_2} -node {destination_node_2}

srvctl config database -db {destination_db_unique_name}
srvctl start database -db {destination_db_unique_name}
srvctl status database -db {destination_db_unique_name}
Open and save PDB state across RAC instances:
sqlplus / as sysdba
ALTER PLUGGABLE DATABASE ALL OPEN INSTANCES=ALL;
ALTER PLUGGABLE DATABASE ALL SAVE STATE INSTANCES=ALL;
EXIT;
Step 4 - Recreate services and complete client cutover
Recreate application services from the pre-disaster srvctl config service output.
srvctl add service \
 -db {destination_db_unique_name} \
 -service {service_name} \
 -preferred {destination_instance_1},{destination_instance_2} \
 -pdb {pdb_name}

srvctl start service -db {destination_db_unique_name} -service {service_name}
srvctl status service -db {destination_db_unique_name}

Phase 5 - Register with Cloud Protect and Complete level 0 backup

Step 1 - Register it with Cloud Protect as a Protected Database
sql /nolog
SQL> rcv add sysbackup_user -db_unique_name {destination_db_unique_name_lower}
SQL> exit

Verify the above step completed successfully before proceeding.

Before any Cloud Protect onboarding operation, verify that the Oracle software owner is a member of the OSBACKUPDBA group (typically backupdba) and can successfully make a local OS-authenticated connection to the target database as SYSBACKUP.

${SQLCL_HOME}/bin/sql -name {destination_rcv_connection_name}
SQL> rcv add database -endpoint {recovery_service_endpoint} -compartment_id {compartment_ocid} -recovery_service_subnets {recovery_service_subnet_ocid} -protection_policy_name {protection_policy_name}
SQL> exit

Verify the above step completed successfully before proceeding.

Step 2 - Enable Real Time Redo
Validate RTR is enabled (if previously was enabled)
${SQLCL_HOME}/bin/sql -name {destination_rcv_connection_name}
SQL> rcv show database
SQL> rcv add realtime_redo
SQL> exit

Verify the above step completed successfully before proceeding.

Step 3 - Complete full backup
${SQLCL_HOME}/bin/sql -name {destination_rcv_connection_name}
SQL> rcv show database
SQL> rcv add schedule -interval {backup_schedule_interval_minutes}
SQL> rcv backup database -level 0
SQL> rcv show restore_range -db_unique_name {destination_db_unique_name_lower}
SQL> exit

Verify the above step completed successfully before proceeding.

Step 4 - Complete Healthchecks
Validate Fleet agent scheduler is accurately processing backups.
Health checks for the scheduler process:
${SQLCL_HOME}/bin/sql -name {destination_rcv_connection_name}
SQL> rcv run checks -name SCHEDULER_STATUS
SQL> rcv run checks -group health
SQL> exit


Appendix A - Required Input Detail

Input	Example / Observed Value	Collection / Why It Is Required
Recovery mode	Production disaster replacement or test/drill restore	Determines whether the recovered database can reuse the original DB_UNIQUE_NAME or must use a distinct value.
Recovery target	<timestamp> SCN, restore point, or latest available	Must be inside the restore range returned by Cloud Protect. Use rcv show restore_range -db_unique_name c1db1.
Source DB name		Required because the restored control file and RMAN catalog identify the database by DB_NAME and DBID.
Source DB unique name		Used to identify the protected source database in Cloud Protect, RCV metadata, wallet paths, and restore-range checks.
Source DBID		Required for control file restore from autobackup and for verifying the RMAN catalog identity. Collect from runbooks, prior RMAN logs, LIST INCARNATION, or preserved control file autobackup information.
Source protected database OCID		Required when importing or validating the lost source protected database metadata on the destination host.
Recovery Service endpoint		Required for rcv import database and rcv add database when the endpoint is not inferred.
Compartment OCID	{compartment_ocid}	Required for Cloud Protect registration and recovery service subnet association.
Recovery service subnet OCID	{recovery_service_subnet_ocid}	Required so the recovered database can reach OCI Recovery Service through the correct networking path.
Protection policy		Required when registering the recovered database as a protected database. Confirm retention and RPO expectations before use.
Source RCV connection		Used before disaster, or from restored metadata, to run source-oriented Cloud Protect checks when the source database identity is being referenced.
Replacement RCV connection		Used after recovery registration to run rcv show database, real-time redo configuration, backup, schedule, and health-check commands against the recovered database.
Source DBRS catalog alias		Used by RMAN during restore and recovery to connect to the Recovery Service catalog for the lost source protected database.
Replacement DBRS catalog alias		Used after Cloud Protect re-registration and post-recovery backup of the replacement database.
Control file backup handle		Required if RESTORE CONTROLFILE FROM AUTOBACKUP cannot locate the desired control file automatically.
Destination cluster hosts		Required for restore execution, Clusterware registration, RAC instance placement, and service configuration.
Destination Oracle owner		Required for running SQLcl, RMAN, sqlplus, and database-home srvctl commands.
Destination Grid home	{destination_grid_home}	Required when asmcmd or Grid-home utilities are not already in PATH.
Destination Oracle home		Required for destination sqlplus, RMAN, SBT library, password file placement, and database-home srvctl.
SQLcl path		Required for Cloud Protect rcv commands and named RCV connections.
Destination DB name		Must match the source DB_NAME for RMAN restore from the source backup and restored control file.
Destination DB unique name		Use a distinct value for drills. Use the original value only for the final production replacement after the old source identity is gone.
Destination Oracle SID		Used to start the single-instance replacement database for restore and recovery.
Destination RAC instances		Required when converting the restored single-instance database back to RAC and registering instances with Clusterware.
Destination data diskgroup		Used for OMF datafiles, control files, password file, SPFILE, BCT, and redo placement as configured.
Destination recovery diskgroup		Used for FRA, archived redo, recovery files, and optional multiplexed online redo placement.
FRA size		Must be large enough for restored archived redo, recovery operations, and post-RESETLOGS activity.
TDE wallet root		Required before media recovery reads encrypted tablespaces.
TDE keystore backup		Required because the source cluster is unavailable. If lost, encrypted tablespaces cannot be recovered.
Wallet password		Required when the keystore is password-based or when creating an auto-login keystore from a password-based keystore.
Password file source		Required to create the destination password file and support RMAN/Clusterware authentication.
Destination password file		Required for the single-instance restore and later RAC Clusterware registration.
Source configuration backup		Required to recreate initialization parameters, RAC instance/thread layout, services, and client cutover configuration.
Redo thread and undo layout		Required to validate or recreate RAC redo threads and per-instance undo settings.
PDB state requirements		Required to validate recovered PDBs and preserve expected open state after RAC startup.
Application service definitions		Required to recreate services and complete client cutover.
Cutover data	DNS targets, client connect strings, monitoring changes	Required to route applications and operations to the recovered database.
Real-time redo requirement	Match source setting when previously enabled	Required to decide whether to run rcv add realtime_redo after Cloud Protect re-registration.
Post-recovery level 0 window	Approved backup window after RESETLOGS	Required because a fresh full backup establishes the recovered database's new protection baseline.
"""


# Logging setup
def setup_logging():
    # Resolve log level from env, default to INFO
    level_name = os.getenv("ORACLE_MCP_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    log_to_stdout_env = os.getenv("ORACLE_MCP_LOG_TO_STDOUT")
    if log_to_stdout_env is None:
        os.environ["ORACLE_MCP_LOG_TO_STDOUT"] = "0"

    # Compute default log dir relative to project root; allow env override
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
    log_dir = os.getenv("ORACLE_MCP_LOG_DIR", os.path.join(base_dir, "logs"))
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.getenv("ORACLE_MCP_LOG_FILE", os.path.join(log_dir, "oci_recovery_mcp_server.log"))

    # Configure root logger once
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S%z",
    )

    # Add a rotating file handler if not already present for this file
    abs_log_file = os.path.abspath(log_file)
    has_file = any(
        isinstance(h, RotatingFileHandler) and getattr(h, "baseFilename", "") == abs_log_file
        for h in root_logger.handlers
    )
    if not has_file:
        fh = RotatingFileHandler(abs_log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8")
        fh.setLevel(level)
        fh.setFormatter(formatter)
        root_logger.addHandler(fh)

    # Optional console handler (default on; set ORACLE_MCP_LOG_TO_STDOUT=0 to disable)
    if os.getenv("ORACLE_MCP_LOG_TO_STDOUT", "0").lower() in (
        "1",
        "true",
        "yes",
        "y",
    ):
        has_stream = any(
            isinstance(h, logging.StreamHandler) and not isinstance(h, RotatingFileHandler)
            for h in root_logger.handlers
        )
        if not has_stream:
            sh = logging.StreamHandler()
            sh.setLevel(level)
            sh.setFormatter(formatter)
            root_logger.addHandler(sh)

    # Quiet noisy libraries by default; override with ORACLE_SDK_LOG_LEVEL
    logging.getLogger("oci").setLevel(os.getenv("ORACLE_SDK_LOG_LEVEL", "WARNING"))
    logging.getLogger("urllib3").setLevel("WARNING")


setup_logging()
logger = logging.getLogger(__name__)

# Exhaustive structured logging helpers

_LOG_MAX_VALUE_CHARS = int(os.getenv("ORACLE_MCP_LOG_MAX_VALUE_CHARS", "20000"))
_LOG_REDACT_KEYS = {
    k.strip().lower()
    for k in os.getenv(
        "ORACLE_MCP_LOG_REDACT_KEYS",
        (
            "authorization,token,security_token,security_token_file,private_key,key_file,"
            "passphrase,password,secret,client_secret"
        ),
    ).split(",")
    if k.strip()
}


def _truncate_str(s: str) -> str:
    if _LOG_MAX_VALUE_CHARS and len(s) > _LOG_MAX_VALUE_CHARS:
        return s[:_LOG_MAX_VALUE_CHARS] + f"...(truncated,len={len(s)})"
    return s


def _safe_jsonable(obj: Any) -> Any:
    try:
        if obj is None or isinstance(obj, (bool, int, float, str)):
            return _truncate_str(obj) if isinstance(obj, str) else obj
        if isinstance(obj, (list, tuple)):
            return [_safe_jsonable(x) for x in obj]
        if isinstance(obj, dict):
            out: dict[str, Any] = {}
            for k, v in obj.items():
                key_l = str(k).lower()
                if any(rk in key_l for rk in _LOG_REDACT_KEYS):
                    out[str(k)] = "***REDACTED***"
                else:
                    out[str(k)] = _safe_jsonable(v)
            return out

        # OCI SDK & pydantic helpers
        try:
            if hasattr(oci, "util") and hasattr(oci.util, "to_dict"):
                d = oci.util.to_dict(obj)
                if isinstance(d, dict):
                    return _safe_jsonable(d)
        except Exception:
            pass

        if hasattr(obj, "model_dump"):
            try:
                return _safe_jsonable(obj.model_dump(exclude_none=False, by_alias=True))
            except Exception:
                pass
        if hasattr(obj, "dict"):
            try:
                return _safe_jsonable(obj.dict(exclude_none=False, by_alias=True))
            except Exception:
                pass
        if hasattr(obj, "__dict__"):
            try:
                return _safe_jsonable(dict(obj.__dict__))
            except Exception:
                pass

        return _truncate_str(repr(obj))
    except Exception:
        return "<unserializable>"


def _log_event(
    event: str,
    *,
    request_id: str,
    tool: Optional[str] = None,
    phase: Optional[str] = None,
    payload: Optional[dict[str, Any]] = None,
    level: int = logging.INFO,
):
    rec = {
        "event": event,
        "request_id": request_id,
        "tool": tool,
        "phase": phase,
        "payload": _safe_jsonable(payload or {}),
    }
    # Log as single-line JSON for easy grepping / ingestion
    try:
        logger.log(level, json.dumps(rec, ensure_ascii=False, default=str))
    except Exception:
        logger.log(level, str(rec))


def _wrap_oci_client(client: Any, *, request_id: str, client_name: str):
    """Proxy that logs every SDK method call + response summary, without changing behavior."""

    class _Proxy:
        def __init__(self, inner: Any):
            self._inner = inner

        def __getattr__(self, name: str):
            attr = getattr(self._inner, name)
            if not callable(attr):
                return attr

            def _call(*args, **kwargs):
                start = time.time()
                _log_event(
                    "oci_call",
                    request_id=request_id,
                    tool=None,
                    phase="start",
                    payload={
                        "client": client_name,
                        "method": name,
                        "args": _safe_jsonable(args),
                        "kwargs": _safe_jsonable(kwargs),
                    },
                )
                try:
                    resp = attr(*args, **kwargs)
                    dur_ms = int((time.time() - start) * 1000)
                    # Response object may be oci.response.Response or other
                    payload = {
                        "client": client_name,
                        "method": name,
                        "duration_ms": dur_ms,
                    }
                    try:
                        payload["status"] = getattr(resp, "status", None)
                        payload["headers"] = getattr(resp, "headers", None)
                        payload["request_id"] = getattr(resp, "request_id", None)
                        payload["opc_request_id"] = getattr(resp, "opc_request_id", None)
                        payload["has_next_page"] = getattr(resp, "has_next_page", None)
                        payload["next_page"] = getattr(resp, "next_page", None)
                    except Exception:
                        pass
                    # Log full data as requested (may be truncated)
                    try:
                        payload["data"] = _safe_jsonable(getattr(resp, "data", resp))
                    except Exception:
                        payload["data"] = "<unavailable>"
                    _log_event(
                        "oci_call",
                        request_id=request_id,
                        tool=None,
                        phase="end",
                        payload=payload,
                    )
                    return resp
                except Exception as e:
                    dur_ms = int((time.time() - start) * 1000)
                    _log_event(
                        "oci_call",
                        request_id=request_id,
                        tool=None,
                        phase="error",
                        payload={
                            "client": client_name,
                            "method": name,
                            "duration_ms": dur_ms,
                            "error": str(e),
                            "traceback": traceback.format_exc(),
                        },
                        level=logging.ERROR,
                    )
                    raise

            return _call

    return _Proxy(client)


def _tool_logger(tool_name: str):
    """
    Decorator to log MCP tool inputs/outputs/errors with a correlation id.

    IMPORTANT (FastMCP constraint):
    FastMCP tool functions must NOT use *args or **kwargs in their signature.
    So this decorator MUST preserve the original function signature.

    We therefore wrap by delegating with the original signature via ParamSpec.
    """
    from functools import wraps
    from typing import ParamSpec, TypeVar

    P = ParamSpec("P")
    R = TypeVar("R")

    def _decorator(fn: Callable[P, R]) -> Callable[P, R]:
        @wraps(fn)
        def _wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
            request_id = uuid.uuid4().hex
            start = time.time()
            _log_event(
                "tool_call",
                request_id=request_id,
                tool=tool_name,
                phase="start",
                payload={
                    "args": _safe_jsonable(args),
                    "kwargs": _safe_jsonable(kwargs),
                },
            )
            try:
                out = fn(*args, **kwargs)
                dur_ms = int((time.time() - start) * 1000)
                _log_event(
                    "tool_call",
                    request_id=request_id,
                    tool=tool_name,
                    phase="end",
                    payload={"duration_ms": dur_ms, "result": _safe_jsonable(out)},
                )
                return out
            except Exception as e:
                dur_ms = int((time.time() - start) * 1000)
                _log_event(
                    "tool_call",
                    request_id=request_id,
                    tool=tool_name,
                    phase="error",
                    payload={
                        "duration_ms": dur_ms,
                        "error": str(e),
                        "traceback": traceback.format_exc(),
                    },
                    level=logging.ERROR,
                )
                raise

        return _wrapped

    return _decorator


# Auth/Config


def _effective_auth_method() -> Literal["session", "apikey", "oauth"]:
    """
    Auth selection is done strictly via environment variables (set by the MCP host).

    Required:
      - ORACLE_MCP_AUTH_METHOD: "session", "apikey", or "oauth"

    Optional:
      - ORACLE_MCP_AUTH_PROFILE: OCI config profile name (defaults to OCI_CONFIG_PROFILE/DEFAULT)

    Modes:
      - "session" / "apikey": local ~/.oci/config based auth. Works over stdio (default)
        or the plain HTTP transport (ORACLE_MCP_HOST/ORACLE_MCP_PORT).
      - "oauth": OCI IAM (IDCS) domain OAuth + UPST token exchange, served over the
        streamable HTTP transport. No local OCI config file is needed; a per-request
        UPST signer is built from the authenticated user's IAM domain access token.
    """
    m = (os.getenv("ORACLE_MCP_AUTH_METHOD") or "session").strip().lower()
    if m in ("apikey", "api_key", "api-key"):
        return "apikey"
    if m in ("oauth", "token_exchange", "token-exchange", "upst"):
        return "oauth"
    return "session"


def _effective_profile_name() -> str:
    prof = (os.getenv("ORACLE_MCP_AUTH_PROFILE") or "").strip()
    if prof:
        return prof
    return os.getenv("OCI_CONFIG_PROFILE", oci.config.DEFAULT_PROFILE)


def _first_env(*names: str, default: Optional[str] = None) -> Optional[str]:
    """Return the first non-empty environment variable among names."""
    for n in names:
        v = os.getenv(n)
        if v is not None and v.strip() != "":
            return v.strip()
    return default


def _env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "y", "on")


def _load_oci_config_for_server() -> dict:
    config = oci.config.from_file(profile_name=_effective_profile_name())
    user_agent_name = __project__.split("oracle.", 1)[1].split("-server", 1)[0]
    config["additional_user_agent"] = f"{user_agent_name}/{__version__}"
    return config


def _build_signer_for_session(config: dict):
    private_key = oci.signer.load_private_key_from_file(config["key_file"])
    token_file = config["security_token_file"]
    with open(token_file, "r", encoding="utf-8") as f:
        token = f.read()
    return oci.auth.signers.SecurityTokenSigner(token, private_key)


# ---------------- OAuth / token-exchange (single hosted, multi-tenancy) ----------------
#
# In "oauth" mode one process serves many tenancies behind a single MCP URL.
# Per-tenancy IDCS domain + confidential OAuth app secrets live in a server-side
# tenancy registry (ORACLE_MCP_TENANCY_REGISTRY). A user selects their tenancy
# with the X-OCI-Tenancy header; FastMCP's per-tenancy OCIProvider (see
# multitenant_auth) handles login. The header is enforced at verification (a token
# is only accepted for the tenancy it names; a mismatch -> 401 -> re-auth), and the
# verified token carries the tenant alias (oracle_mcp_tenant_alias claim), which is
# AUTHORITATIVE for all tool routing.
#
# Each tool call exchanges the user's IAM domain JWT for an OCI UPST token using
# TokenExchangeSigner (built from the resolved tenancy's IDCS domain + credentials).
# The signer self-refreshes the UPST, so we cache it per (tenant alias, token jti).

# Legacy single-tenant env vars: used to synthesize a one-entry registry when no
# registry file is configured (backward compatibility / simple single-tenant hosting).
_ENV_IDCS_DOMAIN = ("ORACLE_MCP_IDCS_DOMAIN", "IDCS_DOMAIN")
_ENV_IDCS_CLIENT_ID = ("ORACLE_MCP_IDCS_CLIENT_ID", "IDCS_CLIENT_ID")
_ENV_IDCS_CLIENT_SECRET = ("ORACLE_MCP_IDCS_CLIENT_SECRET", "IDCS_CLIENT_SECRET")

_oauth_signer_cache: dict[str, Any] = {}
_oauth_signer_lock = threading.Lock()
_OAUTH_SIGNER_CACHE_MAX = int(os.getenv("ORACLE_MCP_OAUTH_SIGNER_CACHE_MAX", "256"))

_registry_singleton: Optional[TenancyRegistry] = None
_registry_lock = threading.Lock()


def _legacy_single_tenant_registry() -> Optional[TenancyRegistry]:
    """Build a one-entry registry from the legacy single-tenant env vars, if set."""
    domain = _first_env(*_ENV_IDCS_DOMAIN)
    client_id = _first_env(*_ENV_IDCS_CLIENT_ID)
    client_secret = _first_env(*_ENV_IDCS_CLIENT_SECRET)
    tenancy_id = _first_env("ORACLE_MCP_TENANCY_ID", "TENANCY_ID_OVERRIDE")
    region = _first_env("ORACLE_MCP_REGION", "OCI_REGION")
    if not (domain and client_id and client_secret and tenancy_id and region):
        return None
    alias = _first_env("ORACLE_MCP_TENANCY_ALIAS", default="default")
    body: dict[str, Any] = {
        "tenancy_id": tenancy_id,
        "idcs_domain": domain,
        "client_id": client_id,
        "client_secret": client_secret,
        "region": region,
    }
    signing_key = _first_env("ORACLE_MCP_JWT_SIGNING_KEY")
    if signing_key:
        body["jwt_signing_key"] = signing_key
    return TenancyRegistry.from_mapping({alias: body})


def _get_registry() -> TenancyRegistry:
    """Load (and cache) the tenancy registry from file or legacy env vars."""
    global _registry_singleton
    if _registry_singleton is not None:
        return _registry_singleton
    with _registry_lock:
        if _registry_singleton is None:
            if (os.getenv("ORACLE_MCP_TENANCY_REGISTRY") or "").strip():
                _registry_singleton = load_registry()
            else:
                reg = _legacy_single_tenant_registry()
                if reg is None:
                    raise RegistryError(
                        "oauth mode requires either ORACLE_MCP_TENANCY_REGISTRY (a "
                        "tenancies.toml file) or the legacy single-tenant env vars "
                        "(ORACLE_MCP_IDCS_DOMAIN, ORACLE_MCP_IDCS_CLIENT_ID, "
                        "ORACLE_MCP_IDCS_CLIENT_SECRET, ORACLE_MCP_TENANCY_ID, "
                        "ORACLE_MCP_REGION)."
                    )
                _registry_singleton = reg
    return _registry_singleton


def _reset_registry_cache() -> None:
    """Test hook: drop the cached registry so the next call re-reads the env."""
    global _registry_singleton
    with _registry_lock:
        _registry_singleton = None


def _current_tenancy() -> TenancyEntry:
    """
    Resolve the tenancy for the current request from the verified token's
    `oracle_mcp_tenant_alias` claim, which is authoritative for all tool routing.

    Header/token consistency is already enforced upstream: MultiTenantOCIAuth.verify_token
    narrows verification to the X-OCI-Tenancy tenancy, so a token that doesn't match a
    known header value is rejected with 401 (the client re-authenticates) before any tool
    runs. The cross-check below is only a defensive backstop for the rare case where the
    header could not be read during verification; it warns (aliases only) and trusts the
    token.
    """
    from fastmcp.server.dependencies import get_access_token

    alias = None
    try:
        access = get_access_token()
        if access is not None:
            alias = (access.claims or {}).get(TENANT_CLAIM)
    except Exception:
        alias = None

    entry = _get_registry().lookup(alias) if alias else None
    if entry is None:
        raise ValueError(
            "No authenticated tenancy on this request. The access token is missing the "
            "tenant claim; reconnect with the X-OCI-Tenancy header set."
        )

    # Defensive backstop only (token remains authoritative).
    try:
        from fastmcp.server.dependencies import get_http_headers

        hdr = (get_http_headers() or {}).get("x-oci-tenancy")
    except Exception:
        hdr = None
    if hdr:
        hdr_entry = _get_registry().lookup(hdr)
        if hdr_entry is not None and hdr_entry.alias != entry.alias:
            logger.warning(
                "X-OCI-Tenancy header (alias=%s) conflicts with the authenticated "
                "tenancy (alias=%s); using the token's tenancy.",
                hdr_entry.alias,
                entry.alias,
            )
    return entry


def _build_token_exchange_signer(entry: TenancyEntry):
    """
    Build (or reuse) a TokenExchangeSigner for the current user + tenancy.

    The IAM domain JWT is taken from the active request's access token. The signer
    self-refreshes the UPST, so we cache it keyed by (tenant alias, token jti) to
    avoid a token exchange on every tool call and to keep tenancies isolated.
    """
    from fastmcp.server.dependencies import get_access_token
    from oci.auth.signers import TokenExchangeSigner

    access_token = get_access_token()
    token = access_token.token
    try:
        jti = access_token.claims.get("jti")
    except Exception:
        jti = None
    if not jti:
        jti = str(hash(token))

    cache_key = f"{entry.alias}:{jti}"
    cached = _oauth_signer_cache.get(cache_key)
    if cached is not None:
        return cached

    # Newer OCI SDKs take the full domain URL (oci_domain_url); older ones take the
    # domain id prefix (oci_domain_id). Pick whichever the installed SDK supports.
    import inspect

    tes_params = inspect.signature(TokenExchangeSigner.__init__).parameters
    domain_kwargs: dict[str, str] = {}
    if "oci_domain_url" in tes_params:
        domain_kwargs["oci_domain_url"] = _domain_to_url(entry.idcs_domain)
    else:
        domain_kwargs["oci_domain_id"] = entry.idcs_domain.split(".")[0]

    try:
        signer = TokenExchangeSigner(
            jwt_or_func=token,
            client_id=entry.client_id,
            client_secret=entry.client_secret,
            **domain_kwargs,
        )
    except Exception as e:
        # Surface the IAM domain's actual error body instead of a bare
        # "401 Unauthorized". A 401/403 here almost always means the OCI side is
        # not set up to exchange the user JWT for a UPST yet: a missing or
        # misconfigured Identity Propagation Trust, the confidential app missing
        # the token-exchange/client-credentials grant, or wrong client credentials.
        # Note: we log the tenancy alias (never the client secret) plus the IAM
        # error body, which is a diagnostic description and contains no secrets.
        resp = getattr(e, "response", None)
        detail = ""
        if resp is not None:
            try:
                detail = f" | IAM {resp.status_code}: {resp.text}"
            except Exception:
                pass
        logger.error(
            "OCI UPST token exchange failed for tenancy alias=%s%s",
            entry.alias,
            detail,
            exc_info=True,
        )
        raise RuntimeError(
            "OCI UPST token exchange failed. The OCI IAM domain rejected the request to "
            "exchange the user's token for a UPST. Verify, in this tenancy's IAM domain: "
            "(1) an Identity Propagation Trust exists that lists this client_id; (2) the "
            "confidential app has the Authorization Code and Client Credentials grants; "
            "(3) the registry's client_id/client_secret are correct." + detail
        ) from e

    with _oauth_signer_lock:
        if len(_oauth_signer_cache) >= _OAUTH_SIGNER_CACHE_MAX:
            _oauth_signer_cache.clear()
        _oauth_signer_cache[cache_key] = signer

    return signer


def _oauth_base_config(entry: TenancyEntry, region: str | None = None) -> dict:
    """Minimal OCI client config for oauth mode (no local OCI config file)."""
    reg = region or entry.region
    if not reg:
        raise ValueError(
            f"oauth mode requires a region for tenancy '{entry.alias}': set it in the "
            "registry or pass an explicit region."
        )
    user_agent_name = __project__.split("oracle.", 1)[1].split("-server", 1)[0]
    return {"region": reg, "additional_user_agent": f"{user_agent_name}/{__version__}"}


def _effective_region(default: Optional[str] = None) -> Optional[str]:
    """
    Resolve the OCI region without requiring a local config file.

    - oauth mode: the authenticated tenancy's region, else default.
    - session/apikey mode: the configured profile's region, else default.
    """
    if _effective_auth_method() == "oauth":
        try:
            return _current_tenancy().region or default
        except Exception:
            return _first_env("ORACLE_MCP_REGION", "OCI_REGION", default=default)
    try:
        return _load_oci_config_for_server().get("region") or default
    except Exception:
        return default


def _make_client(
    ctor: Callable[..., Any],
    region: str | None = None,
    *,
    client_name: str,
    request_id: Optional[str] = None,
):
    """
    Construct and wrap an OCI SDK client using the effective auth method.

    - oauth: minimal regional config + per-request UPST TokenExchangeSigner.
    - apikey: regional config from ~/.oci/config (SDK uses API key fields).
    - session: regional config + SecurityTokenSigner from the session token files.
    """
    method = _effective_auth_method()
    if method == "oauth":
        entry = _current_tenancy()
        config = _oauth_base_config(entry, region)
        signer = _build_token_exchange_signer(entry)
        client = ctor(config, signer=signer)
    else:
        config = _load_oci_config_for_server()
        regional_config = config if region is None else {**config, "region": region}
        if method == "apikey":
            client = ctor(regional_config)
        else:
            signer = _build_signer_for_session(regional_config)
            client = ctor(regional_config, signer=signer)

    rid = request_id or uuid.uuid4().hex
    return _wrap_oci_client(client, request_id=rid, client_name=client_name)


def _default_oauth_storage_root() -> str:
    """Default per-tenant OAuth state location (overridable via env)."""
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
    return os.path.join(base_dir, ".oauth_state")


def _build_auth_provider():
    """
    Build the FastMCP auth provider for oauth mode (returns None otherwise).

    In oauth mode we serve many tenancies behind a single MCP URL via
    MultiTenantOCIAuth, which builds one OCIProvider (OIDC proxy) per tenancy from
    the server-side registry. Persistence knobs (consent off, persisted per-tenant
    signing keys, on-disk client storage, offline_access scope) keep logins sticky
    so users are not re-prompted on every tool call.
    """
    if _effective_auth_method() != "oauth":
        return None

    registry = _get_registry()
    base_url = _first_env("ORACLE_MCP_BASE_URL", "MCP_BASE_URL", default="http://localhost:8000")
    storage_root = _first_env("ORACLE_MCP_OAUTH_STORAGE_DIR", default=_default_oauth_storage_root())
    redirect_path = _first_env("ORACLE_MCP_OAUTH_REDIRECT_PATH", default="/auth/callback")
    scopes = (_first_env("ORACLE_MCP_OAUTH_SCOPES", default="openid offline_access") or "").split()
    require_consent = _env_bool("ORACLE_MCP_OAUTH_REQUIRE_CONSENT", default=False)

    logger.info(
        "Configuring multi-tenant OCI IAM OAuth (tenancies=%d, base_url=%s, consent=%s)",
        len(registry),
        base_url,
        require_consent,
    )
    return MultiTenantOCIAuth(
        registry,
        base_url=base_url,
        storage_root=storage_root,
        required_scopes=scopes,
        require_authorization_consent=require_consent,
        redirect_path=redirect_path,
    )


# Create the FastMCP app that exposes the functions decorated with @mcp.tool.
# In oauth mode this attaches the OCI IAM OAuth provider; otherwise auth is None.
mcp = FastMCP(name=__project__, auth=_build_auth_provider())


def get_recovery_client(
    region: str | None = None,
    *,
    request_id: Optional[str] = None,
) -> oci.recovery.DatabaseRecoveryClient:
    """Create a Recovery Service client using auth selected via env vars."""
    return _make_client(
        oci.recovery.DatabaseRecoveryClient,
        region,
        client_name="recovery",
        request_id=request_id,
    )


def get_identity_client(*, request_id: Optional[str] = None):
    return _make_client(
        oci.identity.IdentityClient,
        None,
        client_name="identity",
        request_id=request_id,
    )


def get_database_client(region: str | None = None, *, request_id: Optional[str] = None):
    return _make_client(
        oci.database.DatabaseClient,
        region,
        client_name="database",
        request_id=request_id,
    )


def get_work_request_client(region: str | None = None, *, request_id: Optional[str] = None):
    """Create an OCI Work Requests client using auth selected via env vars."""
    return _make_client(
        oci.work_requests.WorkRequestClient,
        region,
        client_name="work_requests",
        request_id=request_id,
    )


def get_monitoring_client(region: str | None = None, *, request_id: Optional[str] = None):
    logger.info("entering get_monitoring_client")
    return _make_client(
        oci.monitoring.MonitoringClient,
        region,
        client_name="monitoring",
        request_id=request_id,
    )


def get_limits_client(region: str | None = None, *, request_id: Optional[str] = None):
    """Create an OCI Limits client using auth selected via env vars."""
    return _make_client(
        oci.limits.LimitsClient,
        region,
        client_name="limits",
        request_id=request_id,
    )


def get_onesubscription_client(region: str | None = None, *, request_id: Optional[str] = None):
    """
    Create a OneSubscription SubscribedService client.

    We use this to discover which regions a tenancy is subscribed to for a given service,
    so we can execute compartment-scoped queries across all relevant regions.
    """
    return _make_client(
        oci.onesubscription.SubscribedServiceClient,
        region,
        client_name="onesubscription",
        request_id=request_id,
    )


# ---------------- Subscribed regions helpers ----------------

def _tenant_cache_key() -> str:
    """
    Stable per-tenant key for the in-process caches.

    In the single-hosted oauth deployment one process serves many tenancies, so
    every in-process cache MUST be partitioned by tenant or one tenant's metadata
    would leak to another. get_tenancy() returns the per-request tenant OCID
    (from the verified token in oauth mode, or the local config otherwise).
    """
    try:
        return get_tenancy() or "_default"
    except Exception:
        return "_default"


_REGION_CACHE: dict[str, Any] = {
    "ttl_seconds": int(os.getenv("ORACLE_MCP_REGION_CACHE_TTL_SECONDS", "3600")),
    # items: dict[tenant_key -> {"regions": list[dict], "fetched_at": float}]
    "items": {},
}


def _iam_subscribed_regions_with_status(*, request_id: str) -> list[dict]:
    """
    Returns the tenancy's subscribed regions from IAM (IdentityClient.list_region_subscriptions).
    Output items are: {"region": "<region_name>", "status": "<READY|...>"}.

    Cached in-process for ORACLE_MCP_REGION_CACHE_TTL_SECONDS, partitioned per tenant.
    """
    now = time.time()
    ttl = float(_REGION_CACHE.get("ttl_seconds") or 3600)
    items = _REGION_CACHE.setdefault("items", {})

    tenancy_id = get_tenancy()
    cache_key = f"iam:list_region_subscriptions:{tenancy_id}"
    cached = items.get(cache_key)
    if cached and (now - float(cached.get("fetched_at") or 0.0)) < ttl:
        return cached.get("regions") or []

    identity = get_identity_client(request_id=request_id)
    resp = identity.list_region_subscriptions(tenancy_id=tenancy_id)
    subs = getattr(resp, "data", None) or []

    out: list[dict] = []
    for sub in subs:
        region_name = getattr(sub, "region_name", None) or getattr(sub, "regionName", None)
        status = getattr(sub, "status", None)
        if region_name:
            out.append({"region": region_name, "status": status})

    out = sorted(out, key=lambda x: x.get("region") or "")
    items[cache_key] = {"regions": out, "fetched_at": now}
    return out


def get_tenancy():
    # oauth mode: the tenancy is bound to the authenticated user's token (the
    # X-OCI-Tenancy header selects it at login; the verified claim is authoritative).
    if _effective_auth_method() == "oauth":
        return _current_tenancy().tenancy_id
    # session/apikey: explicit override, else the local OCI config's tenancy.
    override = _first_env("TENANCY_ID_OVERRIDE", "ORACLE_MCP_TENANCY_ID")
    if override:
        return override
    config = _load_oci_config_for_server()
    return config["tenancy"]


def list_all_compartments_internal(only_one_page: bool, limit=100):
    """Internal function to get List all compartments in a tenancy"""
    # Use IdentityClient to list all accessible ACTIVE compartments and include the root tenancy
    identity_client = get_identity_client()
    response = identity_client.list_compartments(
        compartment_id=get_tenancy(),
        compartment_id_in_subtree=True,
        access_level="ACCESSIBLE",
        lifecycle_state="ACTIVE",
        limit=limit,
    )
    compartments = response.data
    # Also include the tenancy itself
    compartments.append(identity_client.get_compartment(compartment_id=get_tenancy()).data)
    if only_one_page:  # limiting the number of items returned
        return compartments
    # Manual pagination loop
    while response.has_next_page:
        response = identity_client.list_compartments(
            compartment_id=get_tenancy(),
            compartment_id_in_subtree=True,
            access_level="ACCESSIBLE",
            lifecycle_state="ACTIVE",
            page=response.next_page,
            limit=limit,
        )
        compartments.extend(response.data)
    return compartments


# ---------------- Nested compartment helpers ----------------

_COMPARTMENT_CACHE: dict[str, Any] = {
    "ttl_seconds": int(os.getenv("ORACLE_MCP_COMPARTMENT_CACHE_TTL_SECONDS", "300")),
    # entries: dict[tenant_key -> {"items": list[Any], "fetched_at": float}]
    "entries": {},
}


def _list_all_compartments_cached(*, request_id: Optional[str] = None) -> list[Any]:
    """
    Return all accessible ACTIVE compartments in the tenancy (plus root tenancy)
    with a small in-process TTL cache to avoid repeated Identity scans.

    NOTE:
    - OCI CLI `oci iam compartment list --compartment-id <root>` returns ONLY direct children.
    - For our use-case (expand subtree), we list the full subtree using:
        list_compartments(compartment_id_in_subtree=True, access_level="ACCESSIBLE")
      and then build a parent->children index locally to BFS the descendants.
    """
    now = time.time()
    ttl = float(_COMPARTMENT_CACHE.get("ttl_seconds") or 300)
    entries = _COMPARTMENT_CACHE.setdefault("entries", {})
    tenant_key = _tenant_cache_key()
    cached = entries.get(tenant_key)

    if cached and cached.get("items") and (now - float(cached.get("fetched_at") or 0.0)) < ttl:
        return cached["items"]  # type: ignore[return-value]

    rid = request_id or uuid.uuid4().hex

    # Refresh cache
    try:
        comps = list_all_compartments_internal(False)

        # Normalize shape and ensure we always have the root tenancy in the list.
        # list_all_compartments_internal already tries to append tenancy, but we make it robust.
        tenancy_id = get_tenancy()
        seen_ids: set[str] = set()
        normalized: list[Any] = []

        for c in comps or []:
            try:
                cid = getattr(c, "id", None) or getattr(c, "ocid", None)
            except Exception:
                cid = None
            if not cid or cid in seen_ids:
                continue
            seen_ids.add(cid)
            normalized.append(c)

        if tenancy_id and tenancy_id not in seen_ids:
            try:
                identity_client = get_identity_client(request_id=rid)
                t = identity_client.get_compartment(compartment_id=tenancy_id).data
                normalized.append(t)
            except Exception:
                pass

        comps = normalized
    except Exception as e:
        # If identity listing fails, fall back to empty (callers will handle)
        _log_event(
            "compartment_cache_refresh_failed",
            request_id=rid,
            tool=None,
            phase="error",
            payload={"error": str(e)},
            level=logging.WARNING,
        )
        comps = []

    entries[tenant_key] = {"items": comps, "fetched_at": now}
    return comps


def _build_children_index(compartments: list[Any]) -> dict[str, list[str]]:
    """
    Build a parent->children map from identity compartment objects.

    Identity compartment model uses:
      - id: compartment OCID
      - compartment_id: parent OCID (called "compartment-id" in OCI CLI JSON)
    """
    children: dict[str, list[str]] = {}
    for c in compartments or []:
        try:
            cid = getattr(c, "id", None) or getattr(c, "ocid", None)
            pid = (
                getattr(c, "compartment_id", None)
                or getattr(c, "compartmentId", None)
                or getattr(c, "parent_id", None)
                or getattr(c, "parentId", None)
            )
            if not cid or not pid:
                continue
            children.setdefault(pid, []).append(cid)
        except Exception:
            continue
    return children


def _expand_compartment_scope(
    root_compartment_id: str,
    *,
    include_child_compartments: bool,
    request_id: Optional[str] = None,
) -> list[str]:
    """
    Expand a root compartment into a list including all descendant compartments (BFS)
    when include_child_compartments=True.

    Robustness:
    - Primary approach: use cached full-subtree identity listing (compartment_id_in_subtree=True)
      and build a parent->children index locally.
    - Fallback: if that yields only the root (common in restricted IAM environments),
      do a direct-children crawl using IdentityClient.list_compartments(compartment_id=<pid>)
      recursively.

    Safety:
    - Cap max compartments scanned via ORACLE_MCP_MAX_COMPARTMENTS_IN_SCOPE (default 200).
    """
    if not include_child_compartments:
        return [root_compartment_id]

    cap = int(os.getenv("ORACLE_MCP_MAX_COMPARTMENTS_IN_SCOPE", "200"))
    rid = request_id or uuid.uuid4().hex

    # ---------------- Primary: cached full-subtree listing ----------------
    try:
        comps = _list_all_compartments_cached(request_id=rid)
        children_index = _build_children_index(comps)

        scope: list[str] = []
        seen: set[str] = set()
        queue: list[str] = [root_compartment_id]

        while queue:
            cid = queue.pop(0)
            if cid in seen:
                continue
            seen.add(cid)
            scope.append(cid)

            if cap and len(scope) >= cap:
                _log_event(
                    "compartment_scope_capped",
                    request_id=rid,
                    tool=None,
                    phase="warn",
                    payload={"root": root_compartment_id, "cap": cap},
                    level=logging.WARNING,
                )
                return scope

            for child in children_index.get(cid, []) or []:
                if child not in seen:
                    queue.append(child)

        # If we found at least one child, we're done.
        if len(scope) > 1:
            return scope
    except Exception:
        # Fall through to direct-children crawl fallback
        pass

    # ---------------- Fallback: direct-children crawl ----------------
    try:
        identity_client = get_identity_client(request_id=rid)

        scope: list[str] = []
        seen: set[str] = set()
        queue: list[str] = [root_compartment_id]

        while queue:
            pid = queue.pop(0)
            if pid in seen:
                continue
            seen.add(pid)
            scope.append(pid)

            if cap and len(scope) >= cap:
                _log_event(
                    "compartment_scope_capped",
                    request_id=rid,
                    tool=None,
                    phase="warn",
                    payload={"root": root_compartment_id, "cap": cap},
                    level=logging.WARNING,
                )
                break

            next_page = None
            while True:
                resp = identity_client.list_compartments(
                    compartment_id=pid,
                    access_level="ACCESSIBLE",
                    lifecycle_state="ACTIVE",
                    limit=1000,
                    page=next_page,
                )
                for c in resp.data or []:
                    cid = getattr(c, "id", None) or getattr(c, "ocid", None)
                    if cid and cid not in seen:
                        queue.append(cid)

                has_next = bool(getattr(resp, "has_next_page", False))
                next_page = getattr(resp, "next_page", None) if has_next else None
                if not has_next:
                    break

        return scope
    except Exception:
        # Final fallback: only root
        return [root_compartment_id]


def _compartment_ids_for_tool(
    root_compartment_id: str,
    *,
    fetch_for_child_compartment: bool,
    request_id: Optional[str] = None,
) -> list[str]:
    """
    Helper used by tools to decide compartment scope.

    Behavior:
    - fetch_for_child_compartment=False  -> [root_compartment_id]
    - fetch_for_child_compartment=True   -> full subtree (including root)

    IMPORTANT:
    - We should avoid tool->tool style calls from inside server handlers.
    - Instead, we reuse the underlying internal helper `_expand_compartment_scope(...)`
      which implements robust subtree expansion with caching + fallback.
    """
    resolved_root = _resolve_compartment_id(root_compartment_id)

    if not fetch_for_child_compartment:
        return [resolved_root]

    rid = request_id or uuid.uuid4().hex

    try:
        ids = _expand_compartment_scope(
            resolved_root,
            include_child_compartments=True,
            request_id=rid,
        )
        if isinstance(ids, list) and ids:
            return [str(x) for x in ids if x]
    except Exception:
        pass

    # Final fallback: only root
    return [resolved_root]


def _fetch_db_home_ids_for_compartment(compartment_id: str, region: Optional[str] = None) -> list[str]:
    """
    Helper: enumerate DB Home OCIDs in a compartment.
    Used when a tool needs a db_home_id but the caller omitted it.
    Returns a list of DB Home OCIDs (may be empty).
    """
    try:
        client = get_database_client(region)
        resp = client.list_db_homes(compartment_id=compartment_id)
        data = resp.data
        # Normalize list shape (SDK may use .items or a raw list)
        raw_list = getattr(data, "items", data)
        raw_list = raw_list if isinstance(raw_list, list) else [raw_list] if raw_list is not None else []
        ids: list[str] = []
        for h in raw_list:
            # Try attribute access first
            hid = getattr(h, "id", None)
            if not hid:
                # Fall back to dict conversion if needed
                try:
                    d = (
                        getattr(oci.util, "to_dict")(h)
                        if hasattr(oci, "util") and hasattr(oci.util, "to_dict")
                        else None
                    )
                    if isinstance(d, dict):
                        hid = d.get("id")
                except Exception:
                    pass
            if hid:
                ids.append(hid)
        return ids
    except Exception:
        # Conservative: on error, return empty so callers can react (e.g., empty results)
        return []


def get_compartment_by_name(compartment_name: str):
    """Internal function to get compartment by name with caching"""
    compartments = list_all_compartments_internal(False)
    # Search for the compartment by name
    for compartment in compartments:
        if compartment.name.lower() == compartment_name.lower():
            return compartment

    return None


def _looks_like_ocid(value: Optional[str]) -> bool:
    return bool(value and isinstance(value, str) and value.strip().lower().startswith("ocid1."))


def _resolve_compartment_id(
    compartment_input: Optional[str],
    *,
    default_to_tenancy: bool = False,
) -> str:
    """
    Accept either a compartment OCID or a compartment display name and return an OCID.

    - If an OCID is provided, return it unchanged.
    - If a display name is provided, resolve it using get_compartment_by_name().
    - If omitted and default_to_tenancy is True, return the tenancy OCID.
    """
    if compartment_input is None:
        if default_to_tenancy:
            return get_tenancy()
        raise ValueError("compartment_id is required.")

    candidate = compartment_input.strip()
    if not candidate:
        if default_to_tenancy:
            return get_tenancy()
        raise ValueError("compartment_id cannot be empty.")

    if _looks_like_ocid(candidate):
        return candidate

    compartment = get_compartment_by_name(candidate)
    if compartment is None:
        raise ValueError(f"Compartment '{candidate}' not found.")

    resolved_id = getattr(compartment, "id", None)
    if not resolved_id:
        raise ValueError(f"Unable to resolve OCID for compartment '{candidate}'.")
    return resolved_id


def fetch_child_compartments(
    compartment_id: Annotated[str, "Root compartment OCID to expand (included in results)."],
    include_self: Annotated[
        bool, "When true (default), include the given compartment_id in the output."
    ] = True,
    limit: Annotated[
        Optional[int],
        "Optional cap on how many compartmentIds to return (defaults to ORACLE_MCP_MAX_COMPARTMENTS_IN_SCOPE or 200).",
    ] = None,
) -> dict:
    """
    Internal helper that expands a root compartment to its subtree.

    Returns a simple JSON-like dict:
      {
        "rootCompartmentId": "<ocid>",
        "total": N,
        "compartmentIds": ["<ocid1>", "<ocid2>", ...]
      }

    Implementation notes:
    - OCI CLI `oci iam compartment list --compartment-id <X>` returns ONLY direct children.
    - This tool returns the full subtree under <X>.
    - Some environments do not allow `compartment_id_in_subtree=True` even with ACCESSIBLE.
      If subtree listing yields no children for the root, we fall back to a direct-children crawl.
    """
    request_id = uuid.uuid4().hex
    compartment_id = _resolve_compartment_id(compartment_id)
    identity_client = get_identity_client(request_id=request_id)

    # 1) Try fast path: use our cached full-subtree listing and BFS it.
    scope = _expand_compartment_scope(
        compartment_id,
        include_child_compartments=True,
        request_id=request_id,
    )

    # 2) If subtree expansion produced only the root, fall back to direct-children crawl.
    # This matches the CLI semantics and works even when subtree listing is restricted.
    if len(scope) <= 1:
        cap = limit
        if cap is None:
            cap = int(os.getenv("ORACLE_MCP_MAX_COMPARTMENTS_IN_SCOPE", "200"))

        queue: list[str] = [compartment_id]
        seen: set[str] = set()
        out: list[str] = []

        while queue:
            pid = queue.pop(0)
            if pid in seen:
                continue
            seen.add(pid)
            out.append(pid)

            if cap and len(out) >= cap:
                _log_event(
                    "compartment_scope_capped",
                    request_id=request_id,
                    tool="fetch_child_compartments",
                    phase="warn",
                    payload={"root": compartment_id, "cap": cap},
                    level=logging.WARNING,
                )
                break

            next_page = None
            while True:
                resp = identity_client.list_compartments(
                    compartment_id=pid,
                    access_level="ACCESSIBLE",
                    lifecycle_state="ACTIVE",
                    limit=1000,
                    page=next_page,
                )
                children = resp.data or []
                for c in children:
                    cid = getattr(c, "id", None) or getattr(c, "ocid", None)
                    if cid and cid not in seen:
                        queue.append(cid)

                has_next = bool(getattr(resp, "has_next_page", False))
                next_page = getattr(resp, "next_page", None) if has_next else None
                if not has_next:
                    break

        scope = out

    # include_self behavior
    if not include_self:
        scope = [x for x in scope if x != compartment_id]

    # final cap enforcement (also applies to fast-path)
    cap2 = limit
    if cap2 is None:
        cap2 = int(os.getenv("ORACLE_MCP_MAX_COMPARTMENTS_IN_SCOPE", "200"))
    if cap2 and len(scope) > cap2:
        scope = scope[:cap2]

    return {
        "rootCompartmentId": compartment_id,
        "total": len(scope),
        "compartmentIds": scope,
    }


def get_compartment_by_name_tool(
    name: Annotated[
        str,
        "Compartment display name to search for (case-insensitive). Searches all "
        "accessible ACTIVE compartments in the tenancy, including the root tenancy.",
    ],
) -> str:
    """Internal helper to return a compartment matching the provided name."""
    compartment = get_compartment_by_name(name)
    if compartment:
        return str(compartment)
    else:
        return json.dumps({"error": f"Compartment '{name}' not found."})


@mcp.tool(
    description=(
        "Lists protected databases in a compartment with optional filters. For each "
        "database it also includes Recovery Service Subnet details, removes noisy "
        "fields, and adds basic per‑database metrics. It also includes "
        "policyLockedDateTime so retention-lock status is clear (null means lock "
        "is disabled for the attached protection policy; a timestamp means lock "
        "is configured/effective). The result is a list of simple dictionaries, "
        "each with cleaned subnet information and a small metrics map."
    )
)
@_tool_logger("list_protected_databases")
def list_protected_databases(
    compartment_id: Annotated[str, "The compartment OCID or compartment display name"],
    fetch_for_child_compartment: Annotated[
        bool,
        "When true, scans the full subtree under compartment_id (including child compartments) and returns the combined results.",
    ] = False,
    lifecycle_state: Annotated[
        Optional[str],
        (
            'Filter by lifecycle state (e.g., "CREATING", "UPDATING", '
            '"ACTIVE", "DELETE_SCHEDULED", "DELETING", "DELETED", "FAILED")'
        ),
    ] = None,
    display_name: Annotated[Optional[str], "Exact match on display name"] = None,
    id: Annotated[Optional[str], "Protected Database OCID"] = None,
    protection_policy_id: Annotated[Optional[str], "Filter results to this Protection Policy OCID"] = None,
    recovery_service_subnet_id: Annotated[Optional[str], "Filter by Recovery Service Subnet OCID"] = None,
    limit: Annotated[Optional[int], "Maximum number of items per page"] = None,
    page: Annotated[
        Optional[str],
        "Pagination token (opc-next-page) to continue listing from",
    ] = None,
    sort_order: Annotated[Optional[str], 'Sort order: "ASC" or "DESC"'] = None,
    sort_by: Annotated[Optional[str], 'Sort by field: "timeCreated" or "displayName"'] = None,
    opc_request_id: Annotated[Optional[str], "Unique identifier for the request"] = None,
    region: Annotated[Optional[str], "OCI region to execute the request in (e.g., us-ashburn-1)"] = None,
) -> list[ProtectedDatabaseSummary]:
    """
    Paginates through Recovery Service to list Protected Databases and returns
    a list of ProtectedDatabaseSummary models mapped from the OCI SDK response.
    """
    try:
        # Keep tool behavior intact; only add correlation-id based logging via wrapped client
        request_id = uuid.uuid4().hex
        client = get_recovery_client(region, request_id=request_id)

        results: list[ProtectedDatabaseSummary] = []

        comp_ids = _compartment_ids_for_tool(
            compartment_id,
            fetch_for_child_compartment=fetch_for_child_compartment,
            request_id=request_id,
        )

        for comp_id in comp_ids:
            has_next_page = True
            next_page: Optional[str] = page

            while has_next_page:
                # Build request kwargs from provided filters
                kwargs = {
                    "compartment_id": comp_id,
                    "page": next_page,
                }
                if lifecycle_state is not None:
                    kwargs["lifecycle_state"] = lifecycle_state
                if display_name is not None:
                    kwargs["display_name"] = display_name
                if id is not None:
                    kwargs["id"] = id
                if protection_policy_id is not None:
                    kwargs["protection_policy_id"] = protection_policy_id
                if recovery_service_subnet_id is not None:
                    kwargs["recovery_service_subnet_id"] = recovery_service_subnet_id
                if limit is not None:
                    kwargs["limit"] = limit
                if sort_order is not None:
                    kwargs["sort_order"] = sort_order
                if sort_by is not None:
                    kwargs["sort_by"] = sort_by
                if opc_request_id is not None:
                    kwargs["opc_request_id"] = opc_request_id

                # Invoke list API and handle pagination
                response: oci.response.Response = client.list_protected_databases(**kwargs)
                has_next_page = response.has_next_page
                next_page = response.next_page if hasattr(response, "next_page") else None

                # Normalize list and map into our summaries
                data = response.data
                items = getattr(data, "items", data)  # collection.items or raw list
                for d in items:
                    logger.debug(f"Item structure: {d}")
                    pd_summary = map_protected_database_summary(d)
                    if pd_summary is None:
                        continue

                    # Start with a dict view of the Pydantic summary (exclude Nones)
                    try:
                        pd_dict = pd_summary.model_dump(exclude_none=True)
                    except Exception:
                        try:
                            pd_dict = pd_summary.dict(exclude_none=True)
                        except Exception:
                            pd_dict = dict(getattr(pd_summary, "__dict__", {}))

                    # Keep retention-lock visibility explicit for clients:
                    # include camelCase key even when value is None.
                    pd_dict["policyLockedDateTime"] = getattr(pd_summary, "policy_locked_date_time", None)

                    # Enrich/clean Recovery Service Subnet details similarly to get_protected_database
                    try:
                        rss_list = getattr(pd_summary, "recovery_service_subnets", None)
                        if rss_list:
                            enriched = []
                            for det in rss_list:
                                if det is None:
                                    continue
                                rss_id = getattr(det, "id", None)
                                needs_enrich = bool(
                                    rss_id
                                    and (
                                        getattr(det, "vcn_id", None) is None
                                        or getattr(det, "subnet_id", None) is None
                                        or getattr(det, "display_name", None) is None
                                        or getattr(det, "compartment_id", None) is None
                                    )
                                )
                                if needs_enrich:
                                    try:
                                        rss_resp: oci.response.Response = client.get_recovery_service_subnet(
                                            recovery_service_subnet_id=rss_id
                                        )
                                        full_rss = rss_resp.data
                                        mapped_det = map_recovery_service_subnet_details(full_rss)
                                        enriched.append(mapped_det or det)
                                    except Exception:
                                        enriched.append(det)
                                else:
                                    enriched.append(det)
                            # Clean and serialize RSS list, dropping noisy fields to match get_protected_database
                            cleaned_rss = []
                            for ed in enriched:
                                if isinstance(ed, dict):
                                    rd = dict(ed)
                                else:
                                    try:
                                        rd = ed.model_dump(exclude_none=True)
                                    except Exception:
                                        try:
                                            rd = ed.dict(exclude_none=True)
                                        except Exception:
                                            rd = dict(getattr(ed, "__dict__", {}))
                                for _rm in (
                                    "lifecycle_details",
                                    "time_created",
                                    "time_updated",
                                    "freeform_tags",
                                    "defined_tags",
                                    "system_tags",
                                ):
                                    rd.pop(_rm, None)
                                cleaned_rss.append(rd)
                            pd_dict["recovery_service_subnets"] = cleaned_rss
                    except Exception:
                        # best-effort enrichment
                        pass

                    # Populate metrics from full GET to align with CLI list output (no derivations/fallbacks)
                    try:
                        pdid = pd_dict.get("id") or getattr(pd_summary, "id", None)
                        if pdid:
                            try:
                                g = client.get_protected_database(protected_database_id=pdid)
                                full_pd = map_protected_database(getattr(g, "data", None))
                                mobj = getattr(full_pd, "metrics", None)
                                md = None
                                if mobj is not None:
                                    try:
                                        md = mobj.model_dump(exclude_none=False)
                                    except Exception:
                                        try:
                                            md = mobj.dict(exclude_none=False)
                                        except Exception:
                                            md = None

                                def _pick(d: dict | None, key: str):
                                    if not isinstance(d, dict):
                                        return None
                                    return d.get(key)

                                metrics_out = {
                                    "backup-space-estimate-in-gbs": _pick(md, "backup_space_estimate_in_gbs"),
                                    "backup-space-used-in-gbs": _pick(md, "backup_space_used_in_gbs"),
                                    "current-retention-period-in-seconds": _pick(
                                        md, "current_retention_period_in_seconds"
                                    ),
                                    "db-size-in-gbs": _pick(md, "database_size_in_gbs"),
                                    "is-redo-logs-enabled": _pick(md, "is_redo_logs_enabled"),
                                    "minimum-recovery-needed-in-days": _pick(
                                        md, "minimum_recovery_needed_in_days"
                                    ),
                                    "retention-period-in-days": _pick(md, "retention_period_in_days"),
                                    "unprotected-window-in-seconds": _pick(
                                        md, "unprotected_window_in_seconds"
                                    ),
                                }

                                # Keep real-time protection status explicit in list output.
                                # Prefer top-level PD flag; fallback to metrics flag.
                                redo_shipped = getattr(full_pd, "is_redo_logs_shipped", None)
                                if redo_shipped is None:
                                    redo_shipped = _pick(md, "is_redo_logs_enabled")

                                # Emit both key variants for client compatibility.
                                pd_dict["is_redo_logs_shipped"] = redo_shipped
                                pd_dict["isRedoLogsShipped"] = redo_shipped

                                pd_dict["metrics"] = metrics_out
                            except Exception:
                                # If GET fails, do not set metrics (avoid misleading partials)
                                pass
                    except Exception:
                        pass

                    results.append(pd_dict)

        # De-dupe by OCID when scanning multiple compartments
        if fetch_for_child_compartment:
            uniq: dict[str, Any] = {}
            for r in results:
                try:
                    rid = r.get("id") if isinstance(r, dict) else getattr(r, "id", None)
                except Exception:
                    rid = None
                if rid and rid not in uniq:
                    uniq[rid] = r
            results = list(uniq.values())

        logger.info(f"Found {len(results)} Protected Databases")
        return results

    except Exception as e:
        logger.error(f"Error in list_protected_databases tool: {str(e)}")
        raise


@mcp.tool(
    description=(
        "Gets a protected database by OCID and presents a clean, easy‑to‑read view. "
        "It includes Recovery Service Subnet details, hides noisy fields, and adds "
        "core metrics. It also includes policyLockedDateTime so retention-lock "
        "status is explicit (null means lock is disabled for the attached "
        "protection policy; a timestamp means lock is configured/effective). "
        "The result is one protected database as a plain dictionary with subnet "
        "info and a simple metrics section."
    )
)
@_tool_logger("get_protected_database")
def get_protected_database(
    protected_database_id: Annotated[str, "Protected Database OCID"],
    opc_request_id: Annotated[Optional[str], "Unique identifier for the request"] = None,
    region: Annotated[Optional[str], "OCI region to execute the request in (e.g., us-ashburn-1)"] = None,
) -> ProtectedDatabase:
    """
    Retrieves a single Protected Database resource from Recovery Service and returns
    a ProtectedDatabase model mapped from the OCI SDK response.
    """
    try:
        request_id = uuid.uuid4().hex
        client = get_recovery_client(region, request_id=request_id)

        # Optional request ID passthrough
        kwargs = {}
        if opc_request_id is not None:
            kwargs["opc_request_id"] = opc_request_id

        response: oci.response.Response = client.get_protected_database(
            protected_database_id=protected_database_id, **kwargs
        )

        data = response.data
        pd = map_protected_database(data)

        # Enrich Recovery Service Subnet details if only IDs are present in PD payload
        try:
            rss_list = getattr(pd, "recovery_service_subnets", None)
            if rss_list:
                enriched: list = []
                for det in rss_list:
                    # det is a RecoveryServiceSubnetDetails model
                    if det is None:
                        continue
                    rss_id = getattr(det, "id", None)
                    # If we have an id but missing core fields, fetch full RSS object
                    needs_enrich = bool(
                        rss_id
                        and (
                            getattr(det, "vcn_id", None) is None
                            or getattr(det, "subnet_id", None) is None
                            or getattr(det, "display_name", None) is None
                            or getattr(det, "compartment_id", None) is None
                        )
                    )
                    if needs_enrich:
                        try:
                            rss_resp: oci.response.Response = client.get_recovery_service_subnet(
                                recovery_service_subnet_id=rss_id
                            )
                            full_rss = rss_resp.data
                            mapped_det = map_recovery_service_subnet_details(full_rss)
                            enriched.append(mapped_det or det)
                        except Exception:
                            # On failure, preserve original partial details
                            enriched.append(det)
                    else:
                        enriched.append(det)
                if enriched:
                    pd.recovery_service_subnets = enriched
        except Exception:
            # Best-effort enrichment; ignore errors and return mapped PD
            pass

        logger.info(f"Fetched Protected Database {protected_database_id}")

        # Build sanitized response dict (exclude None to avoid noisy nulls)
        try:
            pd_dict = pd.model_dump(exclude_none=True)
        except Exception:
            try:
                pd_dict = pd.dict(exclude_none=True)  # pydantic v1 fallback
            except Exception:
                pd_dict = dict(getattr(pd, "__dict__", {}))

        # Keep retention-lock visibility explicit for clients:
        # include camelCase key even when value is None.
        pd_dict["policyLockedDateTime"] = getattr(pd, "policy_locked_date_time", None)

        # Remove top-level fields not desired in response
        for _k in ("change_rate", "compression_ratio"):
            pd_dict.pop(_k, None)

        # Clean nested Recovery Service Subnet details
        _rss = pd_dict.get("recovery_service_subnets")
        if isinstance(_rss, list):
            cleaned_rss = []
            for _det in _rss:
                if isinstance(_det, dict):
                    d = dict(_det)
                else:
                    try:
                        d = _det.model_dump(exclude_none=True)
                    except Exception:
                        try:
                            d = _det.dict(exclude_none=True)
                        except Exception:
                            d = dict(getattr(_det, "__dict__", {}))
                for _rm in (
                    "lifecycle_details",
                    "time_created",
                    "time_updated",
                    "freeform_tags",
                    "defined_tags",
                    "system_tags",
                ):
                    d.pop(_rm, None)
                cleaned_rss.append(d)
            pd_dict["recovery_service_subnets"] = cleaned_rss

        # Normalize metrics to OCI CLI style keys using only values present on
        # PD.metrics (no derivations/fallbacks)
        metrics_obj = getattr(pd, "metrics", None)
        metrics_dict = None
        if metrics_obj is not None:
            try:
                metrics_dict = metrics_obj.model_dump(exclude_none=False)
            except Exception:
                try:
                    metrics_dict = metrics_obj.dict(exclude_none=False)
                except Exception:
                    metrics_dict = None

        def _pick(d: dict | None, key: str):
            if not isinstance(d, dict):
                return None
            return d.get(key)

        metrics_out = {
            "backup-space-estimate-in-gbs": _pick(metrics_dict, "backup_space_estimate_in_gbs"),
            "backup-space-used-in-gbs": _pick(metrics_dict, "backup_space_used_in_gbs"),
            "current-retention-period-in-seconds": _pick(metrics_dict, "current_retention_period_in_seconds"),
            "db-size-in-gbs": _pick(metrics_dict, "database_size_in_gbs"),
            "is-redo-logs-enabled": _pick(metrics_dict, "is_redo_logs_enabled"),
            "minimum-recovery-needed-in-days": _pick(metrics_dict, "minimum_recovery_needed_in_days"),
            "retention-period-in-days": _pick(metrics_dict, "retention_period_in_days"),
            "unprotected-window-in-seconds": _pick(metrics_dict, "unprotected_window_in_seconds"),
        }
        pd_dict["metrics"] = metrics_out

        return pd_dict

    except Exception as e:
        logger.error(f"Error in get_protected_database tool: {str(e)}")
        raise


@mcp.tool(
    description=(
        "Shows how many protected databases are healthy, warning, alert, or unknown "
        "in a compartment. If a quick list doesn’t include health, it checks each "
        "database to fill it in. The result is a small JSON with the counts, the "
        "compartmentId, and the region."
    )
)
@_tool_logger("summarize_protected_database_health")
def summarize_protected_database_health(
    compartment_id: Annotated[
        Optional[str],
        "Compartment OCID or compartment display name. If omitted, defaults to the tenancy OCID from your OCI profile.",
    ] = None,
    fetch_for_child_compartment: Annotated[
        bool,
        "When true, scans the full subtree under compartment_id (including child compartments) and returns aggregated counts plus per-compartment breakdown.",
    ] = False,
    region: Annotated[Optional[str], "OCI region to execute the request in (e.g., us-ashburn-1)"] = None,
) -> ProtectedDatabaseHealthCounts:
    """
    Summarizes Protected Database health status counts (PROTECTED, WARNING, ALERT, UNKNOWN) in a compartment.
    The tool lists protected databases, reads health from summary when available, falls back to GET per PD,
    and returns counts. Total equals PDs scanned. UNKNOWN counts PDs with missing/None health (often DELETED
    or transitional).
    """
    try:
        request_id = uuid.uuid4().hex
        client = get_recovery_client(region, request_id=request_id)
        comp_id = compartment_id or get_tenancy()
        comp_ids = _compartment_ids_for_tool(
            comp_id,
            fetch_for_child_compartment=fetch_for_child_compartment,
            request_id=request_id,
        )

        protected = 0
        warning = 0
        alert = 0
        unknown = 0
        scanned = 0

        per_compartment: list[dict] = []

        has_next_page = True
        next_page: Optional[str] = None

        for each_comp in comp_ids:
            c_protected = 0
            c_warning = 0
            c_alert = 0
            c_unknown = 0
            c_scanned = 0

            has_next_page = True
            next_page = None

            while has_next_page:
                # Fetch ACTIVE PDs page by page
                list_kwargs = {
                    "compartment_id": each_comp,
                    "page": next_page,
                    "lifecycle_state": "ACTIVE",
                }
                response: oci.response.Response = client.list_protected_databases(**list_kwargs)
                has_next_page = response.has_next_page
                next_page = response.next_page if hasattr(response, "next_page") else None

                data = response.data
                items = getattr(data, "items", data)
                for item in items or []:
                    # Try to read health from list summary; shape can vary by SDK versions
                    health = getattr(item, "health", None)
                    if not health and hasattr(item, "__dict__"):
                        try:
                            health = item.__dict__.get("health")
                        except Exception:
                            health = None

                    # Robustly extract PD OCID to allow follow-up GET if required
                    pd_id = getattr(item, "id", None) or (
                        getattr(item, "data", None) and getattr(item.data, "id", None)
                    )
                    logger.debug(f"Item structure: {item}")
                    if pd_id is None:
                        try:
                            item_dict = getattr(item, "__dict__", None) or {}
                            pd_id = item_dict.get("id")
                        except Exception:
                            pd_id = None
                    if not pd_id:
                        # Can't fetch details; skip counting this entry
                        continue

                    scanned += 1
                    c_scanned += 1

                    # If health is not on the summary, fetch the full resource
                    if not health:
                        try:
                            pd_resp: oci.response.Response = client.get_protected_database(
                                protected_database_id=pd_id
                            )
                            pd = pd_resp.data
                            health = getattr(pd, "health", None)
                            if not health and hasattr(pd, "__dict__"):
                                health = pd.__dict__.get("health")
                        except Exception:
                            health = None

                    # Increment appropriate counters
                    if health == "PROTECTED":
                        protected += 1
                        c_protected += 1
                    elif health == "WARNING":
                        warning += 1
                        c_warning += 1
                    elif health == "ALERT":
                        alert += 1
                        c_alert += 1
                    else:
                        # unknown/None health
                        unknown += 1
                        c_unknown += 1

            per_compartment.append(
                {
                    "compartmentId": each_comp,
                    "region": region,
                    "protected": c_protected,
                    "warning": c_warning,
                    "alert": c_alert,
                    "unknown": c_unknown,
                    "total": c_scanned,
                }
            )

        total = scanned
        logger.info(
            "Health summary for compartment %s (region=%s): "
            "PROTECTED=%s, WARNING=%s, ALERT=%s, UNKNOWN=%s, TOTAL=%s",
            comp_id,
            region,
            protected,
            warning,
            alert,
            unknown,
            total,
        )
        # NOTE: construct using the alias key (compartmentId) to avoid any
        # pydantic alias population edge-cases that can result in null output.
        aggregated = ProtectedDatabaseHealthCounts(
            compartmentId=comp_id,
            region=region,
            protected=protected,
            warning=warning,
            alert=alert,
            unknown=unknown,
            total=total,
        )
        try:
            agg_dict = aggregated.model_dump(exclude_none=False, by_alias=True)
        except Exception:
            try:
                agg_dict = aggregated.dict(exclude_none=False, by_alias=True)
            except Exception:
                agg_dict = {
                    "compartmentId": comp_id,
                    "region": region,
                    "protected": protected,
                    "warning": warning,
                    "alert": alert,
                    "unknown": unknown,
                    "total": total,
                }

        return {
            "aggregated": agg_dict,
            "per_compartment": per_compartment,
            "compartmentIdsScanned": comp_ids,
        }
    except Exception as e:
        logger.error(f"Error in summarize_protected_database_health tool: {str(e)}")
        raise


@mcp.tool(
    description=(
        "Use this tool for real-time protection status questions. It shows how many "
        "protected databases have redo transport (real-time protection) turned on or "
        "off in a compartment. It reads the main setting and uses a fallback when "
        "needed. The result is a simple JSON with enabled, disabled, total, the "
        "compartmentId, and the region."
    )
)
@_tool_logger("summarize_protected_database_redo_status")
def summarize_protected_database_redo_status(
    compartment_id: Annotated[
        Optional[str],
        "Compartment OCID or compartment display name. If omitted, defaults to the tenancy OCID from your OCI profile.",
    ] = None,
    fetch_for_child_compartment: Annotated[
        bool,
        "When true, scans the full subtree under compartment_id (including child compartments) and returns aggregated counts plus per-compartment breakdown.",
    ] = False,
    region: Annotated[Optional[str], "OCI region to execute the request in (e.g., us-ashburn-1)"] = None,
) -> ProtectedDatabaseRedoCounts:
    """
    Summarizes redo transport enablement for Protected Databases in a compartment.
    Lists protected databases then fetches each to inspect
    is_redo_logs_shipped (true=enabled, false=disabled).
    """
    try:
        request_id = uuid.uuid4().hex
        client = get_recovery_client(region, request_id=request_id)
        comp_id = compartment_id or get_tenancy()
        comp_ids = _compartment_ids_for_tool(
            comp_id,
            fetch_for_child_compartment=fetch_for_child_compartment,
            request_id=request_id,
        )

        enabled = 0
        disabled = 0
        per_compartment: list[dict] = []

        has_next_page = True
        next_page: Optional[str] = None

        for each_comp in comp_ids:
            c_enabled = 0
            c_disabled = 0

            has_next_page = True
            next_page = None

            while has_next_page:
                # List ACTIVE PDs to assess redo status via GET per PD
                list_kwargs = {
                    "compartment_id": each_comp,
                    "page": next_page,
                    "lifecycle_state": "ACTIVE",
                }
                response: oci.response.Response = client.list_protected_databases(**list_kwargs)
                has_next_page = response.has_next_page
                next_page = response.next_page if hasattr(response, "next_page") else None

                data = response.data
                items = getattr(data, "items", data)
                for item in items or []:
                    # Robustly get the PD OCID from summary item
                    pd_id = getattr(item, "id", None) or (
                        getattr(item, "data", None) and getattr(item.data, "id", None)
                    )
                    if pd_id is None:
                        try:
                            item_dict = getattr(item, "__dict__", None) or {}
                            pd_id = item_dict.get("id")
                        except Exception:
                            pd_id = None
                    if not pd_id:
                        continue

                    # Fetch full Protected Database to read is_redo_logs_shipped (primary)
                    redo_enabled = None
                    try:
                        pd_resp: oci.response.Response = client.get_protected_database(
                            protected_database_id=pd_id
                        )
                        pd = pd_resp.data
                        redo_enabled = getattr(pd, "is_redo_logs_shipped", None)
                        if redo_enabled is None and hasattr(pd, "__dict__"):
                            redo_enabled = pd.__dict__.get("is_redo_logs_shipped") or pd.__dict__.get(
                                "isRedoLogsShipped"
                            )
                        # Fallback: some SDK/reporting expose Real-time protection
                        # under metrics as is_redo_logs_enabled
                        if redo_enabled is None:
                            try:
                                m = getattr(pd, "metrics", None)
                                if m is not None:
                                    redo_enabled = getattr(m, "is_redo_logs_enabled", None)
                                    if redo_enabled is None and hasattr(m, "__dict__"):
                                        redo_enabled = m.__dict__.get(
                                            "is_redo_logs_enabled"
                                        ) or m.__dict__.get("isRedoLogsEnabled")
                            except Exception:
                                pass
                    except Exception:
                        redo_enabled = None

                    if redo_enabled is True:
                        enabled += 1
                        c_enabled += 1
                    elif redo_enabled is False:
                        disabled += 1
                        c_disabled += 1
                    else:
                        # None/unknown -> do not count
                        pass

            per_compartment.append(
                {
                    "compartmentId": each_comp,
                    "region": region,
                    "enabled": c_enabled,
                    "disabled": c_disabled,
                    "total": c_enabled + c_disabled,
                }
            )

        total = enabled + disabled
        logger.info(
            "Redo transport summary for compartment %s (region=%s): ENABLED=%s, DISABLED=%s, TOTAL=%s",
            comp_id,
            region,
            enabled,
            disabled,
            total,
        )
        # NOTE: construct using the alias key (compartmentId) to avoid any
        # pydantic alias population edge-cases that can result in null output.
        aggregated = ProtectedDatabaseRedoCounts(
            compartmentId=comp_id,
            region=region,
            enabled=enabled,
            disabled=disabled,
            total=total,
        )
        try:
            agg_dict = aggregated.model_dump(exclude_none=False, by_alias=True)
        except Exception:
            try:
                agg_dict = aggregated.dict(exclude_none=False, by_alias=True)
            except Exception:
                agg_dict = {
                    "compartmentId": comp_id,
                    "region": region,
                    "enabled": enabled,
                    "disabled": disabled,
                    "total": total,
                }

        return {
            "aggregated": agg_dict,
            "per_compartment": per_compartment,
            "compartmentIdsScanned": comp_ids,
        }
    except Exception as e:
        logger.error(f"Error in summarize_protected_database_redo_status tool: {e}")
        raise


@mcp.tool(
    description=(
        "Adds up the backup space (in GB) used by protected databases in a compartment, "
        "including only those with lifecycle state ACTIVE or DELETE_SCHEDULED (excluding "
        "DELETED). It reads each database’s metrics and also tells you how many databases "
        "were checked. The result is a small JSON with the compartmentId, region, "
        "totalDatabasesScanned, and the total space in GB."
    )
)
@_tool_logger("summarize_backup_space_used")
def summarize_backup_space_used(
    compartment_id: Annotated[
        Optional[str],
        "Compartment OCID or compartment display name. If omitted, defaults to the tenancy OCID from your OCI profile.",
    ] = None,
    fetch_for_child_compartment: Annotated[
        bool,
        "When true, scans the full subtree under compartment_id (including child compartments) and returns aggregated sum plus per-compartment breakdown.",
    ] = False,
    region: Annotated[
        Optional[str],
        "Canonical OCI region (e.g., us-ashburn-1) to execute the request in.",
    ] = None,
) -> dict:
    """
    Sums backup space used (GB) by Protected Databases in a compartment.
    Only includes PDs with lifecycle_state in {'ACTIVE', 'DELETE_SCHEDULED'} (excludes 'DELETED').
    For each included PD: scans, increments total, and reads backup_space_used_in_gbs from metrics.
    Important: metrics are not reliably exposed on list summaries; fetch the full PD to read metrics.
    Returns: compartmentId, region, totalDatabasesScanned, sumBackupSpaceUsedInGBs.
    """
    try:
        request_id = uuid.uuid4().hex
        comp_id = _resolve_compartment_id(compartment_id, default_to_tenancy=True)
        client = get_recovery_client(region, request_id=request_id)
        comp_ids = _compartment_ids_for_tool(
            comp_id,
            fetch_for_child_compartment=fetch_for_child_compartment,
            request_id=request_id,
        )

        sum_gb = 0.0
        scanned = 0
        missing_metrics = 0
        per_compartment: list[dict] = []

        for each_comp in comp_ids:
            c_sum_gb = 0.0
            c_scanned = 0
            c_missing_metrics = 0

            has_next_page = True
            next_page = None

            while has_next_page:
                list_kwargs = {
                    "compartment_id": each_comp,
                    "page": next_page,
                }
                response: oci.response.Response = client.list_protected_databases(**list_kwargs)
                has_next_page = response.has_next_page
                next_page = response.next_page if hasattr(response, "next_page") else None

                data = response.data
                items = getattr(data, "items", data)

                for item in items or []:
                    # Filter by lifecycle state: include only ACTIVE or DELETE_SCHEDULED
                    # (exclude DELETED and others)
                    try:
                        lifecycle_state = getattr(item, "lifecycle_state", None)
                        if not lifecycle_state and hasattr(item, "__dict__"):
                            lifecycle_state = (getattr(item, "__dict__", {}) or {}).get(
                                "lifecycle_state"
                            ) or (getattr(item, "__dict__", {}) or {}).get("lifecycleState")
                    except Exception:
                        lifecycle_state = None
                    if lifecycle_state not in ("ACTIVE", "DELETE_SCHEDULED"):
                        # Skip PDs that are not ACTIVE or DELETE_SCHEDULED (e.g., DELETED, CREATING, etc.)
                        continue

                    # Robustly get the PD OCID from summary item (same as redo status tool)
                    pd_id = getattr(item, "id", None) or (
                        getattr(item, "data", None) and getattr(item.data, "id", None)
                    )
                    logger.debug(f"Item structure: {item}")
                    if pd_id is None:
                        try:
                            item_dict = getattr(item, "__dict__", None) or {}
                            pd_id = item_dict.get("id")
                        except Exception:
                            pd_id = None
                    if not pd_id:
                        continue

                    scanned += 1
                    c_scanned += 1

                    # Always fetch the full Protected Database to read metrics reliably
                    gb_val = None
                    try:
                        pd_resp: oci.response.Response = client.get_protected_database(
                            protected_database_id=pd_id
                        )
                        pd_obj = pd_resp.data
                        metrics = getattr(pd_obj, "metrics", None)
                        if metrics is None and hasattr(pd_obj, "__dict__"):
                            metrics = getattr(pd_obj, "__dict__", {}).get("metrics")
                        # metrics may be a model or a dict; normalise access
                        if metrics is not None:
                            if hasattr(metrics, "backup_space_used_in_gbs"):
                                gb_val = getattr(metrics, "backup_space_used_in_gbs", None)
                            if gb_val is None and hasattr(metrics, "__dict__"):
                                gb_val = metrics.__dict__.get(
                                    "backup_space_used_in_gbs"
                                ) or metrics.__dict__.get("backupSpaceUsedInGbs")
                            if gb_val is None and isinstance(metrics, dict):
                                gb_val = metrics.get("backup_space_used_in_gbs") or metrics.get(
                                    "backupSpaceUsedInGbs"
                                )
                    except Exception:
                        # If GET fails, fall back to any summary metrics representation
                        try:
                            m = getattr(item, "metrics", None)
                            if m is not None:
                                gb_val = getattr(m, "backup_space_used_in_gbs", None)
                                if gb_val is None and hasattr(m, "__dict__"):
                                    gb_val = m.__dict__.get("backup_space_used_in_gbs") or m.__dict__.get(
                                        "backupSpaceUsedInGbs"
                                    )
                                if gb_val is None and isinstance(m, dict):
                                    gb_val = m.get("backup_space_used_in_gbs") or m.get(
                                        "backupSpaceUsedInGbs"
                                    )
                        except Exception:
                            gb_val = None

                    if gb_val is None:
                        missing_metrics += 1
                        c_missing_metrics += 1

                    # Ensure numeric value; treat missing/non-numeric as 0.0
                    try:
                        gb = float(gb_val) if gb_val is not None else 0.0
                    except Exception:
                        gb = 0.0

                    sum_gb += gb
                    c_sum_gb += gb

            per_compartment.append(
                {
                    "compartmentId": each_comp,
                    "region": region,
                    "totalDatabasesScanned": c_scanned,
                    "sumBackupSpaceUsedInGBs": round(c_sum_gb, 2),
                    "missingMetricsCount": c_missing_metrics,
                }
            )

        logger.info(
            "Backup space used summary for compartment %s (region=%s): "
            "scanned=%s, total_gb=%s, missing_metrics=%s",
            comp_id,
            region,
            scanned,
            sum_gb,
            missing_metrics,
        )
        aggregated = ProtectedDatabaseBackupSpaceSum(
            compartmentId=comp_id,
            region=region,
            totalDatabasesScanned=scanned,
            sumBackupSpaceUsedInGBs=round(sum_gb, 2),
        )
        try:
            agg_dict = aggregated.model_dump(exclude_none=False, by_alias=True)
        except Exception:
            try:
                agg_dict = aggregated.dict(exclude_none=False, by_alias=True)
            except Exception:
                agg_dict = {
                    "compartmentId": comp_id,
                    "region": region,
                    "totalDatabasesScanned": scanned,
                    "sumBackupSpaceUsedInGBs": round(sum_gb, 2),
                }

        return {
            "aggregated": agg_dict,
            "per_compartment": per_compartment,
            "compartmentIdsScanned": comp_ids,
            "missingMetricsCount": missing_metrics,
        }
        # logger.info(f"Returning dict result: {result}")
        # return result
    except Exception as e:
        logger.error(f"Error in summarize_backup_space_used tool: {str(e)}")
        raise


@mcp.tool(
    description=(
        "Checks OCI service limits for Autonomous Recovery Service using tenancy context from config profile."
        "It fetches resource availability for protected database backup storage (GB) "
        "and protected database count, then returns both values in a simple JSON "
        "response with tenancy compartment and configured region context."
    )
)
@_tool_logger("check_recovery_service_limits")
def check_recovery_service_limits(
    compartment_id: Annotated[
        Optional[str],
        "(Ignored; accepted for backward compatibility). Limits are always checked against tenancy from config.",
    ] = None,
    region: Annotated[
        Optional[str],
        "(Ignored; accepted for backward compatibility). Region is always taken from OCI config.",
    ] = None,
    opc_request_id: Annotated[Optional[str], "Unique identifier for the request"] = None,
) -> dict:
    """
    Returns resource availability from OCI Limits API for:
      - autonomous-recovery-service / protected-database-backup-storage-gb
      - autonomous-recovery-service / protected-database-count

    Scope/region behavior:
      - Compartment is always the tenancy OCID from server config
      - Region is always the configured profile region
      - `compartment_id` and `region` inputs are accepted only for backward compatibility

    API shape corresponds to:
      GET /20190729/services/autonomous-recovery-service/limits/<limitName>/resourceAvailability
    """
    try:
        request_id = uuid.uuid4().hex
        resolved_compartment_id = get_tenancy()
        target_region = (_effective_region("us-ashburn-1") or "us-ashburn-1").strip()
        client = get_limits_client(target_region, request_id=request_id)

        service_name = "autonomous-recovery-service"
        limit_map = {
            "protectedDatabaseBackupStorageGb": "protected-database-backup-storage-gb",
            "protectedDatabaseCount": "protected-database-count",
        }

        def _as_dict(obj: Any) -> dict[str, Any]:
            if obj is None:
                return {}
            if isinstance(obj, dict):
                return dict(obj)
            try:
                return oci.util.to_dict(obj)
            except Exception:
                pass
            if hasattr(obj, "__dict__"):
                try:
                    return dict(obj.__dict__)
                except Exception:
                    pass
            return {}

        limits_out: dict[str, Any] = {}

        for out_key, limit_name in limit_map.items():
            kwargs: dict[str, Any] = {
                "service_name": service_name,
                "limit_name": limit_name,
                "compartment_id": resolved_compartment_id,
            }
            if opc_request_id is not None:
                kwargs["opc_request_id"] = opc_request_id

            resp: oci.response.Response = client.get_resource_availability(**kwargs)
            data_dict = _as_dict(getattr(resp, "data", None))

            # Keep response explicit and stable for dashboard/tooling usage
            limits_out[out_key] = {
                "serviceName": service_name,
                "limitName": limit_name,
                "scopeType": data_dict.get("scope_type"),
                "available": data_dict.get("available"),
                "used": data_dict.get("used"),
                "fractionalAvailability": data_dict.get("fractional_availability"),
                "fractionalUsage": data_dict.get("fractional_usage"),
                "effectiveQuotaValue": data_dict.get("effective_quota_value"),
                "policyName": data_dict.get("policy_name"),
            }

        return {
            "compartmentId": resolved_compartment_id,
            "region": target_region,
            "serviceName": service_name,
            "limits": limits_out,
        }
    except Exception as e:
        logger.error(f"Error in check_recovery_service_limits tool: {str(e)}")
        raise


@mcp.tool(
    description=(
        "Lists the tenancy's subscribed regions and their status using "
        "IdentityClient.list_region_subscriptions(). "
        "NOTE: The 'service' parameter is accepted for backward compatibility but is "
        "not used, because IAM region subscriptions are tenancy-wide, not service-specific."
    )
)
@_tool_logger("fetch_regions_subscribed")
def fetch_regions_subscribed(
    tenancy_id: Annotated[Optional[str], "OCID of the compartment to scope the search."] = None,
) -> dict:
    request_id = uuid.uuid4().hex
    if not tenancy_id:
        tenancy_id = get_tenancy()
    regions = _iam_subscribed_regions_with_status(request_id=request_id)
    return {
        "tenancyId": tenancy_id,
        "regions": regions,
        "total": len(regions),
    }


@mcp.tool(
    description=(
        "Lists protection policies in a compartment with handy filters and automatic "
        "paging. The result is a straightforward list of protection policies."
    )
)
@_tool_logger("list_protection_policies")
def list_protection_policies(
    compartment_id: Annotated[str, "The compartment OCID or compartment display name"],
    fetch_for_child_compartment: Annotated[
        bool,
        "When true, scans the full subtree under compartment_id (including child compartments) and returns the combined results.",
    ] = False,
    lifecycle_state: Annotated[
        Optional[str],
        'Filter by lifecycle state (e.g., "ACTIVE", "DELETED")',
    ] = None,
    display_name: Annotated[Optional[str], "Exact match on display name"] = None,
    id: Annotated[Optional[str], "Protection Policy OCID"] = None,
    limit: Annotated[Optional[int], "Maximum number of items per page"] = None,
    page: Annotated[
        Optional[str],
        "Pagination token (opc-next-page) to continue listing from",
    ] = None,
    sort_order: Annotated[Optional[str], 'Sort order: "ASC" or "DESC"'] = None,
    sort_by: Annotated[Optional[str], 'Sort by field: "timeCreated" or "displayName"'] = None,
    opc_request_id: Annotated[Optional[str], "Unique identifier for the request"] = None,
    region: Annotated[Optional[str], "OCI region to execute the request in (e.g., us-ashburn-1)"] = None,
) -> list[ProtectionPolicy]:
    """
    Paginates through Recovery Service to list Protection Policies and returns
    a list of ProtectionPolicy models mapped from the OCI SDK response.
    """
    try:
        request_id = uuid.uuid4().hex
        client = get_recovery_client(region, request_id=request_id)

        results: list[ProtectionPolicy] = []

        comp_ids = _compartment_ids_for_tool(
            compartment_id,
            fetch_for_child_compartment=fetch_for_child_compartment,
            request_id=request_id,
        )

        for comp_id in comp_ids:
            has_next_page = True
            next_page: Optional[str] = page

            while has_next_page:
                # Collect filters/controls into kwargs
                kwargs = {
                    "compartment_id": comp_id,
                    "page": next_page,
                }
                if lifecycle_state is not None:
                    kwargs["lifecycle_state"] = lifecycle_state
                if display_name is not None:
                    kwargs["display_name"] = display_name
                if id is not None:
                    kwargs["id"] = id
                if limit is not None:
                    kwargs["limit"] = limit
                if sort_order is not None:
                    kwargs["sort_order"] = sort_order
                if sort_by is not None:
                    kwargs["sort_by"] = sort_by
                if opc_request_id is not None:
                    kwargs["opc_request_id"] = opc_request_id

                response: oci.response.Response = client.list_protection_policies(**kwargs)
                has_next_page = response.has_next_page
                next_page = response.next_page if hasattr(response, "next_page") else None

                data = response.data
                items = getattr(data, "items", data)  # collection.items or raw list
                for d in items:
                    logger.debug(f"Item structure: {d}")
                    pp = map_protection_policy(d)
                    if pp is not None:
                        results.append(pp)

        # De-dupe by OCID when scanning multiple compartments
        if fetch_for_child_compartment:
            uniq: dict[str, Any] = {}
            for r in results:
                rid = getattr(r, "id", None) if r is not None else None
                if rid and rid not in uniq:
                    uniq[rid] = r
            results = list(uniq.values())

        logger.info(f"Found {len(results)} Protection Policies")
        return results

    except Exception as e:
        logger.error(f"Error in list_protection_policies tool: {str(e)}")
        raise


@mcp.tool(description=("Gets a protection policy by OCID and returns it as a simple object."))
@_tool_logger("get_protection_policy")
def get_protection_policy(
    protection_policy_id: Annotated[str, "Protection Policy OCID"],
    opc_request_id: Annotated[Optional[str], "Unique identifier for the request"] = None,
    region: Annotated[Optional[str], "OCI region to execute the request in (e.g., us-ashburn-1)"] = None,
) -> ProtectionPolicy:
    """
    Retrieves a single Protection Policy resource from Recovery Service and returns
    a ProtectionPolicy model mapped from the OCI SDK response.
    """
    try:
        request_id = uuid.uuid4().hex
        client = get_recovery_client(region, request_id=request_id)

        kwargs = {}
        if opc_request_id is not None:
            kwargs["opc_request_id"] = opc_request_id

        response: oci.response.Response = client.get_protection_policy(
            protection_policy_id=protection_policy_id, **kwargs
        )

        data = response.data
        pp = map_protection_policy(data)
        logger.info(f"Fetched Protection Policy {protection_policy_id}")
        return pp

    except Exception as e:
        logger.error(f"Error in get_protection_policy tool: {str(e)}")
        raise


@mcp.tool(
    description=(
        "Lists recovery service subnets in a compartment with helpful filters. When "
        "needed, it fills in the list of associated subnets or uses the subnet_id as "
        "a fallback. The result is a simple list of subnets with the subnets list "
        "included when available."
    )
)
@_tool_logger("list_recovery_service_subnets")
def list_recovery_service_subnets(
    compartment_id: Annotated[str, "The compartment OCID or compartment display name"],
    fetch_for_child_compartment: Annotated[
        bool,
        "When true, scans the full subtree under compartment_id (including child compartments) and returns the combined results.",
    ] = False,
    lifecycle_state: Annotated[
        Optional[str],
        (
            'Filter by lifecycle state (e.g., "CREATING", "ACTIVE", '
            '"UPDATING", "DELETING", "DELETED", "FAILED")'
        ),
    ] = None,
    display_name: Annotated[Optional[str], "Exact match on display name"] = None,
    id: Annotated[Optional[str], "Recovery Service Subnet OCID"] = None,
    vcn_id: Annotated[Optional[str], "Filter by VCN OCID"] = None,
    limit: Annotated[Optional[int], "Maximum number of items per page"] = None,
    page: Annotated[
        Optional[str],
        "Pagination token (opc-next-page) to continue listing from",
    ] = None,
    sort_order: Annotated[Optional[str], 'Sort order: "ASC" or "DESC"'] = None,
    sort_by: Annotated[Optional[str], 'Sort by field: "timeCreated" or "displayName"'] = None,
    opc_request_id: Annotated[Optional[str], "Unique identifier for the request"] = None,
    region: Annotated[Optional[str], "OCI region to execute the request in (e.g., us-ashburn-1)"] = None,
) -> list[RecoveryServiceSubnet]:
    """
    Paginates through Recovery Service to list Recovery Service Subnets and returns
    a list of RecoveryServiceSubnet models mapped from the OCI SDK response.
    """
    try:
        request_id = uuid.uuid4().hex
        client = get_recovery_client(region, request_id=request_id)

        results: list[RecoveryServiceSubnet] = []

        comp_ids = _compartment_ids_for_tool(
            compartment_id,
            fetch_for_child_compartment=fetch_for_child_compartment,
            request_id=request_id,
        )

        for comp_id in comp_ids:
            has_next_page = True
            next_page: Optional[str] = page

            while has_next_page:
                kwargs = {
                    "compartment_id": comp_id,
                    "page": next_page,
                }
                if lifecycle_state is not None:
                    kwargs["lifecycle_state"] = lifecycle_state
                if display_name is not None:
                    kwargs["display_name"] = display_name
                if id is not None:
                    kwargs["id"] = id
                if vcn_id is not None:
                    kwargs["vcn_id"] = vcn_id
                if limit is not None:
                    kwargs["limit"] = limit
                if sort_order is not None:
                    kwargs["sort_order"] = sort_order
                if sort_by is not None:
                    kwargs["sort_by"] = sort_by
                if opc_request_id is not None:
                    kwargs["opc_request_id"] = opc_request_id

                response: oci.response.Response = client.list_recovery_service_subnets(**kwargs)
                has_next_page = response.has_next_page
                next_page = response.next_page if hasattr(response, "next_page") else None

                data = response.data
                items = getattr(data, "items", data)  # collection.items or raw list
                for d in items:
                    logger.debug(f"Item structure: {d}")
                    rss = map_recovery_service_subnet(d)
                    if rss is None:
                        continue
                    # Enrich with subnets list if missing by fetching the full resource
                    try:
                        missing_subnets = getattr(rss, "subnets", None) is None
                        rss_id = getattr(rss, "id", None)
                        if missing_subnets and rss_id:
                            try:
                                g = client.get_recovery_service_subnet(recovery_service_subnet_id=rss_id)
                                full = map_recovery_service_subnet(getattr(g, "data", None))
                                if full and getattr(full, "subnets", None):
                                    rss.subnets = full.subnets
                            except Exception:
                                pass
                    except Exception:
                        pass
                    # Final fallback: if still missing, derive from subnet_id when available
                    try:
                        if getattr(rss, "subnets", None) is None:
                            sid = getattr(rss, "subnet_id", None)
                            if sid:
                                rss.subnets = [sid]
                    except Exception:
                        pass
                    results.append(rss)

        # De-dupe by OCID when scanning multiple compartments
        if fetch_for_child_compartment:
            uniq: dict[str, Any] = {}
            for r in results:
                rid = getattr(r, "id", None) if r is not None else None
                if rid and rid not in uniq:
                    uniq[rid] = r
            results = list(uniq.values())

        logger.info(f"Found {len(results)} Recovery Service Subnets")
        return results

    except Exception as e:
        logger.error(f"Error in list_recovery_service_subnets tool: {str(e)}")
        raise


@mcp.tool(
    description=(
        "Gets a recovery service subnet by OCID and makes sure the subnets list is "
        "present, using subnet_id if necessary. The result is one recovery service "
        "subnet."
    )
)
@_tool_logger("get_recovery_service_subnet")
def get_recovery_service_subnet(
    recovery_service_subnet_id: Annotated[str, "Recovery Service Subnet OCID"],
    opc_request_id: Annotated[Optional[str], "Unique identifier for the request"] = None,
    region: Annotated[Optional[str], "OCI region to execute the request in (e.g., us-ashburn-1)"] = None,
) -> RecoveryServiceSubnet:
    """
    Retrieves a single Recovery Service Subnet resource from Recovery Service and returns
    a RecoveryServiceSubnet model mapped from the OCI SDK response.
    """
    try:
        request_id = uuid.uuid4().hex
        client = get_recovery_client(region, request_id=request_id)

        kwargs = {}
        if opc_request_id is not None:
            kwargs["opc_request_id"] = opc_request_id

        response: oci.response.Response = client.get_recovery_service_subnet(
            recovery_service_subnet_id=recovery_service_subnet_id, **kwargs
        )

        data = response.data
        rss = map_recovery_service_subnet(data)
        # Ensure subnets is populated even if service omits the array
        try:
            if getattr(rss, "subnets", None) is None:
                sid = getattr(rss, "subnet_id", None)
                if sid:
                    rss.subnets = [sid]
        except Exception:
            pass
        logger.info(f"Fetched Recovery Service Subnet {recovery_service_subnet_id}")
        return rss

    except Exception as e:
        logger.error(f"Error in get_recovery_service_subnet tool: {str(e)}")
        raise


@mcp.tool(
    description=(
        "Fetches Recovery Service metrics for a time range. You choose the metric, "
        "time step, and how to combine values, and you can limit it to one protected "
        "database. The result is a simple time series where each item has dimensions "
        "and a list of {timestamp, value} points."
    )
)
@_tool_logger("get_recovery_service_metrics")
def get_recovery_service_metrics(
    compartment_id: Annotated[str, "The compartment OCID or compartment display name to query metrics for."],
    start_time: Annotated[str, "Start time for the metric query. Provide a RFC3339/ISO-8601 timestamp."],
    end_time: Annotated[str, "End time for the metric query. Provide a RFC3339/ISO-8601 timestamp."],
    fetch_for_child_compartment: Annotated[
        bool,
        "When true, scans the full subtree under compartment_id (including child compartments) and returns the combined results.",
    ] = False,
    metricName: Annotated[
        str,
        "The metric that the user wants to fetch. Currently we only support:"
        "SpaceUsedForRecoveryWindow, ProtectedDatabaseSize, ProtectedDatabaseHealth,"
        "DataLossExposure",
    ] = "SpaceUsedForRecoveryWindow",
    resolution: Annotated[
        str,
        "The granularity of the metric. Currently we only support: 1m, 5m, 1h, 1d. Default: 1h.",
    ] = "1h",
    aggregation: Annotated[
        str,
        "The aggregation for the metric. Currently we only support: mean, sum, max, min, count. Default: max",
    ] = "max",
    protected_database_id: Annotated[
        Optional[str],
        "Optional protected database OCID to filter by (maps to resourceId dimension)",
    ] = None,
) -> list[dict]:
    # Build Monitoring query against Recovery metrics namespace
    request_id = uuid.uuid4().hex
    monitoring_client = get_monitoring_client(request_id=request_id)
    namespace = "oci_recovery_service"
    filter_clause = f'{{resourceId="{protected_database_id}"}}' if protected_database_id else ""
    # Query format: MetricName[resolution]{filters}.aggregation()
    query = f"{metricName}[{resolution}]{filter_clause}.{aggregation}()"

    comp_ids = _compartment_ids_for_tool(
        compartment_id,
        fetch_for_child_compartment=fetch_for_child_compartment,
        request_id=request_id,
    )

    results: list[dict] = []

    for comp_id in comp_ids:
        # Fetch time series data for the metric and time window
        series_list = monitoring_client.summarize_metrics_data(
            compartment_id=comp_id,
            summarize_metrics_data_details=SummarizeMetricsDataDetails(
                namespace=namespace,
                query=query,
                start_time=start_time,
                end_time=end_time,
                resolution=resolution,
            ),
        ).data

        # Convert SDK series into a simple dict of dimensions + aggregated datapoints
        for series in series_list:
            logger.debug(f"Item structure: {series}")
            dims = getattr(series, "dimensions", None)
            points = []
            for p in getattr(series, "aggregated_datapoints", []):
                points.append(
                    {
                        "timestamp": getattr(p, "timestamp", None),
                        "value": getattr(p, "value", None),
                    }
                )
            results.append(
                {
                    "compartmentId": comp_id,
                    "dimensions": dims,
                    "datapoints": points,
                }
            )

    return results


@mcp.tool(
    description=(
        "Lists databases in a DB Home or, if none is given, across all DB Homes in a "
        "compartment. It can find DB Homes for you, fills in backup settings only when "
        "needed, and, where possible, links each database to its protection policy. "
        "The result is a list of database summaries with optional backup settings and "
        "protection policy ID."
    )
)
@_tool_logger("list_databases")
def list_databases(
    compartment_id: Annotated[
        Optional[str], "The compartment OCID or display name. Required if db_home_id is not provided."
    ] = None,
    fetch_for_child_compartment: Annotated[
        bool,
        "When true, scans the full subtree under compartment_id (including child compartments) and returns the combined results.",
    ] = False,
    db_home_id: Annotated[
        Optional[str],
        "A Database Home OCID. If omitted, all DB Homes in the compartment will be used.",
    ] = None,
    system_id: Annotated[
        Optional[str], "The OCID of the Exadata DB system to filter by (Exadata only)."
    ] = None,
    limit: Annotated[Optional[int], "The maximum number of items to return per page."] = None,
    page: Annotated[Optional[str], "The pagination token to continue listing from."] = None,
    sort_by: Annotated[Optional[str], 'Sort by field: "DBNAME" | "TIMECREATED"'] = None,
    sort_order: Annotated[Optional[str], '"ASC" or "DESC"'] = None,
    lifecycle_state: Annotated[Optional[str], "Exact lifecycle state filter."] = None,
    db_name: Annotated[Optional[str], "Exact database name filter (case-insensitive)."] = None,
    region: Annotated[Optional[str], "Region to execute the request, e.g., us-ashburn-1."] = None,
) -> list[DatabaseSummary]:
    try:
        request_id = uuid.uuid4().hex
        client = get_database_client(region, request_id=request_id)
        if compartment_id:
            compartment_id = _resolve_compartment_id(compartment_id)

        # Determine compartment scope
        comp_ids: list[str] = []
        if db_home_id is None:
            if not compartment_id:
                raise ValueError(
                    "Either db_home_id must be provided or compartment_id must be set to derive DB Homes."
                )
            comp_ids = _compartment_ids_for_tool(
                compartment_id,
                fetch_for_child_compartment=fetch_for_child_compartment,
                request_id=request_id,
            )
        else:
            # db_home_id is explicit: keep existing behavior and don't expand compartments
            comp_ids = [compartment_id] if compartment_id else []

        results: list[DatabaseSummary] = []

        # Try to correlate database_id -> protection_policy_id via Recovery PDs (best-effort)
        # If we're scanning child compartments, include PDs from each scanned compartment.
        pd_policy_by_dbid: dict[str, str] = {}
        if compartment_id:
            try:
                rec_client = get_recovery_client(region, request_id=request_id)
                pd_comp_ids = (
                    _compartment_ids_for_tool(
                        compartment_id,
                        fetch_for_child_compartment=fetch_for_child_compartment,
                        request_id=request_id,
                    )
                    if fetch_for_child_compartment
                    else [compartment_id]
                )

                for pd_comp_id in pd_comp_ids:
                    has_next = True
                    next_page = None
                    while has_next:
                        lp = rec_client.list_protected_databases(compartment_id=pd_comp_id, page=next_page)
                        has_next = lp.has_next_page
                        next_page = getattr(lp, "next_page", None)
                        pdata = lp.data
                        pitems = getattr(pdata, "items", pdata)
                        for it in pitems or []:
                            logger.debug(f"Item structure: {it}")
                            try:
                                if hasattr(oci, "util") and hasattr(oci.util, "to_dict"):
                                    d = oci.util.to_dict(it)
                                else:
                                    d = getattr(it, "__dict__", {}) or {}
                            except Exception:
                                d = getattr(it, "__dict__", {}) or {}
                            dbid = d.get("databaseId") or d.get("database_id")
                            ppid = d.get("protectionPolicyId") or d.get("protection_policy_id")
                            if dbid and ppid and dbid not in pd_policy_by_dbid:
                                pd_policy_by_dbid[dbid] = ppid
            except Exception:
                pd_policy_by_dbid = {}

        # Common list_databases filters shared across DB Homes
        common_kwargs: dict = {}
        if system_id is not None:
            common_kwargs["system_id"] = system_id
        if limit is not None:
            common_kwargs["limit"] = limit
        if page is not None:
            common_kwargs["page"] = page
        if sort_by is not None:
            common_kwargs["sort_by"] = sort_by
        if sort_order is not None:
            common_kwargs["sort_order"] = sort_order
        if lifecycle_state is not None:
            common_kwargs["lifecycle_state"] = lifecycle_state
        if db_name is not None:
            common_kwargs["db_name"] = db_name

        # Iterate compartments -> DB homes -> list databases
        for each_comp in comp_ids or [compartment_id] if compartment_id else []:
            # Determine DB Home scope for this compartment:
            # - If db_home_id not provided, discover all DB Homes in the compartment.
            # - If provided, just use that one.
            if db_home_id is None:
                home_ids = _fetch_db_home_ids_for_compartment(each_comp, region=region)
            else:
                home_ids = [db_home_id]

            if not home_ids:
                continue

            # For each DB Home, list databases and map summaries
            for hid in home_ids:
                kwargs = dict(common_kwargs)
                kwargs["db_home_id"] = hid
                if db_home_id is None:
                    kwargs["compartment_id"] = each_comp

                response: oci.response.Response = client.list_databases(**kwargs)
                raw = getattr(response.data, "items", response.data)
                for item in raw or []:
                    logger.debug(f"Item structure: {item}")
                    mapped = map_database_summary(item)
                    if mapped is None:
                        continue

                    # Enrich db_backup_config lazily by fetching full Database only if missing
                    try:
                        if getattr(mapped, "db_backup_config", None) is None:
                            db_id = getattr(item, "id", None) or (
                                getattr(item, "data", None) and getattr(item.data, "id", None)
                            )
                            if not db_id and hasattr(item, "__dict__"):
                                db_id = item.__dict__.get("id")
                            if db_id:
                                gd = client.get_database(database_id=db_id).data
                                # Try to locate backup config from object or dict forms
                                cfg_src = getattr(gd, "db_backup_config", None) or getattr(
                                    gd, "database_backup_config", None
                                )
                                if cfg_src is None:
                                    try:
                                        d = (
                                            oci.util.to_dict(gd)
                                            if hasattr(oci, "util") and hasattr(oci.util, "to_dict")
                                            else (getattr(gd, "__dict__", {}) or {})
                                        )
                                    except Exception:
                                        d = getattr(gd, "__dict__", {}) or {}
                                    cfg_src = (
                                        d.get("dbBackupConfig")
                                        or d.get("db_backup_config")
                                        or d.get("databaseBackupConfig")
                                        or d.get("database_backup_config")
                                    )
                                mapped.db_backup_config = map_db_backup_config(cfg_src)
                    except Exception:
                        # Best-effort enrichment; ignore failures and still return the summary
                        pass

                    # Enrich with protection policy id if we correlated via Recovery PDs earlier
                    try:
                        mapped.protection_policy_id = pd_policy_by_dbid.get(mapped.id)
                    except Exception:
                        pass
                    results.append(mapped)

        # De-dupe by DB OCID when scanning multiple compartments / homes
        if fetch_for_child_compartment and db_home_id is None:
            uniq: dict[str, DatabaseSummary] = {}
            for r in results:
                rid = getattr(r, "id", None) if r is not None else None
                if rid and rid not in uniq:
                    uniq[rid] = r
            results = list(uniq.values())

        return results
    except Exception as e:
        logger.error(f"Error in list_databases tool: {e}")
        raise


@mcp.tool(
    description=(
        "Gets a database by OCID and returns an easy object. Where possible, it also "
        "links the database to its protection policy. The result is one database."
    )
)
@_tool_logger("get_database")
def get_database(
    database_id: Annotated[str, "OCID of the Database to retrieve."],
    region: Annotated[Optional[str], "Canonical OCI region (e.g., us-ashburn-1)."] = None,
) -> Database:
    try:
        request_id = uuid.uuid4().hex
        client = get_database_client(region, request_id=request_id)
        resp = client.get_database(database_id=database_id)
        mapped = map_database(resp.data)
        # Enrich protection_policy_id by correlating with Recovery Service
        # Protected Databases in the same compartment
        try:
            # Extract compartment from response (SDK shape may differ)
            comp_id = getattr(resp.data, "compartment_id", None)
            if comp_id is None:
                try:
                    d = (
                        oci.util.to_dict(resp.data)
                        if hasattr(oci, "util") and hasattr(oci.util, "to_dict")
                        else (getattr(resp.data, "__dict__", {}) or {})
                    )
                except Exception:
                    d = getattr(resp.data, "__dict__", {}) or {}
                comp_id = d.get("compartmentId") or d.get("compartment_id")
            if comp_id:
                rec_client = get_recovery_client(region, request_id=request_id)
                has_next = True
                next_page = None
                found_ppid = None
                # Scan PDs in compartment until we find a match by databaseId
                while has_next and not found_ppid:
                    lp = rec_client.list_protected_databases(compartment_id=comp_id, page=next_page)
                    has_next = lp.has_next_page
                    next_page = getattr(lp, "next_page", None)
                    pdata = lp.data
                    pitems = getattr(pdata, "items", pdata)
                    for it in pitems or []:
                        try:
                            if hasattr(oci, "util") and hasattr(oci.util, "to_dict"):
                                d = oci.util.to_dict(it)
                            else:
                                d = getattr(it, "__dict__", {}) or {}
                        except Exception:
                            d = getattr(it, "__dict__", {}) or {}
                        if (d.get("databaseId") or d.get("database_id")) == database_id:
                            found_ppid = d.get("protectionPolicyId") or d.get("protection_policy_id")
                            break
                if mapped is not None:
                    mapped.protection_policy_id = found_ppid
        except Exception:
            # Non-fatal enrichment failure
            pass
        return mapped
    except Exception as e:
        logger.error(f"Error in get_database tool: {e}")
        raise


@mcp.tool(
    description=(
        "Finds database restore requests and returns only active or historical restore jobs."
        "Use this when answering customer questions about database restore status, "
        "restore history, or whether a restore request exists."
    )
)
@_tool_logger("list_restore")
def list_restore(
    compartment_id: Annotated[str, "Compartment OCID or compartment display name to scope work requests."],
    fetch_for_child_compartment: Annotated[
        bool,
        "When true, scans the full subtree under compartment_id (including child compartments) and returns the combined results.",
    ] = False,
    resource_id: Annotated[
        Optional[str], "Optional resource OCID to scope work requests (e.g., Database OCID)."
    ] = None,
    status: Annotated[
        Optional[str], "Optional work request status filter (e.g., IN_PROGRESS, SUCCEEDED, FAILED)."
    ] = None,
    limit: Annotated[Optional[int], "Maximum number of items per backend page."] = None,
    page: Annotated[Optional[str], "Pagination token (opc-next-page) when aggregate_pages=false."] = None,
    sort_order: Annotated[Optional[str], 'Sort order: "ASC" or "DESC".'] = None,
    sort_by: Annotated[Optional[str], "Sort by field when supported by the API."] = None,
    opc_request_id: Annotated[Optional[str], "Unique identifier for the request"] = None,
    region: Annotated[Optional[str], "Canonical OCI region (e.g., us-phoenix-1)."] = None,
    aggregate_pages: Annotated[bool, "When true (default), retrieves all pages."] = True,
) -> list[WorkRequest]:
    try:
        request_id = uuid.uuid4().hex
        client = get_work_request_client(region, request_id=request_id)

        def _is_restore_operation(operation: Optional[str]) -> bool:
            if operation is None:
                return False
            raw = str(operation).strip()
            if raw == "Restore Database":
                return True
            normalized = raw.replace("_", " ").replace("-", " ").lower()
            normalized = " ".join(normalized.split())
            return normalized == "restore database"

        comp_ids = _compartment_ids_for_tool(
            compartment_id,
            fetch_for_child_compartment=fetch_for_child_compartment,
            request_id=request_id,
        )

        results: list[WorkRequest] = []

        for each_comp in comp_ids or [compartment_id]:
            next_page = page
            while True:
                kwargs: dict[str, Any] = {
                    "compartment_id": each_comp,
                }
                if resource_id is not None:
                    kwargs["resource_id"] = resource_id
                if status is not None:
                    kwargs["status"] = status
                if sort_order is not None:
                    kwargs["sort_order"] = sort_order
                if sort_by is not None:
                    kwargs["sort_by"] = sort_by
                if opc_request_id is not None:
                    kwargs["opc_request_id"] = opc_request_id
                if limit is not None:
                    kwargs["limit"] = limit
                elif aggregate_pages:
                    kwargs["limit"] = 1000
                if next_page is not None:
                    kwargs["page"] = next_page

                response = client.list_work_requests(**kwargs)
                items = getattr(response.data, "items", response.data) or []
                raw_items = items if isinstance(items, list) else [items]

                for item in raw_items:
                    mapped = map_work_request(item)
                    if mapped is None:
                        continue
                    if _is_restore_operation(getattr(mapped, "operation_type", None)):
                        results.append(mapped)

                has_next = bool(getattr(response, "has_next_page", False))
                next_page = getattr(response, "next_page", None) if has_next else None
                if not (aggregate_pages and has_next and next_page):
                    break

        if fetch_for_child_compartment:
            uniq: dict[str, WorkRequest] = {}
            for r in results:
                rid = getattr(r, "id", None) if r is not None else None
                if rid and rid not in uniq:
                    uniq[rid] = r
            results = list(uniq.values())

        return results
    except Exception as e:
        logger.error("Error in list_restore tool: %s", e)
        raise


@mcp.tool(
    description=(
        "Lists database backups with flexible filters and optional auto-paging. If "
        "database_id is provided, lists all backups for that database. If compartment_id "
        "is provided, finds AVAILABLE databases with auto-backup enabled and lists their "
        "backups. It includes manual backups, automatic backups and LTR backups as well. "
        "It adds helpful fields like backup destination, database's unique name. The "
        "result is a list of easy-to-read backup summaries."
    )
)
@_tool_logger("list_backups")
def list_backups(
    compartment_id: Annotated[
        Optional[str], "Compartment OCID or compartment display name to scope the search."
    ] = None,
    fetch_for_child_compartment: Annotated[
        bool,
        "When true, scans the full subtree under compartment_id (including child compartments) and returns the combined results.",
    ] = False,
    database_id: Annotated[Optional[str], "OCID of the Database to filter backups for."] = None,
    lifecycle_state: Annotated[Optional[str], "Filter by lifecycle state."] = None,
    type: Annotated[Optional[str], "Backup type filter (e.g., INCREMENTAL, FULL)."] = None,
    limit: Annotated[
        Optional[int],
        "Maximum number of items per backend page (when aggregate_pages=false).",
    ] = None,
    page: Annotated[Optional[str], "Pagination token (opc-next-page) when aggregate_pages=false."] = None,
    region: Annotated[Optional[str], "Canonical OCI region (e.g., us-ashburn-1)."] = None,
    aggregate_pages: Annotated[bool, "When true (default), retrieves all pages."] = True,
) -> list[BackupSummary]:
    try:
        request_id = uuid.uuid4().hex
        client = get_database_client(region, request_id=request_id)

        def _to_dict(o):
            try:
                if hasattr(oci, "util") and hasattr(oci.util, "to_dict"):
                    d = oci.util.to_dict(o)
                    if isinstance(d, dict):
                        return d
            except Exception:
                pass
            return getattr(o, "__dict__", {}) if hasattr(o, "__dict__") else {}

        def _is_auto_backup_enabled_from_dict(d: dict) -> bool:
            cfg = None
            for k in (
                "dbBackupConfig",
                "db_backup_config",
                "backupConfig",
                "backup_config",
                "databaseBackupConfig",
                "database_backup_config",
            ):
                v = d.get(k)
                if isinstance(v, dict):
                    cfg = v
                    break
            src = cfg if isinstance(cfg, dict) else d
            for key in (
                "isAutoBackupEnabled",
                "is_auto_backup_enabled",
                "autoBackupEnabled",
                "auto_backup_enabled",
            ):
                if key in src and src[key] is not None:
                    return bool(src[key])
            return False

        def _list_all_backups_for_db(dbid: str) -> list[dict]:
            out: list[dict] = []
            next_token = None
            while True:
                call_kwargs = {"database_id": dbid}
                if lifecycle_state:
                    call_kwargs["lifecycle_state"] = lifecycle_state
                if type:
                    call_kwargs["type"] = type
                if not aggregate_pages:
                    if limit is not None:
                        call_kwargs["limit"] = limit
                    if page is not None and next_token is None:
                        call_kwargs["page"] = page
                if next_token is not None:
                    call_kwargs["page"] = next_token
                if "limit" not in call_kwargs or call_kwargs.get("limit") is None:
                    call_kwargs["limit"] = 1000
                resp = client.list_backups(**call_kwargs)
                items = getattr(resp.data, "items", resp.data) or []
                raw_list = items if isinstance(items, list) else [items]
                for obj in raw_list:
                    logger.debug(f"Item structure: {obj}")
                    mapped = map_backup_summary(obj)
                    if mapped is None:
                        continue
                    try:
                        out_dict = mapped.model_dump(exclude_none=False, by_alias=True)
                    except Exception:
                        try:
                            out_dict = mapped.dict(exclude_none=False, by_alias=True)
                        except Exception:
                            out_dict = _to_dict(mapped)

                    # Augment with raw SDK values for missing fields
                    try:
                        rawd = _to_dict(obj)
                    except Exception:
                        rawd = getattr(obj, "__dict__", {}) or {}

                    def _pick(d: dict, *keys: str):
                        for k in keys:
                            if k in d and d[k] is not None:
                                return d[k]
                        return None

                    if out_dict.get("database-size-in-gbs") is None:
                        ds = _pick(
                            rawd,
                            "database_size_in_gbs",
                            "databaseSizeInGBs",
                            "databaseSizeInGbs",
                        )
                        if ds is not None:
                            out_dict["database-size-in-gbs"] = ds
                    if out_dict.get("backup-destination-type") is None:
                        bdt = _pick(rawd, "backup_destination_type", "backupDestinationType")
                        if bdt is not None:
                            out_dict["backup-destination-type"] = bdt
                    if out_dict.get("retention-period-in-days") is None:
                        rpd = _pick(rawd, "retention_period_in_days", "retentionPeriodInDays")
                        if rpd is not None:
                            out_dict["retention-period-in-days"] = rpd
                    if out_dict.get("retention-period-in-years") is None:
                        rpy = _pick(rawd, "retention_period_in_years", "retentionPeriodInYears")
                        if rpy is not None:
                            out_dict["retention-period-in-years"] = rpy

                    # Ensure CLI-style keys are present even when values are still null
                    for _k in (
                        "database-size-in-gbs",
                        "backup-destination-type",
                        "retention-period-in-days",
                        "retention-period-in-years",
                    ):
                        if _k not in out_dict:
                            out_dict[_k] = None

                    out.append(out_dict)
                has_next = bool(getattr(resp, "has_next_page", False))
                next_token = getattr(resp, "next_page", None) if has_next else None
                if not (aggregate_pages and has_next and next_token):
                    break
            return out

        # Branch 1: database_id provided
        if database_id:
            backups = _list_all_backups_for_db(database_id)
            # Fetch and set db_unique_name for this database
            try:
                gdb = client.get_database(database_id=database_id)
                gdd = _to_dict(getattr(gdb, "data", None))
                dun = gdd.get("dbUniqueName") or gdd.get("db_unique_name")
            except Exception:
                dun = None
            for bk in backups:
                if "db_unique_name" not in bk or bk["db_unique_name"] is None:
                    bk["db_unique_name"] = dun
            return backups

        # Branch 2: compartment_id and region provided
        if compartment_id:
            comp_ids = _compartment_ids_for_tool(
                compartment_id,
                fetch_for_child_compartment=fetch_for_child_compartment,
                request_id=request_id,
            )

            # find DB Homes then list AVAILABLE databases (per compartment)
            eligible_db_ids: list[str] = []
            db_unique_cache: dict[str, Optional[str]] = {}
            for each_comp in comp_ids:
                home_ids = _fetch_db_home_ids_for_compartment(each_comp, region=region)
                for hid in home_ids or []:
                    next_db_page = None
                    while True:
                        kwargs_db = {
                            "compartment_id": each_comp,
                            "db_home_id": hid,
                            "lifecycle_state": "AVAILABLE",
                            "limit": 1000,
                        }
                        if next_db_page:
                            kwargs_db["page"] = next_db_page
                        dresp = client.list_databases(**kwargs_db)
                        ditems = getattr(dresp.data, "items", dresp.data) or []
                        for d in ditems:
                            logger.debug(f"Item structure: {d}")
                            d_dict = _to_dict(d)
                            dbid = d_dict.get("id") or getattr(d, "id", None)
                            dun = (
                                d_dict.get("dbUniqueName")
                                or d_dict.get("db_unique_name")
                                or getattr(d, "db_unique_name", None)
                            )
                            is_auto = _is_auto_backup_enabled_from_dict(d_dict)
                            if is_auto is False and dbid:
                                # fallback to GET for authoritative value and db_unique_name
                                try:
                                    g = client.get_database(database_id=dbid)
                                    gdd = _to_dict(getattr(g, "data", None))
                                    is_auto = _is_auto_backup_enabled_from_dict(gdd)
                                    if dun is None:
                                        dun = gdd.get("dbUniqueName") or gdd.get("db_unique_name")
                                except Exception:
                                    is_auto = False
                            if dbid:
                                if dun is not None:
                                    db_unique_cache[dbid] = dun
                                if is_auto:
                                    eligible_db_ids.append(dbid)
                        has_next = bool(getattr(dresp, "has_next_page", False))
                        next_db_page = getattr(dresp, "next_page", None) if has_next else None
                        if not has_next:
                            break

            # Aggregate backups for eligible DBs
            all_results: list[dict] = []
            seen_backup_ids: set[str] = set()
            for dbid in eligible_db_ids:
                backups = _list_all_backups_for_db(dbid)
                # Set db_unique_name from cache
                for bk in backups:
                    if "db_unique_name" not in bk or bk["db_unique_name"] is None:
                        bk["db_unique_name"] = db_unique_cache.get(dbid)

                if fetch_for_child_compartment:
                    # de-dupe by backup OCID across DBs/compartments
                    for bk in backups:
                        bid = bk.get("id") if isinstance(bk, dict) else None
                        if bid and bid in seen_backup_ids:
                            continue
                        if bid:
                            seen_backup_ids.add(bid)
                        all_results.append(bk)
                else:
                    all_results.extend(backups)

            return all_results

        # Neither database_id nor compartment_id provided
        raise ValueError("Provide database_id or compartment_id.")

    except Exception as e:
        logger.error("Error in list_backups tool: %s", e)
        raise


@mcp.tool(
    description=(
        "Gets a database backup by OCID and returns a clean dictionary. It includes "
        "common fields like database size, backup destination, and the database's "
        "unique name. The result is one backup with those helpful fields included."
    )
)
@_tool_logger("get_backup")
def get_backup(
    backup_id: Annotated[str, "OCID of the Backup to retrieve."],
    region: Annotated[Optional[str], "Canonical OCI region (e.g., us-ashburn-1)."] = None,
) -> Backup:
    """
    Retrieves a Database Backup by OCID and maps it to the server model.
    Mirrors the simpler logic used in rcv_mcp_server/fast_server.py without additional enrichment.
    """
    try:
        request_id = uuid.uuid4().hex
        client = get_database_client(region, request_id=request_id)
        resp = client.get_backup(backup_id=backup_id)
        mapped = map_backup(resp.data)
        try:
            out = mapped.model_dump(exclude_none=False, by_alias=True)
        except Exception:
            try:
                out = mapped.dict(exclude_none=False, by_alias=True)
            except Exception:
                out = getattr(mapped, "__dict__", {}) or {}
        # Try to augment from raw SDK object dict if mapping missed fields
        try:
            rawd = (
                oci.util.to_dict(resp.data)
                if hasattr(oci, "util") and hasattr(oci.util, "to_dict")
                else (getattr(resp.data, "__dict__", {}) or {})
            )
        except Exception:
            rawd = getattr(resp.data, "__dict__", {}) or {}

        def _pick(d: dict, *keys: str):
            for k in keys:
                if k in d and d[k] is not None:
                    return d[k]
            return None

        if out.get("database-size-in-gbs") is None:
            ds = _pick(rawd, "database_size_in_gbs", "databaseSizeInGBs", "databaseSizeInGbs")
            if ds is not None:
                out["database-size-in-gbs"] = ds
        if out.get("backup-destination-type") is None:
            bdt = _pick(rawd, "backup_destination_type", "backupDestinationType")
            if bdt is not None:
                out["backup-destination-type"] = bdt
        if out.get("retention-period-in-days") is None:
            rpd = _pick(rawd, "retention_period_in_days", "retentionPeriodInDays")
            if rpd is not None:
                out["retention-period-in-days"] = rpd
        if out.get("retention-period-in-years") is None:
            rpy = _pick(rawd, "retention_period_in_years", "retentionPeriodInYears")
            if rpy is not None:
                out["retention-period-in-years"] = rpy

        # Infer destination from DB backup config if still missing (no Recovery Service calls)
        try:
            dbid = out.get("database_id") or rawd.get("databaseId")
            if (out.get("backup-destination-type") is None) and dbid:
                gdb = client.get_database(database_id=dbid)
                gdd = (
                    oci.util.to_dict(getattr(gdb, "data", None))
                    if hasattr(oci, "util") and hasattr(oci.util, "to_dict")
                    else (getattr(getattr(gdb, "data", None), "__dict__", {}) or {})
                )
                cfg = (
                    gdd.get("dbBackupConfig")
                    or gdd.get("db_backup_config")
                    or gdd.get("databaseBackupConfig")
                )
                details = None
                if isinstance(cfg, dict):
                    details = cfg.get("backupDestinationDetails") or cfg.get("backup_destination_details")
                if not details:
                    details = gdd.get("backupDestinationDetails") or gdd.get("backup_destination_details")
                det_list = details if isinstance(details, list) else ([details] if details else [])
                types = []
                for det in det_list:
                    dd = (
                        det
                        if isinstance(det, dict)
                        else (
                            oci.util.to_dict(det)
                            if hasattr(oci, "util") and hasattr(oci.util, "to_dict")
                            else det.__dict__
                            if hasattr(det, "__dict__")
                            else {}
                        )
                    )
                    t = (dd or {}).get("type") or (dd or {}).get("destinationType")
                    tnorm = str(t).upper() if t else None
                    if tnorm in (
                        "RECOVERY_SERVICE",
                        "RECOVERY-SERVICE",
                        "DBRS",
                        "RECOVERY_SERVICE_BACKUP_DESTINATION",
                    ):
                        types.append("DBRS")
                    elif tnorm in ("OBJECT_STORE", "OBJECTSTORE", "OBJECT_STORAGE"):
                        types.append("OBJECT_STORE")
                    elif tnorm in ("NFS",):
                        types.append("NFS")
                if "DBRS" in types:
                    out["backup-destination-type"] = "DBRS"
                elif "OBJECT_STORE" in types:
                    out["backup-destination-type"] = "OBJECT_STORE"
                elif "NFS" in types:
                    out["backup-destination-type"] = "NFS"
        except Exception:
            pass

        # Ensure db_unique_name on model and output
        try:
            dbid = out.get("database_id") or rawd.get("databaseId") or rawd.get("database_id")
            if dbid:
                try:
                    gdb = client.get_database(database_id=dbid)
                    gdd = (
                        oci.util.to_dict(getattr(gdb, "data", None))
                        if hasattr(oci, "util") and hasattr(oci.util, "to_dict")
                        else (getattr(getattr(gdb, "data", None), "__dict__", {}) or {})
                    )
                    dun = gdd.get("dbUniqueName") or gdd.get("db_unique_name")
                    try:
                        if getattr(mapped, "db_unique_name", None) is None:
                            mapped.db_unique_name = dun
                    except Exception:
                        pass
                    if dun is not None:
                        out["db_unique_name"] = dun
                except Exception:
                    pass
        except Exception:
            pass

        # Ensure CLI-style keys are present even when values are still null
        for _k in (
            "database-size-in-gbs",
            "backup-destination-type",
            "retention-period-in-days",
            "retention-period-in-years",
        ):
            if _k not in out:
                out[_k] = None
        return out
    except Exception as e:
        logger.error("Error in get_backup tool: %s", e)
        raise


@mcp.tool(
    description=(
        "Summarizes how databases in a compartment or DB Home are backed up. It can "
        "find DB Homes, looks at each database’s backup settings, can include the time "
        "of the most recent backup, and groups results by destination type while calling "
        "out databases that aren’t configured. The result is one summary object with "
        "counts, name lists, and per‑database details."
    )
)
@_tool_logger("summarize_protected_database_backup_destination")
def summarize_protected_database_backup_destination(
    compartment_id: Annotated[
        Optional[str],
        "Compartment OCID or compartment display name. If omitted, defaults to the tenancy/DEFAULT profile.",
    ] = None,
    fetch_for_child_compartment: Annotated[
        bool,
        "When true, scans the full subtree under compartment_id (including child compartments) and returns aggregated summary plus per-compartment breakdown.",
    ] = False,
    region: Annotated[Optional[str], "Canonical OCI region (e.g., us-ashburn-1)."] = None,
    db_home_id: Annotated[
        Optional[str],
        "Optional DB Home OCID to scope databases. If omitted, all DB Homes in the compartment are used.",
    ] = None,
    include_last_backup_time: Annotated[
        bool, "If true, compute last backup time per DB (extra API calls)."
    ] = True,
    db_name: Annotated[Optional[str], "Exact database name filter (case-insensitive)."] = None,
    limit_per_home: Annotated[Optional[int], "Max databases to fetch per DB Home."] = None,
    max_db_homes: Annotated[Optional[int], "Max number of DB Homes to scan."] = None,
    max_total_databases: Annotated[Optional[int], "Global cap on databases to scan."] = None,
) -> ProtectedDatabaseBackupDestinationSummary:
    try:
        request_id = uuid.uuid4().hex
        db_client = get_database_client(region, request_id=request_id)
        if not compartment_id:
            compartment_id = get_tenancy()

        comp_ids = _compartment_ids_for_tool(
            compartment_id,
            fetch_for_child_compartment=fetch_for_child_compartment,
            request_id=request_id,
        )

        # Discover DB Homes if not specified, then list databases with lifecycle_state=AVAILABLE
        # NOTE: db_home_id is a single home; we do NOT expand it across compartments.
        home_ids_by_comp: dict[str, list[str]] = {}
        for each_comp in comp_ids:
            home_ids_by_comp[each_comp] = (
                [db_home_id] if db_home_id else _fetch_db_home_ids_for_compartment(each_comp, region=region)
            )

        # Explicitly bind the SDK method to avoid any accidental reference to the MCP tool
        list_dbs_method = getattr(db_client, "list_databases")
        db_summaries: list[Any] = []
        for each_comp, home_ids in home_ids_by_comp.items():
            if not home_ids:
                continue
            for hid in home_ids[:max_db_homes] if (max_db_homes is not None) else home_ids:
                call_kwargs = {
                    "compartment_id": each_comp,
                    "db_home_id": hid,
                    "lifecycle_state": "AVAILABLE",
                }
                if db_name is not None:
                    call_kwargs["db_name"] = db_name
                if limit_per_home is not None:
                    call_kwargs["limit"] = limit_per_home
                next_page = None
                while True:
                    local_kwargs = dict(call_kwargs)
                    if next_page:
                        local_kwargs["page"] = next_page
                    resp = list_dbs_method(**local_kwargs)
                    data = getattr(resp.data, "items", resp.data)
                    if isinstance(data, list):
                        db_summaries.extend(data)
                    elif data is not None:
                        db_summaries.append(data)
                    if max_total_databases is not None and len(db_summaries) >= max_total_databases:
                        db_summaries = db_summaries[:max_total_databases]
                        break
                    has_next = bool(getattr(resp, "has_next_page", False))
                    next_page = getattr(resp, "next_page", None) if has_next else None
                    if not has_next:
                        break

        # Simplified: do not correlate via Recovery Protected Databases

        # Helper routines to normalize SDK objects and read fields across variants
        def _to_dict(o: Any) -> dict:
            try:
                if hasattr(oci, "util") and hasattr(oci.util, "to_dict"):
                    d = oci.util.to_dict(o)
                    if isinstance(d, dict):
                        return d
            except Exception:
                pass
            return getattr(o, "__dict__", {}) if hasattr(o, "__dict__") else {}

        def _get(o: Any, *names: str):
            # Try attribute names first, then dict conversion
            for n in names:
                if hasattr(o, n):
                    v = getattr(o, n)
                    if v is not None:
                        return v
            d = _to_dict(o)
            for n in names:
                if d.get(n) is not None:
                    return d.get(n)
            return None

        def _extract_backup_destination_details(db_dict: dict) -> list[dict]:
            # Discover backup destination details from known key variants
            cfg = None
            for k in (
                "dbBackupConfig",
                "db_backup_config",
                "backupConfig",
                "backup_config",
                "databaseBackupConfig",
                "database_backup_config",
            ):
                if isinstance(db_dict.get(k), dict):
                    cfg = db_dict.get(k)
                    break
            if cfg is None:
                cfg = db_dict if isinstance(db_dict, dict) else {}
            details = (
                cfg.get("backupDestinationDetails")
                or cfg.get("backup_destination_details")
                or db_dict.get("backupDestinationDetails")
                or db_dict.get("backup_destination_details")
            )
            if not details:
                return []
            return details if isinstance(details, list) else [details]

        def _normalize_dest_type(t: Optional[str]) -> str:
            # Canonicalize destination types to a small set for reporting
            if not t:
                return "UNKNOWN"
            u = str(t).upper()
            if u in (
                "RECOVERY_SERVICE",
                "RECOVERY-SERVICE",
                "DBRS",
                "RECOVERY_SERVICE_BACKUP_DESTINATION",
            ):
                return "DBRS"
            if u in ("OBJECT_STORE", "OBJECTSTORE", "OBJECT_STORAGE"):
                return "OBJECT_STORE"
            if u in ("NFS",):
                return "NFS"
            return u

        def _is_auto_backup_enabled(db_dict: dict) -> bool:
            # Determine if auto-backup is enabled from known config keys
            cfg = None
            for k in (
                "dbBackupConfig",
                "db_backup_config",
                "backupConfig",
                "backup_config",
                "databaseBackupConfig",
                "database_backup_config",
            ):
                v = db_dict.get(k)
                if isinstance(v, dict):
                    cfg = v
                    break
            if isinstance(cfg, dict):
                for key in (
                    "isAutoBackupEnabled",
                    "is_auto_backup_enabled",
                    "autoBackupEnabled",
                    "auto_backup_enabled",
                ):
                    if key in cfg and cfg[key] is not None:
                        return bool(cfg[key])
            for key in (
                "isAutoBackupEnabled",
                "is_auto_backup_enabled",
                "autoBackupEnabled",
                "auto_backup_enabled",
            ):
                if key in db_dict and db_dict[key] is not None:
                    return bool(db_dict[key])
            return False

        def _read_backup_times_from_obj(o: Any) -> list[Any]:
            # Collect possible time fields from a backup object (SDK shapes differ)
            times = []
            for attr in (
                "time_ended",
                "timeEnded",
                "time_started",
                "timeStarted",
                "time_created",
                "timeCreated",
            ):
                v = getattr(o, attr, None)
                if v is not None:
                    times.append(v)
            if not times:
                d = _to_dict(o)
                for k in ("timeEnded", "timeStarted", "timeCreated"):
                    if d.get(k) is not None:
                        times.append(d[k])
            return times

        # Aggregation structures for summary + per-DB details
        items: list[ProtectedDatabaseBackupDestinationItem] = []
        counts_by_type: dict[str, int] = {}
        db_names_by_type: dict[str, list[str]] = {}
        unconfigured = 0
        unconfigured_names: list[str] = []
        has_backups_names: list[str] = []

        get_db = db_client.get_database
        list_bk = db_client.list_backups

        # Iterate each DB summary, fetch full DB to inspect backup config and infer destinations
        for s in db_summaries:
            try:
                sid = _get(s, "id")
                if not sid:
                    continue
                db_name_val = _get(s, "db_name", "dbName")

                # Prefer backup config from summary item to avoid per-DB GET when possible
                d_obj = None
                d_dict = _to_dict(s)
                cfg_present = False
                try:
                    cfg_present = any(
                        isinstance(d_dict.get(k), dict)
                        for k in (
                            "dbBackupConfig",
                            "db_backup_config",
                            "databaseBackupConfig",
                            "database_backup_config",
                            "backupConfig",
                            "backup_config",
                        )
                    )
                except Exception:
                    cfg_present = False
                if not cfg_present:
                    dresp = get_db(database_id=sid)
                    d_obj = getattr(dresp, "data", None)
                    d_dict = _to_dict(d_obj)

                # Extract configured destination details (normalize to a list of dicts)
                dest_details = _extract_backup_destination_details(d_dict)
                dest_types: list[str] = []
                dest_ids: list[str] = []
                for det in dest_details:
                    dd = det if isinstance(det, dict) else _to_dict(det)
                    t_norm = _normalize_dest_type(dd.get("type") or dd.get("destinationType"))
                    did = dd.get("id") or dd.get("backupDestinationId") or dd.get("destinationId")
                    if t_norm:
                        dest_types.append(t_norm)
                    if did:
                        dest_ids.append(did)

                # Deduplicate and restrict to DBRS/OBJECT_STORE; prefer DBRS if both
                dest_types = list(dict.fromkeys([t for t in dest_types if t in ("DBRS", "OBJECT_STORE")]))
                if "DBRS" in dest_types and "OBJECT_STORE" in dest_types:
                    dest_types = ["DBRS"]
                dest_ids = list(dict.fromkeys([d for d in dest_ids if d]))

                auto_enabled = _is_auto_backup_enabled(d_dict)
                # Configured strictly when auto-backup is enabled
                configured = bool(auto_enabled)
                status = "CONFIGURED" if configured else "UNCONFIGURED"
                last_backup_time = None

                # Optionally compute last backup time (more API calls)
                if include_last_backup_time:
                    try:
                        b_resp = list_bk(database_id=sid)
                        b_data = getattr(b_resp.data, "items", b_resp.data)
                        backups = (
                            b_data if isinstance(b_data, list) else [b_data] if b_data is not None else []
                        )
                        best = None
                        for b in backups:
                            for t in _read_backup_times_from_obj(b):
                                if best is None or (str(t) > str(best)):
                                    best = t
                        if best is not None:
                            last_backup_time = best
                    except Exception:
                        pass
                else:
                    pass

                # Aggregate summary counters and name lists by status/destination
                name_for_lists = db_name_val or sid
                if status == "CONFIGURED":
                    # Select a single effective destination type: DBRS preferred over OBJECT_STORE
                    eff_type = (
                        "DBRS"
                        if "DBRS" in dest_types
                        else ("OBJECT_STORE" if "OBJECT_STORE" in dest_types else "UNKNOWN")
                    )
                    if eff_type in ("DBRS", "OBJECT_STORE"):
                        counts_by_type[eff_type] = counts_by_type.get(eff_type, 0) + 1
                        db_names_by_type.setdefault(eff_type, []).append(name_for_lists)
                else:
                    unconfigured += 1
                    unconfigured_names.append(name_for_lists)

                # Append per-DB detail record
                items.append(
                    ProtectedDatabaseBackupDestinationItem(
                        database_id=sid,
                        db_name=db_name_val,
                        status=status,
                        destination_types=dest_types,
                        destination_ids=dest_ids,
                        last_backup_time=last_backup_time,
                    )
                )
            except Exception:
                # Continue on per-DB errors to maximize overall coverage
                continue

        # Sorting helpers: prioritize DBRS over OBJECT_STORE and then by name
        def _dest_rank(types: list[str]) -> int:
            if not types:
                return 99
            order = {"DBRS": 0, "OBJECT_STORE": 1, "NFS": 2, "UNKNOWN": 3}
            return min(order.get(t, 3) for t in types)

        items = sorted(
            items,
            key=lambda it: (
                _dest_rank(it.destination_types),
                (it.db_name or ""),
            ),
        )

        # Name list post-processing
        def _uniq_sorted(xs: list[str]) -> list[str]:
            return sorted(dict.fromkeys([x for x in xs if x]))

        # Preserve duplicates for name lists that can correspond to different DB OCIDs
        def _sorted_keep(xs: list[str]) -> list[str]:
            return sorted([x for x in xs if x])

        db_names_by_type = {k: _sorted_keep(v) for k, v in db_names_by_type.items()}
        unconfigured_names = _uniq_sorted(unconfigured_names)
        has_backups_names = _uniq_sorted(has_backups_names)

        # De-dupe by DB OCID when scanning multiple compartments
        if fetch_for_child_compartment:
            uniq_items: dict[str, ProtectedDatabaseBackupDestinationItem] = {}
            for it in items:
                did = getattr(it, "database_id", None)
                if did and did not in uniq_items:
                    uniq_items[did] = it
            items = list(uniq_items.values())

        return ProtectedDatabaseBackupDestinationSummary(
            compartment_id=compartment_id,
            region=region,
            total_databases=len(db_summaries),
            unconfigured_count=unconfigured,
            counts_by_destination_type=counts_by_type,
            db_names_by_destination_type=db_names_by_type,
            unconfigured_db_names=unconfigured_names,
            has_backups_db_names=has_backups_names,
            items=items,
        )
    except Exception as e:
        logger.error(f"Error in summarize_protected_database_backup_destination tool: {e}")
        raise


@mcp.tool(
    description=(
        "Lists database homes in a compartment with optional lifecycle filters, "
        "defaulting to your tenancy when no compartment is given, and handles paging "
        "for you. The result is a list of database home summaries."
    )
)
@_tool_logger("list_db_homes")
def list_db_homes(
    compartment_id: Annotated[
        Optional[str], "Compartment OCID or compartment display name to scope the search."
    ] = None,
    fetch_for_child_compartment: Annotated[
        bool,
        "When true, scans the full subtree under compartment_id (including child compartments) and returns the combined results.",
    ] = False,
    db_system_id: Annotated[
        Optional[str], "The OCID of the Exadata DB system to filter the DB homes by."
    ] = None,
    limit: Annotated[Optional[int], "Maximum number of items per page."] = None,
    page: Annotated[Optional[str], "Pagination token (opc-next-page)."] = None,
    region: Annotated[Optional[str], "Canonical OCI region (e.g., us-ashburn-1)."] = None,
) -> list[DatabaseHomeSummary]:
    # Note: This helper is not exposed as an MCP tool; other tools use it internally.
    try:
        request_id = uuid.uuid4().hex
        client = get_database_client(region, request_id=request_id)
        if not compartment_id and not db_system_id:
            compartment_id = get_tenancy()

        comp_ids = (
            _compartment_ids_for_tool(
                compartment_id,
                fetch_for_child_compartment=fetch_for_child_compartment,
                request_id=request_id,
            )
            if compartment_id
            else []
        )

        results: list[DatabaseHomeSummary] = []
        for each_comp in comp_ids or [compartment_id] if compartment_id else []:
            has_next = True
            next_page = page
            while has_next:
                kwargs: dict = {"page": next_page}
                if each_comp:
                    kwargs["compartment_id"] = each_comp
                if db_system_id:
                    kwargs["db_system_id"] = db_system_id
                if limit is not None:
                    kwargs["limit"] = limit
                resp = client.list_db_homes(**kwargs)
                data = getattr(resp.data, "items", resp.data)
                for it in data or []:
                    m = map_database_home_summary(it)
                    if m is not None:
                        results.append(m)
                has_next = resp.has_next_page
                next_page = resp.next_page if hasattr(resp, "next_page") else None

        if fetch_for_child_compartment:
            uniq: dict[str, DatabaseHomeSummary] = {}
            for r in results:
                rid = getattr(r, "id", None) if r is not None else None
                if rid and rid not in uniq:
                    uniq[rid] = r
            results = list(uniq.values())

        return results
    except Exception as e:
        logger.error(f"Error in list_db_homes tool: {e}")
        raise


@mcp.tool(
    description=(
        "Gets a database home by OCID and returns it as a simple object. The result is one database home."
    )
)
@_tool_logger("get_db_home")
def get_db_home(
    db_home_id: Annotated[str, "OCID of the DB Home to retrieve."],
    region: Annotated[Optional[str], "Canonical OCI region (e.g., us-ashburn-1)."] = None,
) -> DatabaseHome:
    try:
        request_id = uuid.uuid4().hex
        client = get_database_client(region, request_id=request_id)
        resp = client.get_db_home(db_home_id=db_home_id)
        return map_database_home(resp.data)
    except Exception as e:
        logger.error(f"Error in get_db_home tool: {e}")
        raise


@mcp.tool(
    description=(
        "Lists database systems in a compartment with optional lifecycle filters, "
        "defaulting to your tenancy when no compartment is given, and handles paging "
        "for you. The result is a list of database system summaries."
    )
)
@_tool_logger("list_db_systems")
def list_db_systems(
    compartment_id: Annotated[
        Optional[str], "Compartment OCID or compartment display name to scope the search."
    ] = None,
    fetch_for_child_compartment: Annotated[
        bool,
        "When true, scans the full subtree under compartment_id (including child compartments) and returns the combined results.",
    ] = False,
    lifecycle_state: Annotated[Optional[str], "Filter by lifecycle state."] = None,
    limit: Annotated[Optional[int], "Maximum number of items per page."] = None,
    page: Annotated[Optional[str], "Pagination token (opc-next-page)."] = None,
    region: Annotated[Optional[str], "Canonical OCI region (e.g., us-ashburn-1)."] = None,
) -> list[DbSystemSummary]:
    try:
        request_id = uuid.uuid4().hex
        client = get_database_client(region, request_id=request_id)
        if not compartment_id:
            compartment_id = get_tenancy()

        comp_ids = (
            _compartment_ids_for_tool(
                compartment_id,
                fetch_for_child_compartment=fetch_for_child_compartment,
                request_id=request_id,
            )
            if compartment_id
            else []
        )

        results: list[DbSystemSummary] = []
        for each_comp in comp_ids or [compartment_id] if compartment_id else []:
            has_next = True
            next_page = page
            while has_next:
                kwargs: dict = {"page": next_page}
                if each_comp:
                    kwargs["compartment_id"] = each_comp
                if lifecycle_state:
                    kwargs["lifecycle_state"] = lifecycle_state
                if limit is not None:
                    kwargs["limit"] = limit
                resp = client.list_db_systems(**kwargs)
                data = getattr(resp.data, "items", resp.data)
                for it in data or []:
                    m = map_db_system_summary(it)
                    if m is not None:
                        results.append(m)
                has_next = resp.has_next_page
                next_page = resp.next_page if hasattr(resp, "next_page") else None

        if fetch_for_child_compartment:
            uniq: dict[str, DbSystemSummary] = {}
            for r in results:
                rid = getattr(r, "id", None) if r is not None else None
                if rid and rid not in uniq:
                    uniq[rid] = r
            results = list(uniq.values())

        return results
    except Exception as e:
        logger.error(f"Error in list_db_systems tool: {e}")
        raise


@mcp.tool(
    description=(
        "Gets a database system by OCID and returns it as a convenient object. The "
        "result is one database system."
    )
)
@_tool_logger("get_db_system")
def get_db_system(
    db_system_id: Annotated[str, "OCID of the DB System to retrieve."],
    region: Annotated[Optional[str], "Canonical OCI region (e.g., us-ashburn-1)."] = None,
) -> DbSystem:
    try:
        request_id = uuid.uuid4().hex
        client = get_database_client(region, request_id=request_id)
        resp = client.get_db_system(db_system_id=db_system_id)
        return map_db_system(resp.data)
    except Exception as e:
        logger.error(f"Error in get_db_system tool: {e}")
        raise


@mcp.tool(
    description=(
        "Returns dashboard-generation guidance for OCI Recovery Service, including "
        "cloud-protected databases."
    )
)
def oci_recovery_service_dashboard_prompt() -> str:
    """Return dashboard-generation guidance as a tool for clients without prompt support."""
    return OCI_RECOVERY_SERVICE_DASHBOARD_PROMPT


@mcp.tool(
    description=(
        "Returns readiness-assessment and onboarding guidance for an on-premises "
        "Oracle Database using Cloud Protect."
    )
)
def onboard_database_with_cloud_protect() -> str:
    """Return Cloud Protect onboarding guidance without inspecting or changing an environment."""
    return CLOUD_PROTECT_ONBOARDING_PROMPT


@mcp.tool(
    name="OutofplaceRestoreOfDatabase",
    description=(
        "CDB Out-of-Place Recovery to an Alternate Location Using RCV and RMAN\n"
        "Use this procedure when an Oracle Multitenant Container Database (CDB) must be "
        "recovered to a different location.\n\n"
        "Typical scenarios include:\n\n"
        "Recovering the database after the source cluster has been lost or deleted due "
        "to a disaster.\n"
        "Creating an alternate database environment for testing, reporting, or auditing "
        "purposes."
    ),
)
def outofplace_restore_of_database(
    source_database_name: Annotated[str, "Source CDB database name"],
    target_database_address: Annotated[str, "Target database host address or IP address"],
    protected_database_ocid: Annotated[str, "Recovery Service protected database OCID"],
    source_database_address: Annotated[
            Optional[str], "Source database host address or IP address"
    ] = None,
    connection_details: Annotated[
        Optional[str], "Approved source and target connection details supplied by the operator"
    ] = None,
) -> str:
    """Return a populated disaster-recovery runbook prompt without running recovery operations."""
    validation_errors = _validate_outofplace_restore_inputs(
        source_database_address=source_database_address,
        source_database_name=source_database_name,
        target_database_address=target_database_address,
        protected_database_ocid=protected_database_ocid,
    )
    if validation_errors:
        return "Cannot populate the recovery runbook. Correct these inputs and try again:\n- " + (
            "\n- ".join(validation_errors)
        )

    replacements = {
        "<source database address>": source_database_address
        or "Not provided; request the source database address before execution.",
        "<source database name>": source_database_name,
        "<target database address>": target_database_address,
        "<ocid of recovery service protected databases>": protected_database_ocid,
        "<connection details>": connection_details
        or "No connection details supplied; request approved connection details before execution.",
    }
    prompt = OUT_OF_PLACE_RESTORE_OF_DATABASE_PROMPT
    for placeholder, value in replacements.items():
        prompt = prompt.replace(placeholder, value)
    return prompt


_OCID_PATTERN = re.compile(
    r"^ocid1\.[a-z][a-z0-9-]*\.[a-z0-9-]+\.(?:[a-z0-9-]*\.)?[A-Za-z0-9_-]+$"
)


def _validate_outofplace_restore_inputs(
    *,
    source_database_address: Optional[str],
    source_database_name: str,
    target_database_address: str,
    protected_database_ocid: str,
) -> list[str]:
    """Validate values before inserting them into the recovery runbook prompt."""
    errors: list[str] = []
    for field_name, address in (
        ("source_database_address", source_database_address),
        ("target_database_address", target_database_address),
    ):
        if address is None and field_name == "source_database_address":
            continue
        if not isinstance(address, str):
            errors.append(f"{field_name} must be an IP address.")
            continue
        try:
            ipaddress.ip_address(address)
        except ValueError:
            errors.append(f"{field_name} must be an IP address.")

    if (
        not isinstance(source_database_name, str)
        or not source_database_name
        or len(source_database_name) >= 32
        or any(character.isspace() for character in source_database_name)
    ):
        errors.append(
            "source_database_name must be a single string with fewer than 32 characters."
        )

    if not isinstance(protected_database_ocid, str) or not _OCID_PATTERN.fullmatch(
        protected_database_ocid
    ):
        errors.append("protected_database_ocid must be a valid OCI OCID.")

    return errors


def main():
    # Entrypoint: choose transport based on env; always log startup meta and log file location
    host = os.getenv("ORACLE_MCP_HOST")
    port = os.getenv("ORACLE_MCP_PORT")
    method = _effective_auth_method()

    # Log startup and where logs are written
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
    log_dir = os.getenv("ORACLE_MCP_LOG_DIR", os.path.join(base_dir, "logs"))
    log_file = os.getenv("ORACLE_MCP_LOG_FILE", os.path.join(log_dir, "oci_recovery_mcp_server.log"))
    logger.info("Starting %s v%s (auth_method=%s)", __project__, __version__, method)
    logger.info("Logs will be written to: %s", os.path.abspath(log_file))

    if method == "oauth":
        # OAuth / UPST token exchange is served over the streamable HTTP transport.
        oauth_host = host or "127.0.0.1"
        oauth_port = int(port or "8000")
        logger.info("Running FastMCP over streamable HTTP with OCI IAM OAuth at http://%s:%s", oauth_host, oauth_port)
        mcp.run(transport="http", host=oauth_host, port=oauth_port)
    elif host and port:
        logger.info("Running FastMCP over HTTP at http://%s:%s", host, port)
        mcp.run(transport="http", host=host, port=int(port))
    else:
        logger.info("Running FastMCP over stdio transport")
        mcp.run()


if __name__ == "__main__":
    main()
