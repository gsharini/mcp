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
# - If ORACLE_MCP_HOST and ORACLE_MCP_PORT are set: Streamable HTTP, with OCI IAM
#   (IDCS) sign-in per caller.
# - Otherwise stdio (default for MCP), on the operator's own OCI profile credentials.
#
# Important robustness choices:
# - We add an "additional_user_agent" string to all OCI client configs for traceability.
# - All credential resolution is delegated to the shared oracle-mcp-common library:
#   build_auth_context() for profile-backed session/apikey credentials, and
#   build_idcs_http_auth()/IDCSHttpAuth.context_for() for HTTP.
# - We try to be resilient to SDK shape differences by using getattr/__dict__/to_dict
#   wherever possible, especially for pagination and nested model fields.
# - We log key milestones and counts for better operability and diagnostics.

import hashlib
import inspect
import json
import logging
import os
from pathlib import Path
import re
import tempfile
import time
import traceback
import uuid
from contextvars import ContextVar
from logging.handlers import RotatingFileHandler
from typing import Annotated, Any, Callable, Optional

import oci
from dotenv import find_dotenv, load_dotenv
from fastmcp import FastMCP
from fastmcp.server.dependencies import get_access_token, get_http_request
from fastmcp.utilities.auth import parse_scopes
from oci.monitoring.models import SummarizeMetricsDataDetails
from oracle_mcp_common import (
    AuthOptions,
    AuthType,
    IDCSHttpAuth,
    build_auth_context,
    build_idcs_http_auth,
    resolve_auth_type,
    resolve_config_file,
    resolve_profile_name,
)

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
    ProtectedDatabaseHealthSummary,
    ProtectedDatabaseRedoCounts,
    ProtectedDatabaseRedoSummary,
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

# Load configuration from a .env file (if present) so all settings can live in one
# config file instead of being exported as environment variables. This runs before
# any module-level env reads below. Precedence: real environment variables win over
# the file (override=False). Point ORACLE_MCP_ENV_FILE at a specific file to override
# the default ".env" discovery (which walks up from the current working directory).
_ENV_FILE = os.getenv("ORACLE_MCP_ENV_FILE") or find_dotenv(usecwd=True)
if _ENV_FILE:
    load_dotenv(_ENV_FILE, override=False)

"""MCP tools available in this server:
- fetch_regions_subscribed
- list_protected_databases
- get_protected_database
- summarize_protected_database_health
- summarize_protected_database_redo_status
- summarize_backup_space_used
- check_recovery_service_limits
- list_protection_policies
- get_protection_policy
- list_recovery_service_subnets
- get_recovery_service_subnet
- get_recovery_service_metrics
- list_databases
- get_database
- list_backups
- get_backup
- list_restore
- summarize_protected_database_backup_destination
- list_db_homes
- get_db_home
- list_db_systems
- get_db_system
- oci_recovery_service_dashboard_prompt
- onboard_database_to_recovery_service
- diagnose_recovery_service_issue
"""

# Logging setup
_STATE_DIR_ENV = "ORACLE_MCP_STATE_DIR"
_STATE_DIR_NAME = ".oci-recovery-mcp"

# Where logging actually ended up, reported at startup. Set by setup_logging().
_LOG_DESTINATION = "stderr"


def _state_dir() -> Path:
    """Per-user directory for this server's own state (logs, installation id).

    Deliberately outside the install tree: the package directory belongs to the
    installer, is read-only on a hardened deployment, and is discarded entirely
    between `uvx` runs -- which would silently throw away the logs an operator is
    told to read. Override with ORACLE_MCP_STATE_DIR when the home directory is
    not writable either.
    """
    configured = (os.getenv(_STATE_DIR_ENV) or "").strip()
    if configured:
        return Path(configured).expanduser()
    try:
        return Path.home() / _STATE_DIR_NAME
    except (RuntimeError, OSError):
        # Path.home() raises when the environment has no home directory at all,
        # which happens in minimal containers.
        return Path(tempfile.gettempdir()) / _STATE_DIR_NAME


def _resolved_log_file() -> str:
    """The log file this process writes to, before any fallback is applied."""
    log_dir = os.getenv("ORACLE_MCP_LOG_DIR") or str(_state_dir() / "logs")
    return os.path.abspath(
        os.getenv("ORACLE_MCP_LOG_FILE") or os.path.join(log_dir, "oci_recovery_mcp_server.log")
    )


class _PrivateRotatingFileHandler(RotatingFileHandler):
    """Rotating handler whose files are readable only by their owner.

    Tool arguments, and tool results at DEBUG, put a tenancy's resource inventory
    in this file. Rotation opens a new file each time, so the mode is applied on
    every open rather than once at setup.
    """

    def _open(self):
        """Open the next log file and tighten its mode to owner-only."""
        stream = super()._open()
        try:
            os.chmod(self.baseFilename, 0o600)
        except OSError:
            # An unchmod-able file (a mounted pipe, an exotic filesystem) is not
            # a reason to stop logging; the file just keeps its default mode.
            pass
        return stream


def setup_logging():
    """
    Configure root logging for the server: level, rotating file handler, console.

    Called once at import, before any tool runs. File logging is best effort --
    when the log file cannot be opened the server keeps running and falls back to
    stderr -- so a read-only or full filesystem never blocks startup.

    Environment:
    - ORACLE_MCP_LOG_LEVEL: root level (default INFO).
    - ORACLE_MCP_LOG_TO_STDOUT: add a console handler (writes to stderr, so it is
      safe under stdio transport). Forced on when file logging is unavailable.
    - ORACLE_SDK_LOG_LEVEL: level for the noisy ``oci`` logger (default WARNING).
    """
    global _LOG_DESTINATION

    # Resolve log level from env, default to INFO
    level_name = os.getenv("ORACLE_MCP_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    log_to_stdout_env = os.getenv("ORACLE_MCP_LOG_TO_STDOUT")
    if log_to_stdout_env is None:
        os.environ["ORACLE_MCP_LOG_TO_STDOUT"] = "0"

    # Configure root logger once
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S%z",
    )

    # Add a rotating file handler if not already present for this file. File
    # logging is best-effort: a read-only filesystem, a directory owned by
    # another user, or a full disk must not stop the server from starting, so
    # the handler falls back to stderr instead of raising through the import.
    abs_log_file = _resolved_log_file()
    has_file = any(
        isinstance(h, RotatingFileHandler) and getattr(h, "baseFilename", "") == abs_log_file
        for h in root_logger.handlers
    )
    file_error: Optional[OSError] = None
    if not has_file:
        try:
            os.makedirs(os.path.dirname(abs_log_file), exist_ok=True)
            fh = _PrivateRotatingFileHandler(
                abs_log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
            )
        except OSError as error:
            file_error = error
        else:
            fh.setLevel(level)
            fh.setFormatter(formatter)
            root_logger.addHandler(fh)
            _LOG_DESTINATION = abs_log_file
    elif not file_error:
        _LOG_DESTINATION = abs_log_file

    # Console handler. Off by default so it can never interleave with the MCP
    # protocol on stdout; note StreamHandler writes to stderr, so enabling it is
    # safe for stdio transport too. Forced on when file logging was unavailable,
    # since otherwise the server would run with no diagnostics at all.
    console_requested = os.getenv("ORACLE_MCP_LOG_TO_STDOUT", "0").lower() in (
        "1",
        "true",
        "yes",
        "y",
    )
    if console_requested or file_error is not None:
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

    if file_error is not None:
        _LOG_DESTINATION = "stderr"
        logging.getLogger(__name__).warning(
            "File logging is disabled: %s is not writable (%s). Logging to stderr instead; "
            "set ORACLE_MCP_LOG_DIR or ORACLE_MCP_STATE_DIR to a writable path.",
            abs_log_file,
            file_error,
        )


setup_logging()
_PROMPTS_DIR = Path(__file__).parent / "data" / "prompts"

OCI_RECOVERY_SERVICE_DASHBOARD_PROMPT = (
    _PROMPTS_DIR / "oci_recovery_service_dashboard.txt"
).read_text(encoding="utf-8")
ONBOARD_DATABASE_TO_RECOVERY_SERVICE_PROMPT = (
    _PROMPTS_DIR / "onboard_database_to_recovery_service.txt"
).read_text(encoding="utf-8")
DIAGNOSE_RECOVERY_SERVICE_ISSUE_PROMPT = (
    _PROMPTS_DIR / "diagnose_recovery_service_issue.txt"
).read_text(encoding="utf-8")

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
    """Cap a string at ORACLE_MCP_LOG_MAX_VALUE_CHARS, noting the original length."""
    if _LOG_MAX_VALUE_CHARS and len(s) > _LOG_MAX_VALUE_CHARS:
        return s[:_LOG_MAX_VALUE_CHARS] + f"...(truncated,len={len(s)})"
    return s


def _payload_summary(obj: Any) -> dict[str, Any]:
    """Describe a result without reproducing it.

    Logged at INFO in place of the payload itself: a tool result is a tenancy's
    resource inventory, and writing it to disk on every call is both a lot of
    volume and a lot of customer data at rest. The full value is still logged at
    DEBUG, which is what a support engineer turns on deliberately.
    """
    if obj is None:
        return {"type": "none"}
    if isinstance(obj, (list, tuple, set)):
        return {"type": "list", "count": len(obj)}
    if isinstance(obj, dict):
        return {"type": "dict", "keys": sorted(str(k) for k in obj)[:20]}
    if isinstance(obj, (bool, int, float, str)):
        return {"type": type(obj).__name__}
    return {"type": type(obj).__name__}


def _log_full_payloads() -> bool:
    """Whether DEBUG logging is on, and full payloads should be written out."""
    return logger.isEnabledFor(logging.DEBUG)


def _safe_jsonable(obj: Any) -> Any:
    """
    Convert an arbitrary value into something ``json.dumps`` can render.

    Walks containers recursively, redacting any key whose name matches
    _LOG_REDACT_KEYS, and unwraps OCI SDK models and pydantic models to plain
    dicts. Every conversion is best effort: a value that resists all of them
    degrades to a truncated ``repr``, and a value that raises becomes
    ``"<unserializable>"``, because logging must never fail a tool call.
    """
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
    """
    Emit one structured log record as a single line of JSON.

    ``request_id`` correlates the record with the other events of the same tool
    call and with the ``opc-request-id`` sent to OCI. ``payload`` is passed through
    _safe_jsonable, so callers may hand it SDK objects directly. Falls back to a
    plain ``str`` rendering if the record will not serialize.
    """
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


_MCP_OPC_REQUEST_ID_PREFIX = "rcvmcp"
_MCP_INSTALLATION_ID_ENV = "ORACLE_MCP_INSTALLATION_ID"
_MCP_INSTALLATION_ID_FILE_ENV = "ORACLE_MCP_INSTALLATION_ID_FILE"
_MCP_INSTALLATION_ID_LENGTH = 8
_MCP_ACTOR_ID_LENGTH = 6
_MCP_REQUEST_ID_LENGTH = 6
_MCP_ACTOR_ID_CONTEXT: ContextVar[str] = ContextVar("mcp_actor_id", default="unknown")
_MCP_TOOL_ID_CONTEXT: ContextVar[str] = ContextVar("mcp_tool_id", default="unknown")
# Used only when a request is made outside an active FastMCP session. It is not
# persisted, so it cannot identify a person across server restarts.
_MCP_SERVER_INSTANCE_ID = uuid.uuid4().hex
_MCP_TOOL_CODES = {
    "list_protected_databases": "lpd",
    "get_protected_database": "gpd",
    "summarize_protected_database_health": "pdh",
    "summarize_protected_database_redo_status": "pdr",
    "summarize_backup_space_used": "bsu",
    "check_recovery_service_limits": "rsl",
    "fetch_regions_subscribed": "frs",
    "list_protection_policies": "lpp",
    "get_protection_policy": "gpp",
    "list_recovery_service_subnets": "lrs",
    "get_recovery_service_subnet": "grs",
    "get_recovery_service_metrics": "rmt",
    "list_databases": "ldb",
    "get_database": "gdb",
    "list_restore": "lwr",
    "list_backups": "lbk",
    "get_backup": "gbk",
    "summarize_protected_database_backup_destination": "pbd",
    "list_db_homes": "ldh",
    "get_db_home": "gdh",
    "list_db_systems": "lds",
    "get_db_system": "gds",
}


def _marker_fragment(value: str, length: int) -> str:
    """Return a fixed-width, lowercase base-36 pseudonym for an internal value."""
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
    number = int.from_bytes(hashlib.sha256(value.encode()).digest(), "big")
    chars: list[str] = []
    for _ in range(length):
        number, remainder = divmod(number, len(alphabet))
        chars.append(alphabet[remainder])
    return "".join(reversed(chars))


def _installation_id_file() -> Path:
    """Return the per-installation ID file, overridable for managed deployments."""
    configured = (os.getenv(_MCP_INSTALLATION_ID_FILE_ENV) or "").strip()
    if configured:
        return Path(configured).expanduser()
    return _state_dir() / "installation-id"


def _mcp_installation_id() -> str:
    """Return a durable opaque ID for this local install or hosted deployment."""
    configured = (os.getenv(_MCP_INSTALLATION_ID_ENV) or "").strip()
    if configured:
        return _marker_fragment(configured, _MCP_INSTALLATION_ID_LENGTH)

    id_file = _installation_id_file()
    try:
        persisted = id_file.read_text(encoding="utf-8").strip()
    except OSError:
        persisted = ""
    if persisted:
        return _marker_fragment(persisted, _MCP_INSTALLATION_ID_LENGTH)

    generated = uuid.uuid4().hex
    try:
        id_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(id_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            output.write(f"{generated}\n")
    except FileExistsError:
        try:
            generated = id_file.read_text(encoding="utf-8").strip() or generated
        except OSError:
            pass
    except OSError:
        # An unwritable home/state directory must not stop a tool call. This
        # fallback remains stable for the current server process only.
        generated = _MCP_SERVER_INSTANCE_ID
    return _marker_fragment(generated, _MCP_INSTALLATION_ID_LENGTH)


def _mcp_actor_id() -> str:
    """Return a privacy-safe opaque identifier for the active MCP user/session."""
    principal = None
    scope = None
    access_token = _current_access_token()
    if access_token is not None:
        claims = getattr(access_token, "claims", None) or {}
        # Some OAuth providers omit sub from the access token. The token jti
        # still provides an opaque, authenticated session identifier.
        principal = claims.get("sub") or claims.get("jti")
        # The issuer identifies the IAM domain this deployment authenticates
        # against, which scopes the pseudonym without naming the user.
        scope = claims.get("iss")

    if not principal:
        # For session/API-key deployments, OCI credentials identify the server
        # account, not the MCP caller. Prefer FastMCP's per-client session so
        # users sharing one configured server remain distinguishable.
        try:
            from fastmcp.server.dependencies import get_context

            principal = get_context().session_id
            scope = scope or "mcp-session"
        except Exception:
            principal = None

    if not principal:
        # Direct SDK use can occur outside a FastMCP request context. Retain a
        # stable server-account pseudonym when a local OCI config is available.
        try:
            config = _load_oci_config_for_server()
            principal = config.get("user")
            scope = scope or config.get("tenancy")
        except Exception:
            principal = _MCP_SERVER_INSTANCE_ID
            scope = "mcp-server"
    return _marker_fragment(f"{scope or ''}:{principal}", _MCP_ACTOR_ID_LENGTH)


def _mcp_opc_request_id(value: Optional[str]) -> str:
    """Return a 32-character OCI request ID with MCP telemetry markers.

    OCI services preserve only the first 32 characters before appending their
    own request-id segments. Keep all telemetry fields inside that prefix.
    """
    request_id = str(value or uuid.uuid4().hex)
    if re.fullmatch(r"rcvmcp-[0-9a-z]{8}-[0-9a-z]{6}-[0-9a-z]{3}[0-9a-z]{6}", request_id):
        return request_id
    installation_id = _mcp_installation_id()
    actor_id = _MCP_ACTOR_ID_CONTEXT.get()[:_MCP_ACTOR_ID_LENGTH].ljust(_MCP_ACTOR_ID_LENGTH, "0")
    tool_code = _MCP_TOOL_CODES.get(_MCP_TOOL_ID_CONTEXT.get(), "unk")
    request_code = _marker_fragment(request_id, _MCP_REQUEST_ID_LENGTH)
    return f"{_MCP_OPC_REQUEST_ID_PREFIX}-{installation_id}-{actor_id}-{tool_code}{request_code}"


def _operation_supports_opc_request_id(operation: Callable[..., Any]) -> bool:
    """Return whether an OCI SDK operation accepts ``opc_request_id``."""
    try:
        return '"opc_request_id"' in inspect.getsource(operation)
    except (OSError, TypeError):
        return False


def _install_opc_request_id_fallback(client: Any, request_id: str) -> None:
    """Mark generated OCI SDK calls that do not expose an ``opc_request_id`` kwarg."""
    base_client = getattr(client, "base_client", None)
    call_api = getattr(base_client, "call_api", None)
    if base_client is None or not callable(call_api):
        return

    marker = _mcp_opc_request_id(request_id)

    def _call_api(*args, **kwargs):
        """Stand in for ``BaseClient.call_api`` and stamp the request-id header."""
        # Generated OCI operations pass header_params to BaseClient.call_api. Adding
        # the header here avoids unsupported operation kwargs and does not enable
        # the SDK's process-wide request-id propagation state.
        call_kwargs = dict(kwargs)
        headers = dict(call_kwargs.get("header_params") or {})
        headers["opc-request-id"] = _mcp_opc_request_id(headers.get("opc-request-id") or marker)
        call_kwargs["header_params"] = headers
        return call_api(*args, **call_kwargs)

    base_client.call_api = _call_api


def _wrap_oci_client(client: Any, *, request_id: str, client_name: str):
    """Proxy that marks and logs every OCI SDK method call and response summary."""
    _install_opc_request_id_fallback(client, request_id)

    class _Proxy:
        """Attribute-forwarding wrapper around one OCI SDK client."""

        def __init__(self, inner: Any):
            """Wrap ``inner`` and start an empty per-method opc_request_id support cache."""
            self._inner = inner
            self._opc_request_id_support: dict[str, bool] = {}

        def __getattr__(self, name: str):
            """
            Return non-callables untouched; wrap SDK operations in a logging shim.

            Whether an operation accepts an ``opc_request_id`` kwarg is decided by reading
            its source, which is expensive, so the answer is cached per method name.
            """
            attr = getattr(self._inner, name)
            if not callable(attr):
                return attr
            if name not in self._opc_request_id_support:
                self._opc_request_id_support[name] = _operation_supports_opc_request_id(
                    getattr(attr, "__func__", attr)
                )
            supports_opc_request_id = self._opc_request_id_support[name]

            def _call(*args, **kwargs):
                """
                Invoke the SDK operation, logging start, end and error events.

                Response metadata (status, headers, paging) is logged at INFO; the response
                body follows the same rule as tool results -- its shape at INFO, its content
                only at DEBUG. Exceptions are logged with a traceback and re-raised.
                """
                kwargs = dict(kwargs)
                if supports_opc_request_id:
                    kwargs["opc_request_id"] = _mcp_opc_request_id(kwargs.get("opc_request_id") or request_id)
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
                    # Response bodies carry the same customer data as tool results,
                    # so they follow the same rule: shape at INFO, body at DEBUG.
                    try:
                        data = getattr(resp, "data", resp)
                        payload["data_summary"] = _payload_summary(data)
                        if _log_full_payloads():
                            payload["data"] = _safe_jsonable(data)
                    except Exception:
                        payload["data_summary"] = {"type": "unavailable"}
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
        """Wrap one tool function, preserving its signature for FastMCP."""

        @wraps(fn)
        def _wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
            """Log the call's start, end and any error, then return the tool's result."""
            request_id = uuid.uuid4().hex
            start = time.time()
            actor_id_token = _MCP_ACTOR_ID_CONTEXT.set(_mcp_actor_id())
            tool_id_token = _MCP_TOOL_ID_CONTEXT.set(tool_name)
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
                end_payload: dict[str, Any] = {
                    "duration_ms": dur_ms,
                    "result_summary": _payload_summary(out),
                }
                if _log_full_payloads():
                    end_payload["result"] = _safe_jsonable(out)
                _log_event(
                    "tool_call",
                    request_id=request_id,
                    tool=tool_name,
                    phase="end",
                    payload=end_payload,
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
            finally:
                _MCP_TOOL_ID_CONTEXT.reset(tool_id_token)
                _MCP_ACTOR_ID_CONTEXT.reset(actor_id_token)

        return _wrapped

    return _decorator


# Auth/Config

_USER_AGENT_NAME = __project__.split("oracle.", 1)[1].split("-server", 1)[0]
_ADDITIONAL_UA = f"{_USER_AGENT_NAME}/{__version__}"


# Auth-type variables the shared library reads ahead of ORACLE_MCP_AUTH_METHOD, in
# its own order of precedence. Anything set here already decides the auth type, so
# the deprecated spelling below must not be translated.
_CANONICAL_AUTH_TYPE_ENV = ("OCI_MCP_AUTH_TYPE", "OCI_IOT_AUTH_TYPE", "OCI_AUTH_TYPE")


def _deprecated_auth_method_override() -> Optional[AuthType]:
    """Translate the one 2.x ORACLE_MCP_AUTH_METHOD spelling the shared library rejects.

    oracle-mcp-common already reads ORACLE_MCP_AUTH_METHOD itself and maps
    "session"/"api_key"/"api-key" onto its own auth types, so this server does not
    need to interpret them. Its normalizer does not recognize the unseparated
    "apikey" spelling that this server's 2.x README documented, though, and an
    unrecognized value is a hard error -- so translate only that case.

    The translation is passed to build_auth_context() as an explicit AuthOptions
    value, which outranks every environment variable in resolve_auth_type(). So it
    is applied only when no canonical OCI_* auth-type variable is set: otherwise the
    deprecated name would silently beat OCI_MCP_AUTH_TYPE, the opposite of what this
    server documents, and OCI_MCP_AUTH_TYPE=security_token would authenticate with
    the profile's API key -- either failing to build a signer at all, or building one
    from the ephemeral session key that OCI then rejects with 401 on every request.

    Everything else is left to resolve_auth_type(), including an unset value, which
    selects "auto": session-token when the profile directly declares a
    security_token_file, otherwise API-key. Forcing a type here instead would break
    that detection -- an API-key-only profile would be rejected for having no
    security_token_file.
    """
    if any((os.getenv(name) or "").strip() for name in _CANONICAL_AUTH_TYPE_ENV):
        return None
    raw = (os.getenv("ORACLE_MCP_AUTH_METHOD") or "").strip().lower()
    if raw == "apikey":
        return AuthType.API_KEY
    return None


def _resolved_auth_type_label() -> str:
    """The auth type the shared library will use, for the startup log line only."""
    try:
        override = _deprecated_auth_method_override()
        return (override or resolve_auth_type()).value
    except Exception:
        return "unresolved"


def _first_env(*names: str, default: Optional[str] = None) -> Optional[str]:
    """Return the first non-empty environment variable among names."""
    for n in names:
        v = (os.getenv(n) or "").strip()
        if v:
            return v
    return default


def _load_oci_config_for_server() -> dict:
    """Read the selected profile's raw OCI config (for informational lookups only,
    e.g. actor-id logging and tenancy discovery). Client construction uses
    oracle_mcp_common.build_auth_context() instead; see _build_profile_auth_context().

    The config file is resolved through oracle_mcp_common.resolve_config_file() so
    these lookups read the same file the credentials came from. The OCI SDK only
    consults OCI_CONFIG_FILE when ~/.oci/config is absent, so reading the file
    directly would resolve the tenancy and region from a different profile than
    the signer whenever both exist.
    """
    config = oci.config.from_file(
        file_location=resolve_config_file(),
        profile_name=resolve_profile_name(),
    )
    config["additional_user_agent"] = _ADDITIONAL_UA
    return config


def _build_profile_auth_context():
    """Resolve stdio OCI credentials through the shared oracle-mcp-common library.

    The library owns auth-type and profile resolution, including this server's
    ORACLE_MCP_AUTH_METHOD/ORACLE_MCP_AUTH_PROFILE variables, so nothing is passed
    unless the deprecated "apikey" spelling needs translating (see
    _deprecated_auth_method_override).
    """
    override = _deprecated_auth_method_override()
    if override is not None:
        return build_auth_context(AuthOptions(auth_type=override))
    return build_auth_context()


# ---------------- HTTP transport auth (OCI IAM / IDCS) ----------------
#
# Transport decides the credential path, exactly as in the other OCI MCP servers:
#
#   * stdio  -- the operator's own OCI credentials, resolved by
#               oracle_mcp_common.build_auth_context() from the selected profile.
#   * HTTP   -- each caller signs in to an OCI IAM (IDCS) domain, and that caller's
#               access token is exchanged for caller-specific OCI credentials by
#               oracle_mcp_common.IDCSHttpAuth.context_for().
#
# The policy (provider + the confidential application's credentials) is built once
# in main() when ORACLE_MCP_HOST/ORACLE_MCP_PORT select the HTTP listener. A fresh
# signer is built for every tool call: it carries the caller's own IAM domain JWT,
# so nothing is cached process-wide outside the request that established it.

_OAUTH_SCOPE_SUFFIX = __project__.removeprefix("oracle.oci-").removesuffix("-mcp-server").replace("-", "_")
_DEFAULT_REQUIRED_SCOPES = f"openid profile email oci_mcp.{_OAUTH_SCOPE_SUFFIX}.invoke".split()

# Scopes IDCS defines itself, which are never namespaced by a resource application.
# Everything else in IDCS_REQUIRED_SCOPES belongs to this server's resource
# application and must be qualified with that application's primary audience.
_IDCS_RESERVED_SCOPES = frozenset(
    {"openid", "profile", "email", "address", "phone", "groups", "offline_access"}
)

_http_auth: Optional[IDCSHttpAuth] = None


def _required_scopes() -> list[str]:
    """The scopes required of every authenticated caller over HTTP."""
    return parse_scopes(os.getenv("IDCS_REQUIRED_SCOPES")) or list(_DEFAULT_REQUIRED_SCOPES)


def _qualify(audience: str, scopes: list[str]) -> list[str]:
    """Name each resource scope the way IDCS does: audience + scope, no separator."""
    return [
        s if (s in _IDCS_RESERVED_SCOPES or "://" in s) else f"{audience}{s}"
        for s in scopes
    ]


def _qualify_upstream_scopes(provider, *, audience: str, scopes: list[str]) -> list[str]:
    """Request resource scopes from IDCS in the fully-qualified form it requires.

    IDCS names a resource application's scopes by concatenating the application's
    primary audience with the scope, without a separator. `/authorize` only
    recognizes that form, so a bare `oci_mcp.recovery.invoke` is rejected with
    `invalid_scope` and sign-in never completes.

    The access token IDCS issues, however, carries the scope *bare* in its `scope`
    claim, with the audience in `aud`. That token is what gets re-validated on every
    request (OAuthProxy.load_access_token swaps the FastMCP JWT for it), and the
    scope check requires the configured scopes to be a subset of that claim. So the
    same setting is needed in two incompatible forms: qualified going out, bare
    coming back. Configuring either one alone breaks the other half of the flow.

    The split is therefore by direction, not by object: every surface that *reaches
    IDCS* carries the qualified form, and every surface that is *compared against an
    issued token* stays bare. Reserved OIDC scopes and anything already absolute are
    left alone.

    Qualified, because IDCS reads them:

      * `update_default_scopes` covers DCR registration defaults, `valid_scopes`,
        and the metadata clients read to decide what to request.
      * `_build_upstream_authorize_url` builds the actual `/authorize` request. It
        uses the scopes the client sent, falling back to the proxy's
        `required_scopes` when the client sends no `scope` parameter at all -- which
        clients do, and which no amount of correct advertising prevents. Wrapping
        the method qualifies both sources at the one point they converge.
      * `_prepare_scopes_for_upstream_refresh` builds the refresh request from the
        scopes stored on the refresh token, and those were parsed from the IDCS
        token response -- so they are bare. Left alone, sign-in succeeds and then
        the session dies at the first refresh, an hour later, with the same
        `invalid_scope` far from any change that would explain it.

    Bare, because they are matched against the token IDCS issued:

      * `token_verifier.required_scopes`, which the verifier compares to the token's
        `scope` claim.
      * `provider.required_scopes`, which FastMCP hands to `RequireAuthMiddleware`
        when it builds the transport routes (fastmcp/server/http.py). That check
        compares against the same bare claim, so qualifying this field would return
        `insufficient_scope` on every request of an otherwise valid session. It is
        left untouched for that reason -- the authorize fallback that also reads it
        is handled in the wrapper above instead.

    FastMCP's own AzureProvider solves the same audience-qualification problem the
    same way, which is why these are the hooks that exist to override.
    """
    for attr in (
        "update_default_scopes",
        "required_scopes",
        "_build_upstream_authorize_url",
        "_prepare_scopes_for_upstream_refresh",
    ):
        if not hasattr(provider, attr):
            raise RuntimeError(
                f"This FastMCP release does not expose '{attr}', so the resource scopes "
                "cannot be qualified with the IAM resource application's audience and "
                "IDCS would reject sign-in with 'invalid_scope'."
            )

    qualified = _qualify(audience, scopes)
    provider.update_default_scopes(qualified)

    build_authorize_url = provider._build_upstream_authorize_url

    def _qualified_authorize_url(
        txn_id,
        transaction,
        _build=build_authorize_url,
        _aud=audience,
        _fallback=list(provider.required_scopes) or list(scopes),
    ):
        """Qualify the scopes of an /authorize request, whatever their source."""
        requested = list(transaction.get("scopes") or []) or list(_fallback)
        return _build(txn_id, {**transaction, "scopes": _qualify(_aud, requested)})

    provider._build_upstream_authorize_url = _qualified_authorize_url
    # Falls back to the configured scopes when a refresh token carries none,
    # mirroring what the authorize path does with an empty transaction.
    provider._prepare_scopes_for_upstream_refresh = (
        lambda stored, _aud=audience, _default=qualified: _qualify(
            _aud, list(stored) or list(_default)
        )
    )
    return qualified


def _disable_cimd(provider) -> None:
    """Turn off CIMD client registration on the OAuth provider.

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
    `client_id_metadata_document_supported` in the authorization-server metadata,
    so clients register with DCR against `/register` instead -- an exchange that
    never leaves this host and works on every deployment.

    `_cimd_manager` is private FastMCP API and there is no public alternative:
    OCIProvider does not forward `enable_cimd` to the underlying proxy. The
    attribute is therefore checked rather than assumed, so an upstream rename
    fails at startup instead of silently restoring the outbound fetch.
    """
    if not hasattr(provider, "_cimd_manager"):
        raise RuntimeError(
            "This FastMCP release does not expose '_cimd_manager', so CIMD client "
            "registration cannot be disabled and client registration would depend on "
            "this host being able to fetch the client's metadata URL. Check whether "
            "OCIProvider now accepts enable_cimd=False and use that instead."
        )
    provider._cimd_manager = None


def _build_http_auth() -> IDCSHttpAuth:
    """Build the HTTP IDCS policy and apply the two settings the shared builder omits."""
    scopes = _required_scopes()
    auth = build_idcs_http_auth(scopes)
    audience = os.getenv("IDCS_AUDIENCE") or ""
    _qualify_upstream_scopes(auth.provider, audience=audience, scopes=scopes)
    _disable_cimd(auth.provider)
    return auth


def _current_access_token():
    """The authenticated caller's IDCS token, or None outside an HTTP request."""
    try:
        return get_access_token()
    except Exception:
        return None


def _serving_http() -> bool:
    """Whether this call arrived over the authenticated HTTP transport."""
    if _current_access_token() is not None:
        return True
    try:
        get_http_request()
    except RuntimeError:
        return False
    return True


def _http_config_and_signer(region: str | None = None):
    """Resolve request-scoped OCI credentials for the current caller.

    The IAM domain JWT is taken from the active request's access token and passed
    to IDCSHttpAuth.context_for(), which returns a signer built for this request
    only: it is never stored outside the request that established the caller's
    identity, so a signer built for one caller can never be reused for another.
    """
    if _http_auth is None:
        raise RuntimeError(
            "HTTP authentication policy has not been initialized. Start the server "
            "through main() with ORACLE_MCP_HOST/ORACLE_MCP_PORT set."
        )
    access_token = _current_access_token()
    try:
        request_auth = _http_auth.context_for(
            access_token.token if access_token else None, region=region
        )
    except Exception as e:
        # Surface the IAM domain's actual error body instead of a bare
        # "401 Unauthorized". A 401/403 here almost always means the OCI side is
        # not set up to exchange the user JWT for a UPST yet: a missing or
        # misconfigured Identity Propagation Trust, the confidential app missing
        # the token-exchange/client-credentials grant, or wrong client credentials.
        # The IAM error body is a diagnostic description and contains no secrets.
        # context_for() wraps SDK failures in ValueError, so the IAM response hangs
        # off the wrapped cause.
        resp = getattr(e, "response", None) or getattr(getattr(e, "__cause__", None), "response", None)
        detail = ""
        if resp is not None:
            try:
                detail = f" | IAM {resp.status_code}: {resp.text}"
            except Exception:
                pass
        logger.error("OCI UPST token exchange failed%s", detail, exc_info=True)
        raise RuntimeError(
            "OCI UPST token exchange failed. The OCI IAM domain rejected the request to "
            "exchange the user's token for a UPST. Verify, in this deployment's IAM domain: "
            "(1) an Identity Propagation Trust exists that lists this client_id; (2) the "
            "confidential app has the Authorization Code and Client Credentials grants; "
            "(3) IDCS_CLIENT_ID/IDCS_CLIENT_SECRET are correct." + detail
        ) from e
    config = {**request_auth.config, "additional_user_agent": _ADDITIONAL_UA}
    return config, request_auth.signer


def _config_and_signer(region: str | None = None):
    """Resolve OCI SDK configuration and a signer for the current call."""
    if _serving_http():
        return _http_config_and_signer(region)
    if _http_auth is not None:
        # main() built an HTTP authentication policy, so this process serves
        # network callers and has no business signing anything with the
        # operator's own credentials. Reaching here means the per-request
        # detection above failed to see a request it should have seen; refusing
        # is the only safe outcome, since the alternative is performing one
        # caller's request under a different, probably broader, identity.
        raise RuntimeError(
            "Refusing to use local profile credentials on an HTTP deployment: this call "
            "arrived outside an authenticated request context, so there is no caller "
            "identity to act as."
        )
    auth_context = _build_profile_auth_context()
    config = {**auth_context.config, "additional_user_agent": _ADDITIONAL_UA}
    if region is not None:
        config["region"] = region
    return config, auth_context.signer


def _effective_region(default: Optional[str] = None) -> Optional[str]:
    """
    Resolve the OCI region without requiring a local config file.

    Over HTTP there is no OCI config file to read, so OCI_REGION supplies the
    default region; over stdio it is the configured profile's region.
    """
    if _serving_http():
        return _first_env("OCI_REGION", "ORACLE_MCP_REGION", default=default)
    try:
        return _load_oci_config_for_server().get("region") or default
    except Exception:
        return _first_env("OCI_REGION", "ORACLE_MCP_REGION", default=default)


def _make_client(
    ctor: Callable[..., Any],
    region: str | None = None,
    *,
    client_name: str,
    request_id: Optional[str] = None,
):
    """Construct and wrap an OCI SDK client for the current call's credentials."""
    config, signer = _config_and_signer(region)
    client = ctor(config, signer=signer)
    rid = request_id or uuid.uuid4().hex
    return _wrap_oci_client(client, request_id=rid, client_name=client_name)


# Every tool here reads; none creates, updates or deletes an OCI resource. These
# hints tell an MCP host that much without a human reading the README, so a host
# can skip a confirmation prompt it would otherwise raise on an unknown tool.
_READ_ONLY_TOOL = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    # Results come from OCI, not from a closed set the server owns.
    "openWorldHint": True,
}

# The guidance tools return static text and never reach the network.
_LOCAL_GUIDANCE_TOOL = {**_READ_ONLY_TOOL, "openWorldHint": False}

# Create the FastMCP app that exposes the functions decorated with @mcp.tool.
# main() attaches the OCI IAM OAuth provider when it selects the HTTP transport.
mcp = FastMCP(name=__project__)


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
    """
    Create an OCI Identity client using auth selected via env vars.

    Always built for the home region: IAM compartments and region subscriptions
    are tenancy-wide, so there is no region to pass.
    """
    return _make_client(
        oci.identity.IdentityClient,
        None,
        client_name="identity",
        request_id=request_id,
    )


def get_database_client(region: str | None = None, *, request_id: Optional[str] = None):
    """Create an OCI Database client using auth selected via env vars."""
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
    """Create an OCI Monitoring client using auth selected via env vars."""
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

    Every in-process cache is partitioned by tenant so a cached result can never
    outlive the tenancy it was computed for -- including across a configuration
    change that repoints the server at a different tenancy. get_tenancy() returns
    the configured tenancy OCID over HTTP, or the local config's over stdio.
    """
    try:
        return get_tenancy() or "_default"
    except Exception:
        return "_default"


def _caller_cache_key() -> str:
    """
    Stable per-caller key for caches whose contents depend on the caller's own
    OCI permissions, appended to the tenant key.

    Tenant partitioning alone is not enough for those: over HTTP every caller has
    their own IAM permissions, so a result computed with one caller's
    authorizations (anything fetched with access_level="ACCESSIBLE") must never be
    served to another. Over stdio there is exactly one set of credentials for the
    whole process, so there is nothing to separate and this contributes nothing to
    the key.

    The subject claim identifies the human, not the session, so the cache still
    survives a token refresh. When the provider omits it we fall back to
    per-session values (jti, then the raw token), which costs a refetch after a
    refresh but never merges two callers. The key is hashed because it is cheap
    to end up in a log line or a debug dump.
    """
    if not _serving_http():
        return ""
    try:
        access = _current_access_token()
        claims = (getattr(access, "claims", None) or {}) if access is not None else {}
        # Only ever caller-specific values here. client_id identifies the
        # registered OAuth application, which many humans share, so it must
        # never appear in this chain. Some providers omit sub; jti and the raw
        # token are both per-session, so the entry is scoped to this session.
        subject = claims.get("sub") or claims.get("jti") or getattr(access, "token", None)
    except Exception:
        subject = None
    if not subject:
        # No request context at all (e.g. startup): don't touch a shared entry.
        return f"anon:{uuid.uuid4().hex}"
    return "sub:" + hashlib.sha256(str(subject).encode()).hexdigest()[:16]


_TOOL_DEADLINE_SECONDS = float(os.getenv("ORACLE_MCP_TOOL_DEADLINE_SECONDS", "120"))


class _Deadline:
    """A cooperative monotonic-time budget for a fan-out the caller cannot see.

    The summary tools issue one request per protected database across every
    compartment in scope, so a large tenancy turns a single tool call into
    hundreds of sequential round trips -- long past the point where an MCP client
    has given up waiting. Stopping at a deadline and saying so is more useful
    than a request that never returns. Set ORACLE_MCP_TOOL_DEADLINE_SECONDS to 0
    to scan without a limit. An OCI request already in flight is allowed to
    finish; callers check the budget between requests.
    """

    def __init__(self, seconds: Optional[float] = None):
        """
        Start the budget, defaulting to ORACLE_MCP_TOOL_DEADLINE_SECONDS.

        A budget of 0 (or None resolving to 0) means no deadline at all.
        """
        budget = _TOOL_DEADLINE_SECONDS if seconds is None else seconds
        self._expires_at = (time.monotonic() + budget) if budget and budget > 0 else None
        self.expired = False

    def reached(self) -> bool:
        """Report whether the budget is spent, latching ``expired`` once it is."""
        if self._expires_at is not None and time.monotonic() >= self._expires_at:
            self.expired = True
        return self.expired


_CACHE_MAX_ENTRIES = int(os.getenv("ORACLE_MCP_CACHE_MAX_ENTRIES", "256"))


def _cache_get(entries: dict[str, Any], key: str, *, ttl: float, now: float) -> Optional[Any]:
    """Return a live cache entry, refreshing its recency, or None.

    Reinserting on a hit makes the dict's insertion order a true LRU order, which
    is what _cache_put evicts from.
    """
    cached = entries.get(key)
    if not cached:
        return None
    if now - float(cached.get("fetched_at") or 0.0) >= ttl:
        entries.pop(key, None)
        return None
    entries[key] = entries.pop(key)
    return cached


def _cache_put(entries: dict[str, Any], key: str, value: Any, *, ttl: float, now: float) -> None:
    """Store a cache entry, sweeping expired ones and bounding the total.

    These caches are partitioned per tenant and per caller, so on the hosted HTTP
    transport they gain an entry for every person who signs in and each one holds
    that caller's whole compartment listing. Without a bound the process grows
    with the user count for the life of the deployment.
    """
    for expired in [
        k for k, v in entries.items() if now - float(v.get("fetched_at") or 0.0) >= ttl
    ]:
        entries.pop(expired, None)
    entries.pop(key, None)
    entries[key] = value
    while len(entries) > _CACHE_MAX_ENTRIES:
        entries.pop(next(iter(entries)))


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
    cached = _cache_get(items, cache_key, ttl=ttl, now=now)
    if cached:
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
    _cache_put(items, cache_key, {"regions": out, "fetched_at": now}, ttl=ttl, now=now)
    return out


def get_tenancy():
    """
    Return the OCID of the tenancy this server serves.

    Under HTTP transport the env override is the only source, since a hosted
    deployment has no local OCI config file to read a tenancy from.
    """
    # An explicit override always wins. Over HTTP it is the only source: there is
    # no local OCI config file on a hosted deployment to read a tenancy from.
    override = _first_env("TENANCY_ID_OVERRIDE", "ORACLE_MCP_TENANCY_ID")
    if override:
        return override
    if _serving_http():
        raise RuntimeError(
            "HTTP deployments must set ORACLE_MCP_TENANCY_ID (or TENANCY_ID_OVERRIDE) "
            "to the OCID of the tenancy this server serves; there is no local OCI "
            "config file to read it from."
        )
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
    # entries: dict["<tenant_key>|<caller_key>" -> {"items": list[Any], "fetched_at": float}]
    "entries": {},
}


def _list_all_compartments_cached(*, request_id: Optional[str] = None) -> list[Any]:
    """
    Return all accessible ACTIVE compartments in the tenancy (plus root tenancy)
    with a small in-process TTL cache to avoid repeated Identity scans.

    The cache is keyed by tenant AND caller: the listing is fetched with
    access_level="ACCESSIBLE", so it contains exactly the compartments the calling
    identity may see. Keying it by tenant alone would let one user's compartment
    tree be served to a differently-authorized user in the same tenancy.

    NOTE:
    - OCI CLI `oci iam compartment list --compartment-id <root>` returns ONLY direct children.
    - For our use-case (expand subtree), we list the full subtree using:
        list_compartments(compartment_id_in_subtree=True, access_level="ACCESSIBLE")
      and then build a parent->children index locally to BFS the descendants.
    """
    now = time.time()
    ttl = float(_COMPARTMENT_CACHE.get("ttl_seconds") or 300)
    entries = _COMPARTMENT_CACHE.setdefault("entries", {})
    cache_key = f"{_tenant_cache_key()}|{_caller_cache_key()}"
    cached = _cache_get(entries, cache_key, ttl=ttl, now=now)

    if cached and cached.get("items"):
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

    _cache_put(entries, cache_key, {"items": comps, "fetched_at": now}, ttl=ttl, now=now)
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
    """Report whether a value is shaped like an OCID rather than a display name."""
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
    annotations=_READ_ONLY_TOOL,
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
                                    """Read one key from a metrics dict that may be missing entirely."""
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
    annotations=_READ_ONLY_TOOL,
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
            """Read one key from a metrics dict that may be missing entirely."""
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
    annotations=_READ_ONLY_TOOL,
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
) -> ProtectedDatabaseHealthSummary:
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
        deadline = _Deadline()
        scanned_compartments: list[str] = []

        has_next_page = True
        next_page: Optional[str] = None

        for each_comp in comp_ids:
            if deadline.reached():
                break
            scanned_compartments.append(each_comp)
            c_protected = 0
            c_warning = 0
            c_alert = 0
            c_unknown = 0
            c_scanned = 0

            has_next_page = True
            next_page = None

            while has_next_page and not deadline.reached():
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
                    if deadline.reached():
                        break
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
                    # Only the compartment in flight when the budget ran out can be
                    # short, because the outer loop breaks on the next iteration.
                    # Without this, a partial compartment is indistinguishable from
                    # one that genuinely holds that few databases.
                    "partial": deadline.expired,
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
        if deadline.expired:
            logger.warning(
                "Health summary stopped at its %ss deadline after %s of %s compartments; "
                "counts are partial.",
                _TOOL_DEADLINE_SECONDS,
                len(scanned_compartments),
                len(comp_ids),
            )

        return ProtectedDatabaseHealthSummary(
            aggregated=aggregated,
            per_compartment=per_compartment,
            compartmentIdsScanned=scanned_compartments,
            truncated=deadline.expired,
        )
    except Exception as e:
        logger.error(f"Error in summarize_protected_database_health tool: {str(e)}")
        raise


@mcp.tool(
    annotations=_READ_ONLY_TOOL,
    description=(
        "Use this tool for real-time protection status questions. It shows how many "
        "protected databases have redo transport (real-time protection) turned on or "
        "off in a compartment. It reads the main setting and uses a fallback when "
        "needed. The result is a simple JSON with enabled, disabled, unknown (the "
        "databases whose setting could not be read), total (all three, i.e. the "
        "databases in scope), the compartmentId, and the region."
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
) -> ProtectedDatabaseRedoSummary:
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
        unknown = 0
        per_compartment: list[dict] = []
        deadline = _Deadline()
        scanned_compartments: list[str] = []

        has_next_page = True
        next_page: Optional[str] = None

        for each_comp in comp_ids:
            if deadline.reached():
                break
            scanned_compartments.append(each_comp)
            c_enabled = 0
            c_disabled = 0
            c_unknown = 0

            has_next_page = True
            next_page = None

            while has_next_page and not deadline.reached():
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
                    if deadline.reached():
                        break
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
                        unknown += 1
                        c_unknown += 1
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
                        # Unreadable is not the same as disabled. Counting it here
                        # keeps a permissions gap visible instead of reporting a
                        # reassuring total that quietly left databases out.
                        unknown += 1
                        c_unknown += 1

            per_compartment.append(
                {
                    "compartmentId": each_comp,
                    "region": region,
                    "enabled": c_enabled,
                    "disabled": c_disabled,
                    "unknown": c_unknown,
                    # total is "databases in scope", so the unreadable ones are in it
                    # -- the same meaning total carries in the health summary. Leaving
                    # them out made a scan with a permissions gap report a smaller
                    # fleet than the caller actually has.
                    "total": c_enabled + c_disabled + c_unknown,
                    # Only the compartment in flight when the budget ran out can be
                    # short, because the outer loop breaks on the next iteration.
                    "partial": deadline.expired,
                }
            )

        total = enabled + disabled + unknown
        logger.info(
            "Redo transport summary for compartment %s (region=%s): "
            "ENABLED=%s, DISABLED=%s, UNKNOWN=%s, TOTAL=%s",
            comp_id,
            region,
            enabled,
            disabled,
            unknown,
            total,
        )
        # NOTE: construct using the alias key (compartmentId) to avoid any
        # pydantic alias population edge-cases that can result in null output.
        aggregated = ProtectedDatabaseRedoCounts(
            compartmentId=comp_id,
            region=region,
            enabled=enabled,
            disabled=disabled,
            unknown=unknown,
            total=total,
        )
        if deadline.expired:
            logger.warning(
                "Redo transport summary stopped at its %ss deadline after %s of %s "
                "compartments; counts are partial.",
                _TOOL_DEADLINE_SECONDS,
                len(scanned_compartments),
                len(comp_ids),
            )

        return ProtectedDatabaseRedoSummary(
            aggregated=aggregated,
            per_compartment=per_compartment,
            compartmentIdsScanned=scanned_compartments,
            truncated=deadline.expired,
        )
    except Exception as e:
        logger.error(f"Error in summarize_protected_database_redo_status tool: {e}")
        raise


@mcp.tool(
    annotations=_READ_ONLY_TOOL,
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
    annotations=_READ_ONLY_TOOL,
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
            """Best-effort conversion of a Limits SDK object to a plain dict."""
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
    annotations=_READ_ONLY_TOOL,
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
    """
    Lists the tenancy's subscribed regions and each region's subscription status.

    ``tenancy_id`` only labels the result; region subscriptions are tenancy-wide,
    so it does not narrow the lookup. When omitted, the server's own tenancy is
    used.
    """
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
    annotations=_READ_ONLY_TOOL,
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
                    # This SDK call names the filter protection_policy_id and rejects "id"
                    # outright; list_protected_databases and list_recovery_service_subnets do
                    # take "id", which is why only this one is remapped.
                    kwargs["protection_policy_id"] = id
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


@mcp.tool(
    annotations=_READ_ONLY_TOOL,
    description=("Gets a protection policy by OCID and returns it as a simple object."))
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
    annotations=_READ_ONLY_TOOL,
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
    annotations=_READ_ONLY_TOOL,
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


# Fields of the mapped WorkRequest that list_restore can sort by. The OCI-style
# camelCase spelling is what the API's own sort_by accepts, so both it and the
# model's attribute name are recognised.
_RESTORE_SORT_FIELDS = {
    "timeaccepted": "time_accepted",
    "time_accepted": "time_accepted",
    "timestarted": "time_started",
    "time_started": "time_started",
    "timefinished": "time_finished",
    "time_finished": "time_finished",
    "status": "status",
    "operationtype": "operation_type",
    "operation_type": "operation_type",
}
_SORT_ORDERS = ("ASC", "DESC")


def _sorted_work_requests(
    items: list[WorkRequest], sort_by: Optional[str], sort_order: Optional[str]
) -> list[WorkRequest]:
    """Order restore work requests locally.

    The Work Requests API has no sort parameters (see the call site), so sorting
    happens here. Entries missing the sort field sort last in either direction,
    rather than being dropped or raising on a None comparison.
    """
    if sort_by is None and sort_order is None:
        return items

    field = "time_accepted"
    if sort_by is not None:
        key = str(sort_by).strip().lower()
        if key not in _RESTORE_SORT_FIELDS:
            raise ValueError(
                "sort_by must be one of: timeAccepted, timeStarted, timeFinished, "
                f"status, operationType. Received: {sort_by!r}"
            )
        field = _RESTORE_SORT_FIELDS[key]

    order = (sort_order or "DESC").strip().upper()
    if order not in _SORT_ORDERS:
        raise ValueError(f"sort_order must be one of: {', '.join(_SORT_ORDERS)}. Received: {sort_order!r}")

    present = [item for item in items if getattr(item, field, None) is not None]
    missing = [item for item in items if getattr(item, field, None) is None]
    return sorted(
        present,
        key=lambda item: getattr(item, field),
        reverse=(order == "DESC"),
    ) + missing


# Monitoring query vocabulary. The tool builds an MQL expression by
# interpolation, so every part of it that comes from the caller is checked
# against these first: an unvalidated value would let a caller reshape the query
# (and break out of the quoted resourceId filter), and a typo would surface as an
# opaque service-side parse error instead of a usable message.
_METRIC_NAMES = (
    "SpaceUsedForRecoveryWindow",
    "ProtectedDatabaseSize",
    "ProtectedDatabaseHealth",
    "DataLossExposure",
)
_METRIC_RESOLUTIONS = ("1m", "5m", "1h", "1d")
_METRIC_AGGREGATIONS = ("mean", "sum", "max", "min", "count")
_OCID_RE = re.compile(r"^ocid1\.[a-z0-9]+\.[a-z0-9-]+\.[a-z0-9-]*\.[A-Za-z0-9._-]+$")


def _validated_choice(value: str, allowed: tuple[str, ...], field: str) -> str:
    """Return value if it is one of allowed, else raise a message naming them."""
    if value not in allowed:
        raise ValueError(f"{field} must be one of: {', '.join(allowed)}. Received: {value!r}")
    return value


def _validated_ocid(value: str, field: str) -> str:
    """Return value if it is shaped like an OCID, else raise."""
    if not _OCID_RE.match(value or ""):
        raise ValueError(f"{field} must be an OCID (ocid1.<type>.<realm>...). Received: {value!r}")
    return value


@mcp.tool(
    annotations=_READ_ONLY_TOOL,
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
    """
    Queries Monitoring for a Recovery Service metric over a time range.

    Returns one time series per dimension combination, each a list of
    {timestamp, value} points at the requested resolution and aggregation, and
    optionally narrowed to a single protected database.
    """
    # Every interpolated part is validated before it reaches the query string.
    metric_name = _validated_choice(metricName, _METRIC_NAMES, "metricName")
    metric_resolution = _validated_choice(resolution, _METRIC_RESOLUTIONS, "resolution")
    metric_aggregation = _validated_choice(aggregation, _METRIC_AGGREGATIONS, "aggregation")

    filter_clause = ""
    if protected_database_id:
        resource_id = _validated_ocid(protected_database_id, "protected_database_id")
        filter_clause = f'{{resourceId="{resource_id}"}}'

    # Build Monitoring query against Recovery metrics namespace
    request_id = uuid.uuid4().hex
    monitoring_client = get_monitoring_client(request_id=request_id)
    namespace = "oci_recovery_service"
    # Query format: MetricName[resolution]{filters}.aggregation()
    query = f"{metric_name}[{metric_resolution}]{filter_clause}.{metric_aggregation}()"

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
                resolution=metric_resolution,
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
    annotations=_READ_ONLY_TOOL,
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
    """
    Lists databases in a DB Home, or across every DB Home in a compartment.

    Exactly one starting point is required: ``db_home_id``, or a
    ``compartment_id`` whose DB Homes are discovered first. Backup settings are
    filled in lazily -- the full Database is fetched only when the summary comes
    back without them -- and each database is correlated with its Recovery
    Service protection policy where one can be found.
    """
    try:
        request_id = uuid.uuid4().hex
        client = get_database_client(region, request_id=request_id)
        if compartment_id:
            compartment_id = _resolve_compartment_id(compartment_id)

        # Determine compartment scope
        comp_ids: list[Optional[str]] = []
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
            # A compartment is not required by the OCI list_databases API when
            # the DB Home has already been supplied.
            comp_ids = [compartment_id]

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
            except Exception as e:
                # No Recovery client or no compartment scope: every database is
                # returned without a policy link, which is the best that can be done.
                _log_event(
                    "protection_policy_enrichment_unavailable",
                    request_id=request_id,
                    tool="list_databases",
                    payload={"error": str(e)},
                    level=logging.WARNING,
                )
                pd_comp_ids = []

            skipped: list[str] = []
            for pd_comp_id in pd_comp_ids:
                # Scoped per compartment on purpose. A caller who cannot list
                # protected databases in one compartment of a subtree gets a 404
                # there; failing the whole correlation would strip the policy link
                # off every database in every *readable* compartment too, which
                # reads as "no protection policy" rather than "could not check".
                try:
                    has_next = True
                    next_page = None
                    while has_next:
                        lp = rec_client.list_protected_databases(compartment_id=pd_comp_id, page=next_page)
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
                            dbid = d.get("databaseId") or d.get("database_id")
                            ppid = d.get("protectionPolicyId") or d.get("protection_policy_id")
                            if dbid and ppid and dbid not in pd_policy_by_dbid:
                                pd_policy_by_dbid[dbid] = ppid
                except Exception as e:
                    skipped.append(pd_comp_id)
                    _log_event(
                        "protection_policy_enrichment_skipped_compartment",
                        request_id=request_id,
                        tool="list_databases",
                        payload={"compartment_id": pd_comp_id, "error": str(e)},
                        level=logging.WARNING,
                    )

            if skipped:
                logger.warning(
                    "Protection policy correlation skipped %s of %s compartments the caller "
                    "cannot read; databases in those compartments have no protectionPolicyId.",
                    len(skipped),
                    len(pd_comp_ids),
                )

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
        for each_comp in comp_ids:
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
    annotations=_READ_ONLY_TOOL,
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
    """
    Retrieves a Database by OCID and maps it to the server model.

    The mapped result is enriched with ``protection_policy_id`` by correlating
    the database with Recovery Service protected databases in the same
    compartment; enrichment failures are swallowed so the core lookup still
    returns.
    """
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
    annotations=_READ_ONLY_TOOL,
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
        Optional[str],
        "Optional work request status filter (e.g., IN_PROGRESS, SUCCEEDED, FAILED). "
        "Applied to the returned restore work requests.",
    ] = None,
    limit: Annotated[Optional[int], "Maximum number of items per backend page."] = None,
    page: Annotated[Optional[str], "Pagination token (opc-next-page) when aggregate_pages=false."] = None,
    sort_order: Annotated[Optional[str], 'Sort order: "ASC" or "DESC". Default "DESC".'] = None,
    sort_by: Annotated[
        Optional[str],
        "Sort the returned restore work requests by one of: timeAccepted, timeStarted, "
        "timeFinished, status, operationType.",
    ] = None,
    opc_request_id: Annotated[Optional[str], "Unique identifier for the request"] = None,
    region: Annotated[Optional[str], "Canonical OCI region (e.g., us-phoenix-1)."] = None,
    aggregate_pages: Annotated[bool, "When true (default), retrieves all pages."] = True,
) -> list[WorkRequest]:
    """
    Lists restore work requests for a compartment, or for a single resource.

    Work requests are fetched per compartment in scope, filtered down to restore
    operations, then sorted and optionally narrowed by status. With
    ``aggregate_pages`` set (the default) every backend page is walked, so
    ``page`` and ``limit`` only apply when it is turned off.
    """
    try:
        request_id = uuid.uuid4().hex
        client = get_work_request_client(region, request_id=request_id)

        def _is_restore_operation(operation: Optional[str]) -> bool:
            """
            Match a work request operation type against "Restore Database", ignoring
            separator and case differences between SDK versions.
            """
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
                # status/sort_by/sort_order are deliberately NOT forwarded:
                # oci.work_requests.WorkRequestClient.list_work_requests accepts only
                # resource_id, limit, page and opc_request_id, and raises ValueError on
                # anything else. They are applied to the results below instead, the same
                # way this tool already filters by operation type.
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
                    if not _is_restore_operation(getattr(mapped, "operation_type", None)):
                        continue
                    if status is not None and str(
                        getattr(mapped, "status", "") or ""
                    ).strip().upper() != status.strip().upper():
                        continue
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

        return _sorted_work_requests(results, sort_by, sort_order)
    except Exception as e:
        logger.error("Error in list_restore tool: %s", e)
        raise


@mcp.tool(
    annotations=_READ_ONLY_TOOL,
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
    """
    Lists Database backups, either for one database or across a compartment.

    With ``database_id``, backups for that database are listed directly. With
    ``compartment_id``, AVAILABLE databases that have auto-backup enabled are
    discovered first and their backups are combined. Manual, automatic and
    long-term retention backups are all included, and each result is augmented
    from the raw SDK object for fields the model mapper leaves unset.
    """
    try:
        request_id = uuid.uuid4().hex
        client = get_database_client(region, request_id=request_id)

        def _to_dict(o):
            """Best-effort conversion of an SDK object to a plain dict."""
            try:
                if hasattr(oci, "util") and hasattr(oci.util, "to_dict"):
                    d = oci.util.to_dict(o)
                    if isinstance(d, dict):
                        return d
            except Exception:
                pass
            return getattr(o, "__dict__", {}) if hasattr(o, "__dict__") else {}

        def _is_auto_backup_enabled_from_dict(d: dict) -> bool:
            """
            Read the auto-backup flag out of a database dict.

            The backup config nests under several different key spellings depending on
            SDK version and casing, so each known variant is tried before falling back to
            looking for the flag at the top level.
            """
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
            """Walk every backup page for one database and return mapped dicts."""
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
                        """Return the first non-null value among several key spellings."""
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
    annotations=_READ_ONLY_TOOL,
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
            """Return the first non-null value among several key spellings."""
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
    annotations=_READ_ONLY_TOOL,
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
    """
    Summarizes how the databases in a compartment or DB Home are backed up.

    Discovers DB Homes when none is given, reads each database's backup
    configuration, optionally looks up the most recent backup time, and groups
    the databases by destination type (DBRS, Object Store, NFS) while calling out
    those with no backup destination configured. Returns one summary object
    carrying counts, name lists and per-database detail.
    """
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
            """Best-effort conversion of an SDK object to a plain dict."""
            try:
                if hasattr(oci, "util") and hasattr(oci.util, "to_dict"):
                    d = oci.util.to_dict(o)
                    if isinstance(d, dict):
                        return d
            except Exception:
                pass
            return getattr(o, "__dict__", {}) if hasattr(o, "__dict__") else {}

        def _get(o: Any, *names: str):
            """Read the first non-null of several field names, by attribute then by key."""
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
            """
            Return a database's backup destination entries as a list.

            The details live under the backup config, whose key spelling varies by SDK
            version, and may arrive as a single object rather than a list.
            """
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
            """Canonicalize a destination type to DBRS, OBJECT_STORE, NFS or UNKNOWN."""
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
            """Read the auto-backup flag out of a database dict, trying each key variant."""
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
            """
            Collect every timestamp a backup object exposes, newest field first.

            End, start and creation times are all gathered because SDK shapes differ in
            which of them they populate; the caller picks the most recent.
            """
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
            """Rank a database's destination types so DBRS sorts ahead of the rest."""
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
            """Sort names, dropping blanks and duplicates."""
            return sorted(dict.fromkeys([x for x in xs if x]))

        # Preserve duplicates for name lists that can correspond to different DB OCIDs
        def _sorted_keep(xs: list[str]) -> list[str]:
            """
            Sort names, dropping blanks but keeping duplicates.

            Two databases may share a name under different OCIDs, so collapsing
            duplicates here would undercount them.
            """
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
    annotations=_READ_ONLY_TOOL,
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
    """
    Lists DB Homes in a compartment, defaulting to the tenancy when none is given.

    Not exposed as an MCP tool; the database and backup tools call it to discover
    DB Homes before listing what lives in them. Paging is handled internally.
    """
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
    annotations=_READ_ONLY_TOOL,
    description=(
        "Gets a database home by OCID and returns it as a simple object. The result is one database home."
    )
)
@_tool_logger("get_db_home")
def get_db_home(
    db_home_id: Annotated[str, "OCID of the DB Home to retrieve."],
    region: Annotated[Optional[str], "Canonical OCI region (e.g., us-ashburn-1)."] = None,
) -> DatabaseHome:
    """Retrieves a DB Home by OCID and maps it to the server model."""
    try:
        request_id = uuid.uuid4().hex
        client = get_database_client(region, request_id=request_id)
        resp = client.get_db_home(db_home_id=db_home_id)
        return map_database_home(resp.data)
    except Exception as e:
        logger.error(f"Error in get_db_home tool: {e}")
        raise


@mcp.tool(
    annotations=_READ_ONLY_TOOL,
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
    """
    Lists DB Systems in a compartment, defaulting to the tenancy when none is given.

    Paging is handled internally, and the scan can be widened to the full
    compartment subtree.
    """
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
    annotations=_READ_ONLY_TOOL,
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
    """Retrieves a DB System by OCID and maps it to the server model."""
    try:
        request_id = uuid.uuid4().hex
        client = get_database_client(region, request_id=request_id)
        resp = client.get_db_system(db_system_id=db_system_id)
        return map_db_system(resp.data)
    except Exception as e:
        logger.error(f"Error in get_db_system tool: {e}")
        raise


@mcp.tool(
    annotations=_LOCAL_GUIDANCE_TOOL,
    description=(
        "Returns dashboard-generation guidance for OCI Recovery Service, including "
        "cloud-protected databases."
    )
)
@_tool_logger("oci_recovery_service_dashboard_prompt")
def oci_recovery_service_dashboard_prompt() -> str:
    """Return dashboard-generation guidance as a tool for clients without prompt support."""
    return OCI_RECOVERY_SERVICE_DASHBOARD_PROMPT


@mcp.tool(
    annotations=_LOCAL_GUIDANCE_TOOL,
    description=(
        "Always call this tool first when a user asks to onboard, protect, enable Recovery Service backups for, or register a database to Recovery Service. The tool first determines and verifies whether the target database is OCI DBaaS or purely on-premises, retrieves the latest Oracle requirements, and performs only the read-only prerequisite checks appropriate for that deployment type. For OCI DBaaS, it configures DBRS automatic backups using the current UpdateDatabase / DbBackupConfig contract, then independently verifies the protected database, assigned policy, health status, and initial backup. For on-premises databases, it proceeds with the Cloud Protect workflow only after the deployment type has been verified and the required approval has been obtained."
    )
)
@_tool_logger("onboard_database_to_recovery_service")
def onboard_database_to_recovery_service() -> str:
    """Return database onboarding guidance as a tool for clients without prompt support."""
    return ONBOARD_DATABASE_TO_RECOVERY_SERVICE_PROMPT


@mcp.tool(
    annotations=_LOCAL_GUIDANCE_TOOL,
    description=(
        "Use this tool first whenever the user's underlying goal is to investigate, explain, or assess the health of Oracle Database backup, protection, or recoverability in an environment using Recovery Service. This includes explicit failures as well as implicit concerns such as unexpected backup behavior, stale or missing backups, protection lag, missing recovery points, restore/PITR problems, policy or retention behavior, RMAN issues, or questions about whether a protected database is healthy and recoverable. Also use it when the user asks whether anything is wrong with the protection environment, even without reporting an error. The tool provides an evidence-driven, access-first diagnostic workflow that traces the actual execution path, acquires relevant evidence, tests competing root-cause hypotheses, independently assesses recoverability, and guides safe remediation and verification. Do not use it for general database questions unrelated to backup, recovery, protection, or recoverability."
    )
)
@_tool_logger("diagnose_recovery_service_issue")
def diagnose_recovery_service_issue() -> str:
    """Return Recovery Service diagnostic guidance as a tool for clients without prompt support."""
    return DIAGNOSE_RECOVERY_SERVICE_ISSUE_PROMPT


def main():
    """
    Console entrypoint: start FastMCP over stdio, or over HTTP when a listener is
    configured.

    ORACLE_MCP_HOST and ORACLE_MCP_PORT must be set together; with neither set the
    server speaks stdio using local profile credentials. With both set it serves
    streamable HTTP and authenticates every caller against an OCI IAM (IDCS)
    domain -- local profile credentials are never used to serve a network
    listener.
    """
    global _http_auth

    host = (os.getenv("ORACLE_MCP_HOST") or "").strip()
    port = (os.getenv("ORACLE_MCP_PORT") or "").strip()

    # Log startup and where logs are actually going (stderr if the file could
    # not be opened, so the line never points at a file that does not exist).
    logger.info("Starting %s v%s", __project__, __version__)
    logger.info("Logs will be written to: %s", _LOG_DESTINATION)

    if bool(host) != bool(port):
        raise ValueError(
            "ORACLE_MCP_HOST and ORACLE_MCP_PORT must either both be set or both be unset."
        )

    if not host:
        logger.info("Running FastMCP over stdio transport (auth_type=%s)", _resolved_auth_type_label())
        mcp.run()
        return

    try:
        port_number = int(port)
    except ValueError as exc:
        raise ValueError("ORACLE_MCP_PORT must be an integer from 1 to 65535.") from exc
    if not 1 <= port_number <= 65535:
        raise ValueError("ORACLE_MCP_PORT must be an integer from 1 to 65535.")

    # HTTP transport authenticates every caller against an OCI IAM (IDCS) domain;
    # local profile credentials are never used to serve a network listener.
    logger.info("Running FastMCP over streamable HTTP with OCI IAM OAuth at http://%s:%s", host, port)
    _http_auth = _build_http_auth()
    mcp.auth = _http_auth.provider
    mcp.run(transport="http", host=host, port=port_number)


if __name__ == "__main__":
    main()
