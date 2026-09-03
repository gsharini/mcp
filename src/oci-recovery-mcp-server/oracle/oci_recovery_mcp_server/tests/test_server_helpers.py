"""
Copyright (c) 2025, 2026 Oracle and/or its affiliates.
Licensed under the Universal Permissive License v1.0 as shown at
https://oss.oracle.com/licenses/upl.

Server-level helpers: response serialization, config lookups, the OCI client
wrapper, and the tool logging decorator.
"""

import logging
import logging.handlers
import stat
from types import SimpleNamespace
from unittest.mock import MagicMock

import oci
import pytest

from _helpers import _raise, _response
import oracle.oci_recovery_mcp_server.server as server
from oracle.oci_recovery_mcp_server.server import mcp


def test_deadline_uses_a_monotonic_cooperative_budget(monkeypatch):
    """
    _Deadline reports unspent until the monotonic clock passes the budget, then
    latches expired. A budget of zero disables the deadline entirely.
    """
    moments = iter([100.0, 100.5, 101.0])
    monkeypatch.setattr(server.time, "monotonic", lambda: next(moments))

    deadline = server._Deadline(seconds=1.0)
    assert deadline.reached() is False
    assert deadline.reached() is True

    disabled = server._Deadline(seconds=0)
    assert disabled.reached() is False


def test_server_helpers_handle_serialization_config_and_wrapping(monkeypatch, tmp_path):
    """
    _safe_jsonable redacts secret-looking keys wherever they appear -- top level,
    nested, and inside pydantic-style dumps -- truncates long strings, and never
    raises, degrading to "<unserializable>" for a value whose repr fails.
    _log_event falls back to plain text when JSON encoding fails, the OCI client
    wrapper emits start/end and start/error event pairs while re-raising, and only
    the deprecated unseparated "apikey" spelling is still translated locally.
    """
    monkeypatch.setattr(server, "_LOG_MAX_VALUE_CHARS", 5)
    monkeypatch.setattr(
        server.oci.util,
        "to_dict",
        lambda _obj: _raise(RuntimeError("no SDK conversion")),
    )

    class DumpOnly:
        """A pydantic-style object exposing only ``model_dump``."""

        __slots__ = ()

        def model_dump(self, **_kwargs):
            """Return a payload holding one secret-looking key and one long value."""
            return {"token": "secret", "value": "abcdef"}

    class DictOnly:
        """An older pydantic-style object exposing only ``dict``."""

        __slots__ = ()

        def dict(self, **_kwargs):
            """Return a payload holding one secret-looking key."""
            return {"private_key": "secret", "value": "ok"}

    class BadRepr:
        """An object that cannot even be repr'd -- the last fallback _safe_jsonable has."""

        __slots__ = ()

        def __repr__(self):
            """Fail, leaving _safe_jsonable no way to render this object."""
            raise RuntimeError("bad repr")

    safe = server._safe_jsonable(
        {
            "access_token": "secret",
            "nested": ["abcdef"],
            "dump": DumpOnly(),
            "dict": DictOnly(),
            "object": SimpleNamespace(answer=42),
            "repr": object(),
        }
    )
    assert safe["access_token"] == "***REDACTED***"
    assert safe["nested"] == ["abcde...(truncated,len=6)"]
    assert safe["dump"]["token"] == "***REDACTED***"
    assert safe["dict"]["private_key"] == "***REDACTED***"
    assert safe["object"] == {"answer": 42}
    assert isinstance(safe["repr"], str)
    assert server._safe_jsonable(BadRepr()) == "<unserializable>"

    log_calls = []
    monkeypatch.setattr(
        server.logger,
        "log",
        lambda level, message: log_calls.append((level, message)),
    )
    server._log_event(
        "unit_event",
        request_id="rid",
        tool="tool",
        phase="phase",
        payload={"value": 1},
    )
    assert "unit_event" in log_calls[-1][1]

    monkeypatch.setattr(
        server.json,
        "dumps",
        lambda *_args, **_kwargs: _raise(TypeError("cannot encode")),
    )
    server._log_event("fallback_event", request_id="rid")
    assert "fallback_event" in log_calls[-1][1]

    wrapped_events = []
    monkeypatch.setattr(
        server,
        "_log_event",
        lambda event, **kwargs: wrapped_events.append((event, kwargs)),
    )
    inner = SimpleNamespace(
        value=3,
        successful=MagicMock(return_value=_response(SimpleNamespace(id="ok"))),
        failing=MagicMock(side_effect=RuntimeError("boom")),
    )
    wrapped = server._wrap_oci_client(inner, request_id="rid", client_name="database")
    assert wrapped.value == 3
    assert wrapped.successful("arg", key="value").data.id == "ok"
    with pytest.raises(RuntimeError, match="boom"):
        wrapped.failing()
    assert [kwargs["phase"] for _, kwargs in wrapped_events] == [
        "start",
        "end",
        "start",
        "error",
    ]

    # Auth type and profile are resolved by oracle-mcp-common, not here; the only
    # thing this server still translates is the deprecated unseparated "apikey".
    for name in server._CANONICAL_AUTH_TYPE_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ORACLE_MCP_AUTH_METHOD", "apikey")
    assert server._deprecated_auth_method_override() is server.AuthType.API_KEY
    for shared_spelling in ("api-key", "api_key", "session"):
        monkeypatch.setenv("ORACLE_MCP_AUTH_METHOD", shared_spelling)
        assert server._deprecated_auth_method_override() is None
    monkeypatch.delenv("ORACLE_MCP_AUTH_METHOD", raising=False)
    assert server._deprecated_auth_method_override() is None
    assert server._resolved_auth_type_label() == "auto"
    monkeypatch.delenv("ORACLE_MCP_AUTH_PROFILE", raising=False)
    monkeypatch.setenv("OCI_CONFIG_PROFILE", "PROFILE2")

    monkeypatch.setattr(
        server.oci.config,
        "from_file",
        lambda file_location, profile_name: {
            "region": profile_name,
            "config_file": file_location,
        },
    )
    loaded = server._load_oci_config_for_server()
    assert loaded["region"] == "PROFILE2"
    assert loaded["additional_user_agent"].startswith("oci-recovery-mcp/")


def test_logging_tool_wrapper_tenancy_and_apikey_client_paths(monkeypatch, tmp_path):
    """
    setup_logging is idempotent and installs both handlers when the console is
    requested, the tool decorator logs a start/error pair and re-raises, and
    get_tenancy prefers the env override, then the profile under stdio -- while
    under HTTP it uses the configured tenancy and never touches the OCI config.
    """
    root_logger = server.logging.getLogger()
    original_handlers = list(root_logger.handlers)
    try:
        root_logger.handlers = []
        monkeypatch.setenv("ORACLE_MCP_LOG_DIR", str(tmp_path))
        monkeypatch.setenv("ORACLE_MCP_LOG_TO_STDOUT", "yes")
        server.setup_logging()
        assert any(
            isinstance(handler, server.RotatingFileHandler)
            for handler in root_logger.handlers
        )
        assert any(
            isinstance(handler, server.logging.StreamHandler)
            and not isinstance(handler, server.RotatingFileHandler)
            for handler in root_logger.handlers
        )
        server.setup_logging()
    finally:
        root_logger.handlers = original_handlers

    phases = []
    monkeypatch.setattr(
        server,
        "_log_event",
        lambda _event, **kwargs: phases.append(kwargs["phase"]),
    )

    @server._tool_logger("boom")
    def failing_tool():
        """A decorated tool that always raises, to exercise the error phase."""
        raise ValueError("bad input")

    with pytest.raises(ValueError, match="bad input"):
        failing_tool()
    assert phases == ["start", "error"]

    # session/apikey: explicit override wins, else the profile's tenancy.
    monkeypatch.setenv("ORACLE_MCP_AUTH_METHOD", "apikey")
    monkeypatch.setenv("TENANCY_ID_OVERRIDE", "tenancy-override")
    assert server.get_tenancy() == "tenancy-override"
    monkeypatch.delenv("TENANCY_ID_OVERRIDE", raising=False)
    monkeypatch.delenv("ORACLE_MCP_TENANCY_ID", raising=False)
    monkeypatch.setattr(
        server, "_load_oci_config_for_server", lambda: {"tenancy": "profile-tenancy"}
    )
    assert server.get_tenancy() == "profile-tenancy"

    # HTTP: the tenancy this deployment serves is configured, and the local profile
    # is never consulted (there is no OCI config file on a hosted server).
    monkeypatch.setenv("ORACLE_MCP_TENANCY_ID", "ocid1.tenancy.oc1..hosted")
    monkeypatch.setattr(server, "_serving_http", lambda: True)
    monkeypatch.setattr(
        server,
        "_load_oci_config_for_server",
        lambda: (_ for _ in ()).throw(AssertionError("HTTP must not read the OCI config")),
    )
    assert server.get_tenancy() == "ocid1.tenancy.oc1..hosted"


def test_logging_falls_back_to_stderr_when_the_log_file_cannot_be_opened(monkeypatch, tmp_path):
    """
    An unopenable log file leaves the server running and logging to stderr.

    A read-only filesystem, a directory owned by another user, or a full disk must
    not stop the server from starting: setup_logging() runs at import, so an
    unhandled OSError here would take the process down before main() could report
    anything at all.
    """
    unwritable = tmp_path / "no-write"
    unwritable.mkdir(mode=0o500)
    monkeypatch.setenv("ORACLE_MCP_LOG_DIR", str(unwritable / "logs"))

    root = logging.getLogger()
    original_handlers = list(root.handlers)
    for handler in original_handlers:
        root.removeHandler(handler)
    try:
        server.setup_logging()
        assert server._LOG_DESTINATION == "stderr"
        # Diagnostics are forced to the console, so the server is never silent.
        assert any(
            isinstance(h, logging.StreamHandler)
            and not isinstance(h, logging.handlers.RotatingFileHandler)
            for h in root.handlers
        )
    finally:
        for handler in list(root.handlers):
            root.removeHandler(handler)
        for handler in original_handlers:
            root.addHandler(handler)


def test_log_files_are_private_to_their_owner(monkeypatch, tmp_path):
    """
    Each rotation opens the log file with mode 0600.

    Tool arguments, and tool results at DEBUG, put a tenancy's resource inventory
    in this file; on a shared host the default mode would let every local user
    read it.
    """
    log_file = tmp_path / "logs" / "server.log"
    log_file.parent.mkdir()
    handler = server._PrivateRotatingFileHandler(str(log_file), encoding="utf-8")
    try:
        handler.emit(logging.LogRecord("t", logging.INFO, __file__, 1, "entry", None, None))
        assert stat.S_IMODE(log_file.stat().st_mode) == 0o600
    finally:
        handler.close()


def test_state_directory_is_outside_the_install_tree(monkeypatch, tmp_path):
    """
    State lands under the home directory by default, and follows the env override.

    The package directory is read-only on a hardened deployment and is thrown away
    entirely between ``uvx`` runs, which would silently discard the logs an
    operator is told to read.
    """
    monkeypatch.delenv(server._STATE_DIR_ENV, raising=False)
    monkeypatch.setattr(server.Path, "home", classmethod(lambda cls: tmp_path))
    assert server._state_dir() == tmp_path / server._STATE_DIR_NAME
    assert server._installation_id_file().parent == server._state_dir()

    monkeypatch.setenv(server._STATE_DIR_ENV, str(tmp_path / "elsewhere"))
    assert server._state_dir() == tmp_path / "elsewhere"


def test_results_are_summarized_at_info_and_written_only_at_debug(monkeypatch):
    """
    A tool result is logged as its shape at INFO and in full only at DEBUG, so an
    ordinary run does not write a tenancy's resource inventory to disk.
    """
    events = []
    monkeypatch.setattr(
        server, "_log_event", lambda event, **kwargs: events.append((event, kwargs))
    )

    @server._tool_logger("demo")
    def demo():
        """A decorated tool returning a result that names a real-looking OCID."""
        return [{"id": "ocid1.protecteddatabase.oc1..secret"}]

    monkeypatch.setattr(server, "_log_full_payloads", lambda: False)
    demo()
    end = [kwargs["payload"] for _e, kwargs in events if kwargs.get("phase") == "end"][-1]
    assert end["result_summary"] == {"type": "list", "count": 1}
    assert "result" not in end

    monkeypatch.setattr(server, "_log_full_payloads", lambda: True)
    demo()
    end = [kwargs["payload"] for _e, kwargs in events if kwargs.get("phase") == "end"][-1]
    assert end["result"] == [{"id": "ocid1.protecteddatabase.oc1..secret"}]


def test_caches_evict_expired_entries_and_stay_bounded():
    """
    The caches drop expired entries, cap at _CACHE_MAX_ENTRIES, and evict
    least-recently-used first -- a hit moves an entry back to the front.

    Both caches are partitioned per tenant and per caller, so a hosted deployment
    gains an entry for every person who signs in.
    """
    entries: dict = {}
    now = 1000.0
    for index in range(server._CACHE_MAX_ENTRIES + 5):
        server._cache_put(entries, f"k{index}", {"fetched_at": now}, ttl=300, now=now)
    assert len(entries) == server._CACHE_MAX_ENTRIES
    assert "k0" not in entries  # oldest evicted first

    aged = {"stale": {"fetched_at": 0.0}, "fresh": {"fetched_at": now}}
    server._cache_put(aged, "new", {"fetched_at": now}, ttl=300, now=now)
    assert set(aged) == {"fresh", "new"}

    assert server._cache_get(aged, "stale", ttl=300, now=now) is None
    assert server._cache_get(aged, "fresh", ttl=300, now=now) is not None
    # A hit refreshes recency, so eviction order is least-recently-used.
    assert list(aged) == ["new", "fresh"]


def test_http_deployments_refuse_to_fall_back_to_profile_credentials(monkeypatch):
    """
    Once an HTTP auth policy exists, _config_and_signer raises rather than reach
    for the local profile; with none built, stdio resolves through it as usual.

    Signing a remote caller's request with the operator's own credentials would
    perform it under a different, probably broader, identity.
    """
    monkeypatch.setattr(server, "_serving_http", lambda: False)
    monkeypatch.setattr(server, "_http_auth", object())
    monkeypatch.setattr(
        server, "_build_profile_auth_context", lambda: pytest.fail("profile credentials used")
    )
    with pytest.raises(RuntimeError, match="Refusing to use local profile credentials"):
        server._config_and_signer()

    # With no HTTP policy built, stdio resolves through the profile as usual.
    monkeypatch.setattr(server, "_http_auth", None)
    monkeypatch.setattr(
        server,
        "_build_profile_auth_context",
        lambda: SimpleNamespace(config={"region": "us-ashburn-1"}, signer=object()),
    )
    config, signer = server._config_and_signer()
    assert config["region"] == "us-ashburn-1"
    assert signer is not None
