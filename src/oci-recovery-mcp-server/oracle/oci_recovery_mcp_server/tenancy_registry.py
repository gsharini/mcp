"""
Copyright (c) 2025, Oracle and/or its affiliates.
Licensed under the Universal Permissive License v1.0 as shown at
https://oss.oracle.com/licenses/upl.
"""

# Server-side tenancy registry for the single-hosted, multi-tenancy OAuth model.
#
# In the hosted (oauth) deployment one process serves many tenancies. Each tenancy
# has its own OCI IAM (IDCS) domain + confidential OAuth app, so the secrets that
# differ per tenancy live here, server-side, and never leave the VM. A user selects
# their tenancy by sending the `X-OCI-Tenancy` HTTP header (the tenancy OCID or the
# short alias); the server matches it against this registry and serves that tenancy
# with the corresponding IDCS domain / client id / client secret.
#
# File format (TOML), pointed at by ORACLE_MCP_TENANCY_REGISTRY:
#
#   [TENANCY_NAME]
#   tenancy_id    = "ocid1.tenancy.oc1..aaaa"
#   idcs_domain   = "idcs-xxxx.identity.oraclecloud.com"
#   client_id     = "..."
#   client_secret = "..."
#   region        = "us-ashburn-1"
#   # optional: jwt_signing_key = "..."   (else a key is generated + persisted per alias)
#
# The TOML table name is the alias (used in OAuth route paths, so it must be URL-safe).

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass
from typing import Optional

# `_select` is reserved for the no-header tenant-selection facade (see multitenant_auth).
_RESERVED_ALIASES = {"_select"}
_ALIAS_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_REQUIRED_FIELDS = ("tenancy_id", "idcs_domain", "client_id", "client_secret", "region")


@dataclass(frozen=True)
class TenancyEntry:
    """One tenancy's server-side configuration."""

    alias: str
    tenancy_id: str
    idcs_domain: str
    client_id: str
    client_secret: str
    region: str
    jwt_signing_key: Optional[str] = None

    def __repr__(self) -> str:  # never leak secrets in logs/reprs
        return f"TenancyEntry(alias={self.alias!r}, tenancy_id={self.tenancy_id!r}, region={self.region!r})"


class RegistryError(ValueError):
    """Raised when the tenancy registry is missing or invalid."""


class TenancyRegistry:
    """Immutable lookup of tenancies, indexed by both alias and tenancy OCID."""

    def __init__(self, entries: list[TenancyEntry]):
        self._by_alias: dict[str, TenancyEntry] = {}
        self._by_ocid: dict[str, TenancyEntry] = {}
        for e in entries:
            self._by_alias[e.alias] = e
            self._by_ocid[e.tenancy_id] = e
        self._entries = list(entries)

    @property
    def entries(self) -> list[TenancyEntry]:
        return list(self._entries)

    @property
    def aliases(self) -> list[str]:
        return [e.alias for e in self._entries]

    def __len__(self) -> int:
        return len(self._entries)

    def lookup(self, key: Optional[str]) -> Optional[TenancyEntry]:
        """Resolve a tenancy by alias or tenancy OCID (returns None if unknown)."""
        if not key:
            return None
        k = key.strip()
        return self._by_alias.get(k) or self._by_ocid.get(k)

    @classmethod
    def from_mapping(cls, data: dict) -> "TenancyRegistry":
        """Build + validate a registry from a parsed TOML mapping."""
        if not isinstance(data, dict) or not data:
            raise RegistryError("Tenancy registry is empty: expected at least one [alias] table.")

        entries: list[TenancyEntry] = []
        seen_ocids: dict[str, str] = {}  # ocid -> alias (for uniqueness errors)

        for alias, body in data.items():
            if not isinstance(body, dict):
                raise RegistryError(
                    f"Registry entry [{alias}] must be a table of key = value pairs."
                )
            if alias in _RESERVED_ALIASES:
                raise RegistryError(f"Registry alias '{alias}' is reserved; choose another name.")
            if not _ALIAS_RE.match(alias):
                raise RegistryError(
                    f"Registry alias '{alias}' is not URL-safe; use only letters, digits, '-' and '_'."
                )

            missing = [f for f in _REQUIRED_FIELDS if not str(body.get(f, "")).strip()]
            if missing:
                raise RegistryError(
                    f"Registry entry [{alias}] is missing required field(s): {', '.join(missing)}."
                )

            # HTTPS-only: the IAM domain carries the OAuth/token-exchange flows.
            if str(body["idcs_domain"]).strip().lower().startswith("http://"):
                raise RegistryError(
                    f"Registry entry [{alias}] idcs_domain must use https, not http. "
                    "Use the bare host or an https:// URL."
                )

            tenancy_id = str(body["tenancy_id"]).strip()
            if tenancy_id in seen_ocids:
                raise RegistryError(
                    f"Duplicate tenancy_id in registry: [{alias}] and [{seen_ocids[tenancy_id]}] "
                    "share the same tenancy OCID."
                )
            seen_ocids[tenancy_id] = alias

            signing_key = body.get("jwt_signing_key")
            signing_key = str(signing_key).strip() if signing_key else None

            entries.append(
                TenancyEntry(
                    alias=alias,
                    tenancy_id=tenancy_id,
                    idcs_domain=str(body["idcs_domain"]).strip(),
                    client_id=str(body["client_id"]).strip(),
                    client_secret=str(body["client_secret"]).strip(),
                    region=str(body["region"]).strip(),
                    jwt_signing_key=signing_key,
                )
            )

        return cls(entries)

    @classmethod
    def from_file(cls, path: str) -> "TenancyRegistry":
        if not os.path.isfile(path):
            raise RegistryError(f"Tenancy registry file not found: {path}")
        try:
            with open(path, "rb") as f:
                data = tomllib.load(f)
        except tomllib.TOMLDecodeError as e:
            raise RegistryError(f"Tenancy registry {path} is not valid TOML: {e}") from e
        return cls.from_mapping(data)


def load_registry(path: Optional[str] = None) -> TenancyRegistry:
    """Load the registry from `path` or ORACLE_MCP_TENANCY_REGISTRY.

    Raises RegistryError with an actionable message if unset/missing/invalid.
    """
    registry_path = (path or os.getenv("ORACLE_MCP_TENANCY_REGISTRY") or "").strip()
    if not registry_path:
        raise RegistryError(
            "oauth mode requires a server-side tenancy registry. Set "
            "ORACLE_MCP_TENANCY_REGISTRY to the path of a tenancies.toml file."
        )
    return TenancyRegistry.from_file(registry_path)
