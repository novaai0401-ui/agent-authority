"""Behalf — the reference implementation of agent authority (Python port).

Five verbs, one primitive (the Mandate):

    from behalf import create_behalf

    b = create_behalf()
    mandate = b.grant(                          # 1. GRANT
        principal="alice",
        agent="research-agent",
        can=["read:calendar", "spend:usd<=50"],
        expires_in="1h",
    )
    mandate.authorize("spend:usd=20")           # 2. AUTHORIZE
    child = mandate.attenuate(can=["read:calendar"], expires_in="10m")  # 3. DELEGATE
    b.revoke(mandate.id)                         # 4. REVOKE
    trail = b.audit(mandate.id)                  # 5. AUDIT
"""

from .audit import verify as verify_audit_log
from .behalf import Behalf, create_behalf
from .capability import Capability, is_narrowing, parse as parse_capability, permits
from .lint import LintFinding, is_clean, lint
from .errors import (
    AuthorizationError,
    BehalfError,
    CapabilityParseError,
    IntegrityError,
    WideningError,
)
from .mandate import Mandate
from .persist import (
    FileAuditStore,
    FileConsentStore,
    FilePolicyStore,
    FileRevocationStore,
)
from .control_plane import ControlPlane, create_control_plane
from .mcp_server import McpServer, create_mcp_server
from .quickstart import find_surface, generate_quickstart, list_surfaces
from .remote import (
    ControlPlaneClient,
    HttpAuditStore,
    HttpRateStore,
    HttpRevocationStore,
    control_plane_consent,
)
from .store import (
    AuditStore,
    CachingRevocationStore,
    ConsentStore,
    MemoryAuditStore,
    MemoryConsentStore,
    MemoryPolicyStore,
    MemoryRateStore,
    MemoryRevocationStore,
    PolicyStore,
    RateStore,
    RevocationStore,
)

__version__ = "0.1.0"

__all__ = [
    "Behalf",
    "create_behalf",
    "Mandate",
    "Capability",
    "parse_capability",
    "permits",
    "is_narrowing",
    "lint",
    "is_clean",
    "LintFinding",
    "verify_audit_log",
    "BehalfError",
    "AuthorizationError",
    "WideningError",
    "IntegrityError",
    "CapabilityParseError",
    "MemoryRevocationStore",
    "MemoryAuditStore",
    "MemoryRateStore",
    "RevocationStore",
    "AuditStore",
    "RateStore",
    "FileRevocationStore",
    "FileAuditStore",
    "FileConsentStore",
    "FilePolicyStore",
    "MemoryConsentStore",
    "MemoryPolicyStore",
    "CachingRevocationStore",
    "ConsentStore",
    "PolicyStore",
    "ControlPlane",
    "create_control_plane",
    "HttpRevocationStore",
    "HttpAuditStore",
    "HttpRateStore",
    "ControlPlaneClient",
    "control_plane_consent",
    "McpServer",
    "create_mcp_server",
    "generate_quickstart",
    "find_surface",
    "list_surfaces",
]
