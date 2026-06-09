"""MCP / A2A middleware — wrap a tool server once; every call is authorized."""

from __future__ import annotations

from typing import Awaitable, Callable, Optional, Union

from .behalf import Behalf
from .errors import AuthorizationError
from .mandate import Mandate

# A capability rule: a fixed string or a callable deriving one from call args.
CapabilityRule = Union[str, Callable[[dict], str]]
ToolHandler = Callable[..., object]


def with_behalf(
    server,
    *,
    policy: dict[str, CapabilityRule],
    on_denied: str = "throw",
    on_prompt: Optional[Callable[[dict], bool]] = None,
):
    """Wrap a tool server so every call is authorized first.

    ``server`` must expose ``call_tool(name, args, ctx=None)``. The caller's
    mandate rides on ``ctx["mandate"]``. Tools absent from ``policy`` pass
    through unguarded (explicit opt-in).
    """

    class _Guarded:
        def call_tool(self, name: str, args: dict, ctx: Optional[dict] = None):
            rule = policy.get(name, _MISSING)
            if rule is _MISSING:
                return server.call_tool(name, args, ctx)

            capability = rule(args) if callable(rule) else rule
            mandate: Optional[Mandate] = (ctx or {}).get("mandate")

            denied: Optional[str] = None
            if mandate is None:
                denied = "no mandate presented"
            else:
                try:
                    mandate.authorize(capability)
                except AuthorizationError as e:
                    denied = e.reason

            if denied:
                if on_denied == "prompt" and on_prompt is not None:
                    allow = on_prompt(
                        {"tool": name, "capability": capability, "mandate": mandate}
                    )
                    if not allow:
                        raise AuthorizationError(capability, f"{denied} (consent declined)")
                else:
                    raise AuthorizationError(capability, denied)

            return server.call_tool(name, args, ctx)

    return _Guarded()


# Symmetric binding for agent-to-agent calls — same enforcement shape.
with_behalf_a2a = with_behalf

_MISSING = object()


def behalf_mcp_tools(engine: Optional[Behalf] = None) -> list[dict]:
    """The three discovery tools: request_mandate, present_mandate, check_authority."""
    eng = engine or Behalf.default()

    def request_mandate(args: dict) -> dict:
        m = eng.grant(
            principal=args["principal"],
            agent=args["agent"],
            can=args["can"],
            expires_in=args["expiresIn"],
        )
        return {"mandate": m.serialize(), "id": m.id}

    def present_mandate(args: dict) -> dict:
        m = eng.import_(args["mandate"])
        eng.verify_signature(m.token)
        return {
            "valid": True,
            "id": m.id,
            "principal": m.principal,
            "agent": m.agent,
            "expiresAt": m.expires_at,
            "chain": m.chain,
        }

    def check_authority(args: dict) -> dict:
        m = eng.import_(args["mandate"])
        try:
            m.authorize(args["action"])
            return {"allowed": True}
        except AuthorizationError as e:
            return {"allowed": False, "reason": e.reason}

    return [
        {
            "name": "request_mandate",
            "description": "Request a scoped, time-bound mandate authorizing an agent.",
            "inputSchema": {
                "type": "object",
                "required": ["principal", "agent", "can", "expiresIn"],
                "properties": {
                    "principal": {"type": "string"},
                    "agent": {"type": "string"},
                    "can": {"type": "array", "items": {"type": "string"}},
                    "expiresIn": {"type": "string"},
                },
            },
            "handler": request_mandate,
        },
        {
            "name": "present_mandate",
            "description": "Validate a serialized mandate and return its decoded scope.",
            "inputSchema": {
                "type": "object",
                "required": ["mandate"],
                "properties": {"mandate": {"type": "string"}},
            },
            "handler": present_mandate,
        },
        {
            "name": "check_authority",
            "description": "Check whether a mandate authorizes an action (does not perform it).",
            "inputSchema": {
                "type": "object",
                "required": ["mandate", "action"],
                "properties": {"mandate": {"type": "string"}, "action": {"type": "string"}},
            },
            "handler": check_authority,
        },
    ]
