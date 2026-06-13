# agent-authority (Python)

**Authorization for AI agents** — the reference implementation of **agent
authority** (project name: *Behalf*). Verifiable, scoped, time-bound, revocable
**capability tokens** (mandates) with attenuable, macaroon/biscuit-style
**delegation**, plus MCP and agent-to-agent (A2A) middleware. Capability-based
security, OAuth 2.1 on-behalf-of–style grants, and SPIFFE/SVID-style agent
identity for multi-agent / LLM systems.

Identical API shape to the TypeScript library, **zero dependencies** (standard
library only). The optional `cryptography` extra enables a constant-time Ed25519
backend and sealed credentials:

```bash
pip install agent-authority          # core, dependency-free
pip install "agent-authority[seal]"  # + sealed credentials / hardened crypto
```

## The five verbs

```python
from agent_authority import create_behalf

b = create_behalf()

# 1. GRANT
mandate = b.grant(
    principal="alice",
    agent="research-agent",
    can=["read:calendar", "spend:usd<=50"],
    expires_in="1h",
)

# 2. AUTHORIZE — raises AuthorizationError if denied
mandate.authorize("spend:usd=20")

# 3. ATTENUATE — narrow for a sub-agent; can only shrink
child = mandate.attenuate(can=["read:calendar"], expires_in="10m")

# 4. REVOKE — kills the mandate and its downstream chain
b.revoke(mandate.id)

# 5. AUDIT — every authorize() wrote a hash-chained record
trail = b.audit(mandate.id)
```

## MCP / A2A middleware

```python
from agent_authority.mcp import with_behalf

server = with_behalf(
    my_tool_server,  # exposes call_tool(name, args, ctx=None)
    policy={
        "send_email": "write:email",
        "read_calendar": "read:calendar",
        "transfer_funds": lambda args: f"spend:usd<={args['amount']}",
    },
    on_denied="throw",  # or "prompt" with on_prompt=...
)

# Pass the caller's mandate on the context:
server.call_tool("read_calendar", {}, {"mandate": mandate})
```

`agent_authority.mcp.behalf_mcp_tools()` returns the three discovery tools
(`request_mandate`, `present_mandate`, `check_authority`).

## Develop

```bash
python3 -m unittest discover -s tests   # 28 tests
```
