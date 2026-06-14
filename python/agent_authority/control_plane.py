"""The Behalf control plane (Python port, stdlib http.server).

Wire-compatible with the TypeScript control plane and clients: same routes, same
JSON shapes. Centralizes revocation propagation, audit retention, and a
consent/policy surface with a dashboard at /. Zero dependencies.
"""

from __future__ import annotations

import json
import re
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import parse_qs, unquote, urlparse

from .store import (
    MemoryAuditStore,
    MemoryConsentStore,
    MemoryPolicyStore,
    MemoryRateStore,
    MemoryRevocationStore,
)


def _esc(s) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _list_revoked(store) -> list:
    return sorted(getattr(store, "_revoked", set()))


def _dashboard(revoked, recent, consents) -> str:
    pending = [c for c in consents if c["status"] == "pending"]
    rev_rows = "".join(f"<tr><td><code>{_esc(i)}</code></td></tr>" for i in revoked) or "<tr><td>none</td></tr>"
    pend_rows = (
        "".join(
            f"<tr><td><code>{_esc(c['id'])}</code></td><td>{_esc(c['agent'])}</td><td><code>{_esc(c['capability'])}</code></td></tr>"
            for c in pending
        )
        or "<tr><td colspan=3>none</td></tr>"
    )
    audit_rows = (
        "".join(
            f"<tr><td>{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(e['ts'] / 1000))}</td>"
            f"<td>{_esc(e['decision'])}</td><td><code>{_esc(e['action'])}</code></td><td>{_esc(e.get('reason') or '')}</td></tr>"
            for e in recent
        )
        or "<tr><td colspan=4>none</td></tr>"
    )
    return (
        "<!doctype html><html><head><meta charset='utf-8'><title>Behalf Control Plane</title>"
        "<style>body{font:14px system-ui,sans-serif;margin:2rem;max-width:60rem}"
        "table{border-collapse:collapse;width:100%;margin:.5rem 0 2rem}td,th{border:1px solid #ddd;padding:.3rem .5rem}"
        "code{background:#f4f4f4;padding:.1rem .3rem;border-radius:3px}</style></head><body>"
        "<h1>Behalf Control Plane</h1>"
        f"<h2>Revoked mandates ({len(revoked)})</h2><table><tr><th>id</th></tr>{rev_rows}</table>"
        f"<h2>Pending consent ({len(pending)})</h2><table><tr><th>id</th><th>agent</th><th>capability</th></tr>{pend_rows}</table>"
        f"<h2>Recent audit ({len(recent)})</h2><table><tr><th>time</th><th>decision</th><th>action</th><th>reason</th></tr>{audit_rows}</table>"
        "</body></html>"
    )


class ControlPlane:
    def __init__(
        self,
        *,
        revocations=None,
        audit=None,
        rate=None,
        consents=None,
        policies=None,
        tenant_scoped: bool = False,
        tenants: Optional[dict] = None,
        require_tenant: bool = False,
        consent_ttl_ms: Optional[int] = None,
        token: Optional[str] = None,
    ) -> None:
        self.revocations = revocations or MemoryRevocationStore()
        self.audit = audit or MemoryAuditStore()
        self.rate = rate or MemoryRateStore()
        self.tenant_scoped = tenant_scoped
        self.tenants = tenants or {}
        self.require_tenant = require_tenant
        self.consent_ttl_ms = consent_ttl_ms
        self.token = token
        self.consents = consents or MemoryConsentStore()
        self.policies = policies or MemoryPolicyStore()
        self._server: Optional[ThreadingHTTPServer] = None
        # The HTTP server is threaded, so serialize audit writes to keep the
        # hash chain race-free (the control plane is the single logical writer).
        self._audit_lock = threading.Lock()

    def listen(self, port: int = 0) -> int:
        self._server = ThreadingHTTPServer(("127.0.0.1", port), self._make_handler())
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return self._server.server_address[1]

    def close(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    def _make_handler(self):
        cp = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # silence default logging
                pass

            def _resolve(self):
                """Return {"admin": bool, "issuer": str|None} or None if unauthorized."""
                if not cp.token and not cp.tenants:
                    return {"admin": True, "issuer": None}
                auth = self.headers.get("authorization") or ""
                bearer = auth[7:] if auth.startswith("Bearer ") else ""
                if cp.token and bearer == cp.token:
                    return {"admin": True, "issuer": None}
                if cp.tenants and bearer and bearer in cp.tenants:
                    return {"admin": False, "issuer": cp.tenants[bearer]}
                return None

            def _auth_ok(self) -> bool:
                return self._resolve() is not None

            def _send(self, status: int, body) -> None:
                data = json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _send_html(self, html: str) -> None:
                data = html.encode("utf-8")
                self.send_response(200)
                self.send_header("content-type", "text/html; charset=utf-8")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _read_json(self):
                length = int(self.headers.get("content-length") or 0)
                if not length:
                    return None
                try:
                    return json.loads(self.rfile.read(length))
                except Exception:
                    return None

            def _sweep(self, rec):
                """Pending consent past its TTL becomes 'expired' (terminal deny)."""
                if (
                    rec["status"] == "pending"
                    and cp.consent_ttl_ms is not None
                    and int(time.time() * 1000) - rec["createdAt"] > cp.consent_ttl_ms
                ):
                    rec["status"] = "expired"
                    rec["decidedAt"] = int(time.time() * 1000)
                    cp.consents.put(rec)
                return rec

            def do_GET(self):
                caller = self._resolve()
                if caller is None:
                    return self._send(401, {"error": "unauthorized"})
                if cp.require_tenant and caller["issuer"] is None:
                    return self._send(403, {"error": "a tenant token is required"})
                issuer_scope = caller["issuer"]
                path = urlparse(self.path).path
                if path == "/":
                    # A tenant only sees its own audit; shared revocation/consent
                    # views are withheld so the dashboard can't leak across tenants.
                    if issuer_scope:
                        recent = list(reversed(cp.audit.for_issuer(issuer_scope)[-20:]))
                        return self._send_html(_dashboard([], recent, []))
                    recent = [] if cp.tenant_scoped else list(reversed(cp.audit.all()[-20:]))
                    return self._send_html(
                        _dashboard(_list_revoked(cp.revocations), recent, cp.consents.list())
                    )
                if path == "/v1/revoked":
                    all_ids = _list_revoked(cp.revocations)
                    if issuer_scope:
                        prefix = f"{issuer_scope} "
                        all_ids = [i[len(prefix):] for i in all_ids if i.startswith(prefix)]
                    return self._send(200, {"ids": all_ids})
                m = re.match(r"^/v1/revoked/(.+)$", path)
                if m:
                    rid = unquote(m.group(1))
                    # Tenants see their namespaced revocations PLUS global (admin) ones.
                    if issuer_scope:
                        revoked = cp.revocations.is_revoked(f"{issuer_scope} {rid}") or cp.revocations.is_revoked(rid)
                    else:
                        revoked = cp.revocations.is_revoked(rid)
                    return self._send(200, {"revoked": bool(revoked)})
                if path == "/v1/audit":
                    qs = parse_qs(urlparse(self.path).query)
                    if issuer_scope:
                        entries = cp.audit.for_issuer(issuer_scope)
                    else:
                        issuer = qs.get("issuer", [None])[0]
                        if issuer:
                            entries = cp.audit.for_issuer(issuer)
                        elif cp.tenant_scoped:
                            return self._send(403, {"error": "issuer query required (tenant-scoped)"})
                        else:
                            entries = cp.audit.all()
                    total = len(entries)
                    try:
                        offset = max(0, int(qs.get("offset", ["0"])[0]))
                    except ValueError:
                        offset = 0
                    try:
                        limit = int(qs.get("limit", ["0"])[0])
                    except ValueError:
                        limit = 0
                    if offset or limit > 0:
                        entries = entries[offset : offset + limit] if limit > 0 else entries[offset:]
                    return self._send(200, {"entries": entries, "total": total})
                m = re.match(r"^/v1/audit/(.+)$", path)
                if m:
                    entries = cp.audit.for_mandate(unquote(m.group(1)))
                    if issuer_scope:
                        entries = [e for e in entries if e.get("issuer") == issuer_scope]
                    return self._send(200, {"entries": entries})
                if path == "/v1/consent":
                    records = [self._sweep(r) for r in cp.consents.list()]
                    if issuer_scope:
                        records = [r for r in records if r.get("issuer") == issuer_scope]
                    return self._send(200, {"consents": records})
                m = re.match(r"^/v1/consent/([^/]+)$", path)
                if m:
                    rec = cp.consents.get(m.group(1))
                    if not rec or (issuer_scope and rec.get("issuer") != issuer_scope):
                        return self._send(404, {"error": "not found"})
                    return self._send(200, self._sweep(rec))
                m = re.match(r"^/v1/policy/([^/]+)$", path)
                if m:
                    name = m.group(1)
                    key = f"{issuer_scope} {name}" if issuer_scope else name
                    return (
                        self._send(200, {"name": name, "policy": cp.policies.get(key)})
                        if cp.policies.has(key)
                        else self._send(404, {"error": "not found"})
                    )
                return self._send(404, {"error": f"no route for GET {path}"})

            def do_POST(self):
                caller = self._resolve()
                if caller is None:
                    return self._send(401, {"error": "unauthorized"})
                if cp.require_tenant and caller["issuer"] is None:
                    return self._send(403, {"error": "a tenant token is required"})
                issuer_scope = caller["issuer"]
                path = urlparse(self.path).path
                body = self._read_json() or {}
                if path == "/v1/revoke":
                    if not body.get("id"):
                        return self._send(400, {"error": "id required"})
                    rid = str(body["id"])
                    cp.revocations.revoke(f"{issuer_scope} {rid}" if issuer_scope else rid)
                    return self._send(200, {"ok": True})
                if path == "/v1/audit":
                    fields = body.get("fields")
                    if fields:
                        if issuer_scope and fields.get("issuer") != issuer_scope:
                            return self._send(403, {"error": "issuer does not match tenant token"})
                        with cp._audit_lock:
                            entry = cp.audit.record(
                                mandate_id=fields["mandateId"],
                                chain=fields["chain"],
                                action=fields["action"],
                                decision=fields["decision"],
                                reason=fields.get("reason"),
                                issuer=fields.get("issuer"),
                            )
                        return self._send(200, {"entry": entry})
                    if body.get("entry"):
                        if issuer_scope and body["entry"].get("issuer") != issuer_scope:
                            return self._send(403, {"error": "issuer does not match tenant token"})
                        with cp._audit_lock:
                            cp.audit.append(body["entry"])
                        return self._send(200, {"entry": body["entry"]})
                    return self._send(400, {"error": "fields or entry required"})
                if path == "/v1/consent":
                    if not body.get("agent") or not body.get("capability"):
                        return self._send(400, {"error": "agent and capability required"})
                    cid = uuid.uuid4().hex
                    rec = {
                        "id": cid,
                        "agent": body["agent"],
                        "capability": body["capability"],
                        "context": body.get("context"),
                        "status": "pending",
                        "createdAt": int(time.time() * 1000),
                    }
                    if issuer_scope:
                        rec["issuer"] = issuer_scope
                    cp.consents.put(rec)
                    return self._send(201, rec)
                if path == "/v1/rate":
                    if not body.get("key"):
                        return self._send(400, {"error": "key required"})
                    window_ms = int(body.get("windowMs", 0))
                    limit = float(body.get("limit", -1))
                    if window_ms <= 0 or limit < 0:
                        return self._send(400, {"error": "windowMs must be > 0 and limit must be >= 0"})
                    # The control plane is the time authority — the client's clock
                    # is ignored so it can't slide the window to evade the cap.
                    rate_key = f"{issuer_scope} {body['key']}" if issuer_scope else body["key"]
                    with cp._audit_lock:
                        allowed = cp.rate.hit(rate_key, window_ms, limit, int(time.time() * 1000))
                    return self._send(200, {"allowed": allowed})
                m = re.match(r"^/v1/consent/([^/]+)/decision$", path)
                if m:
                    rec = cp.consents.get(m.group(1))
                    if not rec or (issuer_scope and rec.get("issuer") != issuer_scope):
                        return self._send(404, {"error": "not found"})
                    self._sweep(rec)
                    if rec["status"] == "expired":
                        return self._send(200, rec)
                    rec["status"] = "approved" if body.get("approve") else "denied"
                    rec["decidedAt"] = int(time.time() * 1000)
                    cp.consents.put(rec)
                    return self._send(200, rec)
                return self._send(404, {"error": f"no route for POST {path}"})

            def do_PUT(self):
                caller = self._resolve()
                if caller is None:
                    return self._send(401, {"error": "unauthorized"})
                if cp.require_tenant and caller["issuer"] is None:
                    return self._send(403, {"error": "a tenant token is required"})
                issuer_scope = caller["issuer"]
                path = urlparse(self.path).path
                m = re.match(r"^/v1/policy/([^/]+)$", path)
                if m:
                    body = self._read_json() or {}
                    name = m.group(1)
                    key = f"{issuer_scope} {name}" if issuer_scope else name
                    cp.policies.set(key, body.get("policy", body))
                    return self._send(200, {"name": name, "policy": cp.policies.get(key)})
                return self._send(404, {"error": f"no route for PUT {path}"})

        return Handler


def main() -> None:
    """Run a durable, file-backed control plane (the agent-authority-control-plane bin).

    PORT and BEHALF_HOME are read from the environment; blocks until interrupted.
    """
    import os
    import time as _time

    from .persist import (
        FileAuditStore,
        FileConsentStore,
        FilePolicyStore,
        FileRateStore,
        FileRevocationStore,
    )

    home = os.environ.get("BEHALF_HOME") or os.path.join(os.path.expanduser("~"), ".behalf")
    os.makedirs(home, exist_ok=True)
    port = int(os.environ.get("PORT", "8787"))
    cp = create_control_plane(
        revocations=FileRevocationStore(os.path.join(home, "revocations.json")),
        audit=FileAuditStore(os.path.join(home, "audit.jsonl")),
        consents=FileConsentStore(os.path.join(home, "consents.json")),
        policies=FilePolicyStore(os.path.join(home, "policies.json")),
        rate=FileRateStore(os.path.join(home, "rate.json")),
        token=os.environ.get("BEHALF_TOKEN"),
    )
    bound = cp.listen(port)
    print(f"agent-authority control plane listening on http://127.0.0.1:{bound}  (dashboard at /)", file=__import__("sys").stderr)
    try:
        while True:
            _time.sleep(3600)
    except KeyboardInterrupt:
        cp.close()


def create_control_plane(
    *,
    revocations=None,
    audit=None,
    rate=None,
    consents=None,
    policies=None,
    tenant_scoped: bool = False,
    tenants: Optional[dict] = None,
    require_tenant: bool = False,
    consent_ttl_ms: Optional[int] = None,
    token: Optional[str] = None,
) -> ControlPlane:
    return ControlPlane(
        revocations=revocations,
        audit=audit,
        rate=rate,
        consents=consents,
        policies=policies,
        tenant_scoped=tenant_scoped,
        tenants=tenants,
        require_tenant=require_tenant,
        consent_ttl_ms=consent_ttl_ms,
        token=token,
    )


if __name__ == "__main__":
    main()
