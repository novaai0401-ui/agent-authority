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
from urllib.parse import unquote, urlparse

from .store import MemoryAuditStore, MemoryRevocationStore


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


def _dashboard(revocations, audit, consents) -> str:
    revoked = _list_revoked(revocations)
    recent = list(reversed(audit.all()[-20:]))
    pending = [c for c in consents.values() if c["status"] == "pending"]
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
    def __init__(self, *, revocations=None, audit=None, token: Optional[str] = None) -> None:
        self.revocations = revocations or MemoryRevocationStore()
        self.audit = audit or MemoryAuditStore()
        self.token = token
        self.consents: dict = {}
        self.policies: dict = {}
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

            def _auth_ok(self) -> bool:
                if not cp.token:
                    return True
                return self.headers.get("authorization") == f"Bearer {cp.token}"

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

            def do_GET(self):
                if not self._auth_ok():
                    return self._send(401, {"error": "unauthorized"})
                path = urlparse(self.path).path
                if path == "/":
                    return self._send_html(_dashboard(cp.revocations, cp.audit, cp.consents))
                if path == "/v1/revoked":
                    return self._send(200, {"ids": _list_revoked(cp.revocations)})
                m = re.match(r"^/v1/revoked/(.+)$", path)
                if m:
                    return self._send(200, {"revoked": bool(cp.revocations.is_revoked(unquote(m.group(1))))})
                if path == "/v1/audit":
                    return self._send(200, {"entries": cp.audit.all()})
                m = re.match(r"^/v1/audit/(.+)$", path)
                if m:
                    return self._send(200, {"entries": cp.audit.for_mandate(unquote(m.group(1)))})
                if path == "/v1/consent":
                    return self._send(200, {"consents": list(cp.consents.values())})
                m = re.match(r"^/v1/consent/([^/]+)$", path)
                if m:
                    rec = cp.consents.get(m.group(1))
                    return self._send(200, rec) if rec else self._send(404, {"error": "not found"})
                m = re.match(r"^/v1/policy/([^/]+)$", path)
                if m:
                    name = m.group(1)
                    return (
                        self._send(200, {"name": name, "policy": cp.policies[name]})
                        if name in cp.policies
                        else self._send(404, {"error": "not found"})
                    )
                return self._send(404, {"error": f"no route for GET {path}"})

            def do_POST(self):
                if not self._auth_ok():
                    return self._send(401, {"error": "unauthorized"})
                path = urlparse(self.path).path
                body = self._read_json() or {}
                if path == "/v1/revoke":
                    if not body.get("id"):
                        return self._send(400, {"error": "id required"})
                    cp.revocations.revoke(str(body["id"]))
                    return self._send(200, {"ok": True})
                if path == "/v1/audit":
                    fields = body.get("fields")
                    if fields:
                        with cp._audit_lock:
                            entry = cp.audit.record(
                                mandate_id=fields["mandateId"],
                                chain=fields["chain"],
                                action=fields["action"],
                                decision=fields["decision"],
                                reason=fields.get("reason"),
                            )
                        return self._send(200, {"entry": entry})
                    if body.get("entry"):
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
                    cp.consents[cid] = rec
                    return self._send(201, rec)
                m = re.match(r"^/v1/consent/([^/]+)/decision$", path)
                if m:
                    rec = cp.consents.get(m.group(1))
                    if not rec:
                        return self._send(404, {"error": "not found"})
                    rec["status"] = "approved" if body.get("approve") else "denied"
                    rec["decidedAt"] = int(time.time() * 1000)
                    return self._send(200, rec)
                return self._send(404, {"error": f"no route for POST {path}"})

            def do_PUT(self):
                if not self._auth_ok():
                    return self._send(401, {"error": "unauthorized"})
                path = urlparse(self.path).path
                m = re.match(r"^/v1/policy/([^/]+)$", path)
                if m:
                    body = self._read_json() or {}
                    name = m.group(1)
                    cp.policies[name] = body.get("policy", body)
                    return self._send(200, {"name": name, "policy": cp.policies[name]})
                return self._send(404, {"error": f"no route for PUT {path}"})

        return Handler


def create_control_plane(*, revocations=None, audit=None, token: Optional[str] = None) -> ControlPlane:
    return ControlPlane(revocations=revocations, audit=audit, token=token)
