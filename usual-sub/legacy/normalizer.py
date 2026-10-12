"""Semantic proxy identity; preserve credentials and transport/security settings."""
from __future__ import annotations
import ipaddress, socket, urllib.parse
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "usual-sub" / "legacy"))
from domain import ProxyURI
import proxy_parser as legacy

# Parameters that materially change the tunnel. Unknown parameters are preserved
# conservatively so a future protocol extension cannot silently collapse configs.
IDENTITY_QUERY_KEYS = {
    "type", "security", "sni", "servername", "host", "path", "serviceName",
    "authority", "mode", "headerType", "flow", "encryption", "pbk", "sid",
    "spx", "fp", "alpn", "allowInsecure", "ech", "pqv", "packetEncoding",
    "seed", " obfs", "obfs", "obfs-password", "plugin", "plugin-opts",
    "method", "remarks", "tls", "net", "scy", "aid", "alterId", "headerType",
}

def _host_port(uri):
    p = ProxyURI.parse(uri)
    if p.scheme == "vmess":
        try:
            obj = legacy._vmess_object(uri)
            return str(obj.get("add") or obj.get("address") or "").strip().lower(), int(obj.get("port") or 0)
        except Exception:
            return (p.host or ""), p.port or 0
    return (p.host or "").strip().lower(), p.port or 0

def _canonical_host(host):
    if not host: return ""
    try: return ipaddress.ip_address(host).compressed
    except ValueError: pass
    try:
        # Resolve aliases to an address for identity only; never rewrite the URI
        # that is emitted to clients. Failed DNS resolution falls back to hostname.
        answers = sorted({x[4][0] for x in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)})
        if answers: return ",".join(answers)
    except (OSError, UnicodeError): pass
    return host.rstrip(".").lower()

def semantic_key(uri):
    p = ProxyURI.parse(uri)
    host, port = _host_port(p.raw)
    if p.scheme == "vmess":
        try:
            obj = legacy._vmess_object(p.raw)
            account = str(obj.get("id") or obj.get("uuid") or "")
            params = {k: obj[k] for k in sorted(obj) if k.lower() in IDENTITY_QUERY_KEYS or k.lower() in {"add", "address", "port", "id", "uuid"}}
            # Host is canonicalized separately; address itself must not split aliases.
            params.pop("add", None); params.pop("address", None); params.pop("port", None)
        except Exception:
            account, params = "", {}
    else:
        account = urllib.parse.unquote(p.username or "")
        params = {k.lower(): sorted(v) for k, v in p.query.items() if k.lower() not in {"remarks", "name"}}
        # For Shadowsocks the auth is encoded before @; preserve complete credential blob.
        if p.scheme == "ss": account = p.raw.split("://",1)[1].split("@",1)[0]
    # Include protocol, port, credentials/account and all transport/security details.
    # This intentionally keeps different UUIDs/accounts distinct even on same server.
    return (p.scheme, _canonical_host(host), int(port or 0), account, tuple(sorted((k, repr(v)) for k,v in params.items())))

def deduplicate_semantic(uris):
    seen, output, dropped = set(), [], []
    for uri in uris:
        key = semantic_key(uri.raw if hasattr(uri, "raw") else str(uri))
        if key in seen: dropped.append(uri)
        else: seen.add(key); output.append(uri)
    return output, dropped
