"""Xray outbound builder: URI parsing/conversion only; no process management."""
import base64
import json
import urllib.parse

def _query(parsed):
    return urllib.parse.parse_qs(parsed.query, keep_blank_values=True)


def _q(query, key, default=""):
    values = query.get(key, [])
    return str(values[0]) if values else default


def _truthy(value):
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _tls_settings(query, default_server_name=""):
    tls = {}
    server_name = _q(query, "sni", default_server_name)
    if server_name:
        tls["serverName"] = server_name
    fp = _q(query, "fp")
    if fp:
        tls["fingerprint"] = fp
    alpn = _q(query, "alpn")
    if alpn:
        tls["alpn"] = [x.strip() for x in alpn.split(",") if x.strip()]
    if _truthy(_q(query, "allowInsecure")):
        tls["allowInsecure"] = True
    return tls


def _vmess_object(uri):
    parsed = urllib.parse.urlsplit(uri.split("#", 1)[0])
    payload = urllib.parse.unquote(parsed.netloc + parsed.path).strip()
    raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
    obj = json.loads(raw.decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("VMess payload must be a JSON object")
    return obj


def _stream_settings(network, security, query, host, vmess=None):
    vmess = vmess or {}
    net = (network or "tcp").lower()
    sec = (security or "none").lower()
    stream = {"network": net, "security": sec}
    if sec == "tls":
        tlsq = dict(query)
        if not _q(tlsq, "sni") and vmess.get("sni"):
            tlsq["sni"] = [str(vmess["sni"])]
        if not _q(tlsq, "fp") and vmess.get("fp"):
            tlsq["fp"] = [str(vmess["fp"])]
        if not _q(tlsq, "alpn") and vmess.get("alpn"):
            tlsq["alpn"] = [str(vmess["alpn"])]
        stream["tlsSettings"] = _tls_settings(tlsq, host)
    elif sec == "reality":
        reality = {
            "serverName": _q(query, "sni", str(vmess.get("sni") or host)),
            "fingerprint": _q(query, "fp", str(vmess.get("fp") or "chrome")),
            "publicKey": _q(query, "pbk"),
            "shortId": _q(query, "sid"),
        }
        spider = _q(query, "spx")
        if spider:
            reality["spiderX"] = spider
        if not reality["publicKey"]:
            raise ValueError("REALITY public key (pbk) is missing")
        stream["realitySettings"] = reality
    elif sec not in {"none", ""}:
        raise ValueError(f"unsupported Xray security mode: {sec}")

    if net == "ws":
        path = _q(query, "path", str(vmess.get("path") or "/"))
        headers = {}
        ws_host = _q(query, "host", str(vmess.get("host") or ""))
        if ws_host:
            headers["Host"] = ws_host
        stream["wsSettings"] = {"path": path or "/", "headers": headers}
    elif net == "grpc":
        service = _q(query, "serviceName", _q(query, "path", str(vmess.get("path") or "")))
        grpc = {"serviceName": service}
        authority = _q(query, "authority", _q(query, "host", str(vmess.get("host") or "")))
        if authority:
            grpc["authority"] = authority
        if _q(query, "mode").lower() == "multi":
            grpc["multiMode"] = True
        stream["grpcSettings"] = grpc
    elif net in {"httpupgrade", "http-upgrade"}:
        stream["network"] = "httpupgrade"
        host_header = _q(query, "host", str(vmess.get("host") or ""))
        settings = {"path": _q(query, "path", str(vmess.get("path") or "/"))}
        if host_header:
            settings["host"] = host_header
        stream["httpupgradeSettings"] = settings
    elif net == "xhttp":
        settings = {"path": _q(query, "path", str(vmess.get("path") or "/"))}
        xhost = _q(query, "host", str(vmess.get("host") or ""))
        if xhost:
            settings["host"] = xhost
        mode = _q(query, "mode", str(vmess.get("mode") or ""))
        if mode:
            settings["mode"] = mode
        stream["xhttpSettings"] = settings
    elif net not in {"tcp", "kcp", "http"}:
        raise ValueError(f"unsupported Xray transport: {net}")
    elif net == "tcp":
        header_type = _q(query, "headerType", str(vmess.get("type") or "none"))
        if header_type and header_type != "none":
            stream["tcpSettings"] = {"header": {"type": header_type}}
    return stream


def build_xray_outbound(uri):
    """Convert supported share links to a single Xray outbound config.

    Xray cannot validate Hysteria2, TUIC, or AnyTLS links; those are rejected
    rather than incorrectly marked healthy by a TCP-only test.
    """
    parsed = urllib.parse.urlsplit(uri.split("#", 1)[0])
    scheme = parsed.scheme.lower()
    query = _query(parsed)
    if scheme == "vmess":
        obj = _vmess_object(uri)
        host = str(obj.get("add") or obj.get("address") or "").strip()
        port = int(obj.get("port", 0))
        uid = str(obj.get("id") or obj.get("uuid") or "")
        if not host or not uid or not 1 <= port <= 65535:
            raise ValueError("VMess host, UUID, or port is missing")
        user = {"id": uid, "alterId": int(obj.get("aid") or 0), "security": str(obj.get("scy") or obj.get("cipher") or "auto")}
        outbound = {"protocol": "vmess", "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]}}
        stream = _stream_settings(str(obj.get("net") or "tcp"), "tls" if str(obj.get("tls") or "").lower() in {"tls", "true", "1"} else "none", query, host, obj)
    elif scheme == "vless":
        host, port = parsed.hostname, parsed.port
        uid = urllib.parse.unquote(parsed.username or "")
        if not host or not uid or not port:
            raise ValueError("VLESS host, UUID, or port is missing")
        user = {"id": uid, "encryption": _q(query, "encryption", "none")}
        flow = _q(query, "flow")
        if flow:
            user["flow"] = flow
        outbound = {"protocol": "vless", "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]}}
        stream = _stream_settings(_q(query, "type", "tcp"), _q(query, "security", "none"), query, host)
    elif scheme == "trojan":
        host, port = parsed.hostname, parsed.port
        password = urllib.parse.unquote(parsed.username or "")
        if not host or not password or not port:
            raise ValueError("Trojan host, password, or port is missing")
        outbound = {"protocol": "trojan", "settings": {"servers": [{"address": host, "port": port, "password": password}]}}
        stream = _stream_settings(_q(query, "type", "tcp"), _q(query, "security", "tls"), query, host)
    elif scheme == "ss":
        netloc = parsed.netloc
        if "@" in netloc:
            credentials, hostport = netloc.rsplit("@", 1)
            if ":" not in credentials:
                decoded = base64.urlsafe_b64decode(credentials + "=" * (-len(credentials) % 4)).decode("utf-8")
                method, password = decoded.split(":", 1)
            else:
                method, password = credentials.split(":", 1)
            hp = urllib.parse.urlsplit("//" + hostport)
            host, port = hp.hostname, hp.port
        else:
            decoded = base64.urlsafe_b64decode(netloc + "=" * (-len(netloc) % 4)).decode("utf-8")
            credentials, hostport = decoded.rsplit("@", 1)
            method, password = credentials.split(":", 1)
            hp = urllib.parse.urlsplit("//" + hostport)
            host, port = hp.hostname, hp.port
        if not host or not port or not method or not password:
            raise ValueError("Shadowsocks method/password/host/port is missing")
        outbound = {"protocol": "shadowsocks", "settings": {"servers": [{"address": host, "port": port, "method": method, "password": password}]}}
        stream = {"network": "tcp", "security": "none"}
    elif scheme in {"socks", "socks5"}:
        host, port = parsed.hostname, parsed.port
        if not host or not port:
            raise ValueError("SOCKS host/port is missing")
        server = {"address": host, "port": port}
        if parsed.username is not None:
            server["users"] = [{"user": urllib.parse.unquote(parsed.username), "pass": urllib.parse.unquote(parsed.password or "")}]
        outbound = {"protocol": "socks", "settings": {"servers": [server]}}
        stream = None
    elif scheme in {"http", "https"}:
        host, port = parsed.hostname, parsed.port
        if not host or not port:
            raise ValueError("HTTP proxy host/port is missing")
        server = {"address": host, "port": port}
        if parsed.username is not None:
            server["users"] = [{"user": urllib.parse.unquote(parsed.username), "pass": urllib.parse.unquote(parsed.password or "")}]
        outbound = {"protocol": "http", "settings": {"servers": [server]}}
        stream = {"network": "tcp", "security": "tls"} if scheme == "https" else None
        if stream and parsed.hostname:
            stream["tlsSettings"] = {"serverName": parsed.hostname}
    else:
        raise ValueError(f"Xray cannot validate protocol {scheme!r}; use a protocol-specific core")

    if stream:
        outbound["streamSettings"] = stream
    return outbound



def build_config(uri, *, loglevel="none"):
    """Build a minimal Xray config for validating exactly one proxy URI."""
    return {
        "log": {"loglevel": loglevel},
        "inbounds": [],
        "outbounds": [build_xray_outbound(uri)],
    }
