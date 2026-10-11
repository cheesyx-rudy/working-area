#!/usr/bin/env python3
"""Build a single sing-box JSON config for the isolated GitHub JSON test space.

Uses the existing project's source list and extraction/filter helpers from
usual-sub/legacy/proxy_parser.py. It never writes to the production subscription
or the MosHub project. Unsupported URI schemes are skipped with a count.
"""
from __future__ import annotations
import base64, importlib.util, json, re, sys, urllib.parse
from pathlib import Path
from datetime import datetime, timezone

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
LEGACY = REPO / "usual-sub" / "legacy"
OUTPUT = HERE / "config.json"
MAX_CONFIGS = 1000

spec = importlib.util.spec_from_file_location("likvid_legacy_parser", LEGACY / "proxy_parser.py")
legacy = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = legacy
assert spec.loader is not None
spec.loader.exec_module(legacy)


def q(uri: str) -> dict[str, list[str]]:
    return urllib.parse.parse_qs(urllib.parse.urlsplit(uri).query, keep_blank_values=True)


def first(query, *names, default=""):
    for name in names:
        vals = query.get(name)
        if vals and vals[0] != "":
            return urllib.parse.unquote(vals[0])
    return default


def tag_for(uri, index):
    fragment = urllib.parse.urlsplit(uri).fragment
    label = urllib.parse.unquote(fragment).strip()
    label = re.sub(r"[^\w .()\-🌐-🙏]", "", label, flags=re.UNICODE).strip()
    label = re.sub(r"\s+", " ", label)[:70]
    return f"node-{index:04d}" + (f"-{label}" if label else "")


def host_port(parsed):
    host = parsed.hostname
    port = parsed.port
    if not host or not port:
        raise ValueError("missing host or port")
    return host, port


def decode_vmess(uri):
    raw = urllib.parse.urlsplit(uri)
    payload = urllib.parse.unquote((raw.netloc + raw.path).strip())
    payload += "=" * (-len(payload) % 4)
    obj = json.loads(base64.urlsafe_b64decode(payload).decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("VMess payload is not an object")
    return obj


def convert(uri, index):
    p = urllib.parse.urlsplit(uri)
    scheme = p.scheme.lower()
    tag = tag_for(uri, index)
    query = q(uri)
    common = {"tag": tag}
    if scheme == "vmess":
        obj = decode_vmess(uri)
        server = str(obj.get("add") or obj.get("address") or "").strip()
        port = int(obj.get("port") or 0)
        uid = str(obj.get("id") or "").strip()
        if not server or not port or not uid: raise ValueError("VMess requires add, port and id")
        ob = {**common, "type":"vmess", "server":server, "server_port":port,
              "uuid":uid, "security":str(obj.get("scy") or "auto"), "alter_id":int(obj.get("aid") or 0)}
        net = str(obj.get("net") or "tcp").lower()
        if net == "ws":
            headers = {}
            if obj.get("host"): headers["Host"] = str(obj["host"])
            ob["transport"] = {"type":"ws", "path":str(obj.get("path") or "/"), **({"headers":headers} if headers else {})}
        elif net == "grpc":
            ob["transport"] = {"type":"grpc", "service_name":str(obj.get("path") or obj.get("serviceName") or "")}
        elif net not in ("tcp", "http", "kcp", "quic", "h2", "httpupgrade"):
            raise ValueError(f"unsupported VMess transport {net}")
        tls = str(obj.get("tls") or "").lower() in ("tls", "true", "1")
        if tls:
            ob["tls"] = {"enabled":True, "server_name":str(obj.get("sni") or obj.get("host") or server)}
            if obj.get("alpn"): ob["tls"]["alpn"] = [x.strip() for x in str(obj["alpn"]).split(",") if x.strip()]
        return ob
    if scheme in ("vless", "trojan", "ss", "hysteria", "hysteria2", "hy2", "tuic", "anytls", "socks", "socks5", "http"):
        if scheme in ("ss",):
            # SIP002 form: ss://method:password@host:port or base64(method:password)@host:port
            netloc = p.netloc
            if "@" not in netloc:
                payload = urllib.parse.unquote(netloc.split("#",1)[0])
                try: payload = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)).decode()
                except Exception: pass
                if "@" in payload: netloc = payload
            pp = urllib.parse.urlsplit("ss://" + netloc)
            host, port = host_port(pp)
            userinfo = urllib.parse.unquote(pp.username or "")
            password = urllib.parse.unquote(pp.password or "")
            if not password and ":" in userinfo: userinfo, password = userinfo.split(":",1)
            method = userinfo
            if not method or not password: raise ValueError("Shadowsocks requires method and password")
            return {**common,"type":"shadowsocks","server":host,"server_port":port,"method":method,"password":password}
        host, port = host_port(p)
        username = urllib.parse.unquote(p.username or "")
        password = urllib.parse.unquote(p.password or "")
        if scheme in ("trojan", "hysteria", "hysteria2", "hy2", "anytls") and not password:
            password, username = username, ""
        if scheme in ("vless", "trojan"):
            if scheme == "vless" and not username: raise ValueError("VLESS UUID missing")
            if scheme == "trojan" and not password: raise ValueError("Trojan password missing")
            net = first(query,"type",default="tcp").lower()
            security = first(query,"security",default="none").lower()
            tls = {"enabled": security in ("tls", "reality", "xtls"), "server_name":first(query,"sni","servername",default=host)}
            fp = first(query,"fp")
            if fp: tls["utls"] = {"enabled":True,"fingerprint":fp}
            if security == "reality":
                reality = {"enabled":True,"public_key":first(query,"pbk","publicKey"),"short_id":first(query,"sid","shortId")}
                reality = {k:v for k,v in reality.items() if v}
                tls["reality"] = reality
            ob = ({**common,"type":"vless","server":host,"server_port":port,"uuid":username,"tls":tls}
                  if scheme == "vless" else {**common,"type":"trojan","server":host,"server_port":port,"password":password,"tls":tls})
            if scheme == "vless":
                flow = first(query,"flow")
                if flow: ob["flow"] = flow
            if net == "ws":
                headers = {}
                ws_host = first(query,"host")
                if ws_host: headers["Host"] = ws_host
                ob["transport"] = {"type":"ws","path":first(query,"path",default="/"), **({"headers":headers} if headers else {})}
            elif net == "grpc": ob["transport"] = {"type":"grpc","service_name":first(query,"serviceName","service_name")}
            elif net not in ("tcp", "raw", "httpupgrade"):
                raise ValueError(f"unsupported transport {net}")
            return ob
        elif scheme in ("hysteria2", "hy2", "hysteria"):
            if not password: password = username
            if not password: raise ValueError("Hysteria password missing")
            ob = {**common,"type":"hysteria2","server":host,"server_port":port,"password":password}
            ob["tls"] = {"enabled":True,"server_name":first(query,"sni","peer",default=host),"insecure":first(query,"insecure")=="1"}
            ob["tls"].pop("insecure", None) if first(query,"insecure") not in ("1","true") else None
            ob["tls"]["insecure"] = first(query,"insecure") in ("1","true")
            ob["obfs"] = ({"type":"salamander","password":first(query,"obfs-password","obfs_password")} if first(query,"obfs")=="salamander" and first(query,"obfs-password","obfs_password") else None)
            if ob["obfs"] is None: ob.pop("obfs")
        elif scheme == "tuic":
            if not username or not password: raise ValueError("TUIC requires UUID and password")
            ob = {**common,"type":"tuic","server":host,"server_port":port,"uuid":username,"password":password,
                  "congestion_control":first(query,"congestion_control",default="bbr"),"udp_relay_mode":first(query,"udp_relay_mode",default="native"),
                  "tls":{"enabled":True,"server_name":first(query,"sni",default=host)}}
        elif scheme == "anytls":
            if not password: raise ValueError("AnyTLS password missing")
            ob = {**common,"type":"anytls","server":host,"server_port":port,"password":password,
                  "tls":{"enabled":True,"server_name":first(query,"sni",default=host)}}
        elif scheme in ("socks", "socks5", "http"):
            ob = {**common,"type":"socks" if scheme in ("socks","socks5") else "http","server":host,"server_port":port}
            if username: ob["username"] = username
            if password: ob["password"] = password
        else:
            # VLESS/Trojan transport and TLS/REALITY settings
            net = first(query,"type",default="tcp").lower()
            security = first(query,"security",default="none").lower()
            tls = {"enabled":True,"server_name":first(query,"sni","servername",default=host)}
            fp = first(query,"fp")
            if fp: tls["utls"] = {"enabled":True,"fingerprint":fp}
            if security == "reality":
                reality = {"enabled":True,"public_key":first(query,"pbk","publicKey"),"short_id":first(query,"sid","shortId")}
                reality = {k:v for k,v in reality.items() if v}
                tls["reality"] = reality
            elif security in ("tls","xtls"):
                pass
            else: tls["enabled"] = False
            if scheme == "vless": ob = {**common,"type":"vless","server":host,"server_port":port,"uuid":username,"tls":tls}
            else: ob = {**common,"type":"trojan","server":host,"server_port":port,"password":password,"tls":tls}
            if not ob.get("uuid") and scheme == "vless": raise ValueError("VLESS UUID missing")
            if scheme == "trojan" and not password: raise ValueError("Trojan password missing")
            if net == "ws":
                headers = {}
                ws_host = first(query,"host")
                if ws_host: headers["Host"] = ws_host
                ob["transport"] = {"type":"ws","path":first(query,"path",default="/"), **({"headers":headers} if headers else {})}
            elif net == "grpc": ob["transport"] = {"type":"grpc","service_name":first(query,"serviceName","service_name")}
            elif net not in ("tcp", "raw", "httpupgrade"):
                raise ValueError(f"unsupported transport {net}")
        return ob
    raise ValueError(f"unsupported scheme {scheme}")


def collect_uris():
    sources_file = LEGACY / "proxy_sources.txt"
    if not sources_file.exists(): raise SystemExit(f"Missing source list: {sources_file}")
    sources = [x.strip() for x in sources_file.read_text(encoding="utf-8").splitlines() if x.strip() and not x.lstrip().startswith("#")]
    found, seen = [], set()
    for source in sources:
        try:
            for uri in legacy.extract_uris(legacy.fetch(source)):
                key = uri.split("#",1)[0]
                if key in seen or legacy.is_mlkem_encryption_proxy(uri): continue
                seen.add(key); found.append(uri)
        except Exception as exc:
            print(f"[SOURCE ERROR] {source}: {exc}")
    return found[:MAX_CONFIGS]


def build(uris):
    outbounds = []
    errors = {}
    for i, uri in enumerate(uris, 1):
        try: outbounds.append(convert(uri, i))
        except Exception as exc:
            scheme = urllib.parse.urlsplit(uri).scheme.lower()
            errors[scheme] = errors.get(scheme, 0) + 1
            # Never print credentials or the URI itself.
            print(f"[SKIP] config #{i}: {scheme or 'unknown'} conversion failed ({type(exc).__name__}: {exc})")
    if not outbounds:
        raise SystemExit("No supported configs converted; refusing to overwrite the previous JSON.")
    node_tags = [x["tag"] for x in outbounds]
    outbounds.append({"type":"urltest","tag":"auto-balance","outbounds":node_tags,
                      "url":"https://www.gstatic.com/generate_204","interval":"5m","tolerance":50})
    outbounds.extend([{"type":"direct","tag":"direct"},{"type":"block","tag":"block"}])
    return {"log":{"level":"warn","timestamp":True},
            "dns":{"servers":[{"type":"https","tag":"dns-remote","server":"1.1.1.1","detour":"auto-balance"}],"final":"dns-remote","strategy":"prefer_ipv4"},
            "inbounds":[{"type":"tun","tag":"tun-in","interface_name":"singtun0","address":["172.19.0.1/30","fdfe:dcba:9876::1/126"],"auto_route":True,"strict_route":True,"stack":"mixed"}],
            "outbounds":outbounds,
            "route":{"auto_detect_interface":True,"final":"auto-balance","rules":[{"action":"sniff"},{"protocol":"dns","action":"hijack-dns"}]},
            "experimental":{"cache_file":{"enabled":True,"store_fakeip":True}}}, errors


def main():
    uris = collect_uris()
    print(f"[INPUT] extracted {len(uris)} unique URI configs from the existing source list")
    config, errors = build(uris)
    tmp = OUTPUT.with_suffix(".tmp")
    tmp.write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    json.loads(tmp.read_text(encoding="utf-8"))
    tmp.replace(OUTPUT)
    nodes = sum(1 for x in config["outbounds"] if str(x.get("tag","")).startswith("node-"))
    print(f"[DONE] wrote {OUTPUT.name}; supported nodes={nodes}; skipped by scheme={errors}")

if __name__ == "__main__": main()
