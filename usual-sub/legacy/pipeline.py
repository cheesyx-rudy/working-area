#!/usr/bin/env python3
"""YAML-driven ETL pipeline for LIKVID-VPN subscriptions."""
import argparse, concurrent.futures, json, os, sys, time, urllib.request
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import urlsplit
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "usual-sub" / "legacy"))
import proxy_parser as legacy


def load_config(path):
    with open(path, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    if not isinstance(cfg, dict) or not isinstance(cfg.get("stages"), list):
        raise ValueError("YAML must contain a root mapping and stages list")
    names = [s.get("name") for s in cfg["stages"] if s.get("enabled", True)]
    allowed = {"collect", "filter_unsupported", "normalize", "deduplicate", "cluster_analysis", "xray_probe", "stability_check"}
    unknown = set(names) - allowed
    if unknown:
        raise ValueError("Unknown stage(s): " + ", ".join(sorted(unknown)))
    return cfg


def ident(uri):
    return uri.split("#", 1)[0].strip()


def cluster_key(uri):
    """Cluster similar variants by endpoint + protocol/transport, not by secret/path."""
    try:
        p = urlsplit(uri.split("#", 1)[0]); scheme = p.scheme.lower()
        if scheme == "vmess":
            o = legacy._vmess_object(uri); host = str(o.get("add") or o.get("address") or "").lower()
            port = int(o.get("port") or 0); net = str(o.get("net") or "tcp").lower()
            sec = "tls" if str(o.get("tls") or "").lower() in {"tls", "true", "1"} else "none"
        else:
            host, port = (p.hostname or "").lower(), p.port or 0
            q = legacy._query(p); net = legacy._q(q, "type", "tcp").lower(); sec = legacy._q(q, "security", "none").lower()
        return f"{scheme}|{host}|{port}|{net}|{sec}"
    except Exception:
        return "invalid|" + ident(uri)


def collect(cfg):
    sc = cfg.get("sources", {}); path = Path(sc.get("path", "usual-sub/legacy/proxy_sources.txt"))
    if not path.is_absolute(): path = ROOT / path
    if not path.exists(): raise FileNotFoundError(f"Sources list not found: {path}")
    urls = [x.strip() for x in path.read_text(encoding="utf-8").splitlines() if x.strip() and not x.lstrip().startswith("#")]
    result, seen = [], set(); limit = int(sc.get("max_source_bytes", 20*1024*1024)); timeout = int(sc.get("fetch_timeout_seconds", 30))
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "LIKVID-VPN-ETL/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as r: raw = r.read(limit + 1)
            if len(raw) > limit: raise ValueError("source exceeds configured byte limit")
            for uri in legacy.extract_uris(raw.decode("utf-8", errors="replace")):
                if uri not in seen: seen.add(uri); result.append(uri)
            print(f"[COLLECT] {url}: {len(result)} cumulative links")
        except Exception as e: print(f"[COLLECT:ERROR] {url}: {type(e).__name__}: {e}")
    return result


def write_lines(path, lines):
    path.parent.mkdir(parents=True, exist_ok=True); tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text("".join(str(x).rstrip() + "\n" for x in lines), encoding="utf-8"); tmp.replace(path)


def run(config_path, xray_binary):
    cfg = load_config(config_path); pipeline = cfg.get("pipeline", {}); outcfg = cfg.get("outputs", {})
    records, rejected, report = [], [], {"pipeline": pipeline.get("name", "likvid"), "started_at": datetime.now(timezone.utc).isoformat(), "stages": [], "clusters": []}
    enabled = [s for s in cfg["stages"] if s.get("enabled", True)]
    for st in enabled:
        name, before, t0 = st["name"], len(records), time.monotonic()
        if name == "collect": records = collect(cfg)
        elif name == "filter_unsupported":
            keep=[]
            for u in records:
                if st.get("skip_mlkem", True) and legacy.is_mlkem_encryption_proxy(u): rejected.append({"uri":u,"stage":name,"reason":"unsupported ML-KEM config"})
                else: keep.append(u)
            records=keep
        elif name == "normalize": records = [u.strip() for u in records if u.strip()]
        elif name == "deduplicate":
            seen=set(); keep=[]
            for u in records:
                k=ident(u) if st.get("identity")=="uri_without_fragment" else u
                if k in seen: rejected.append({"uri":u,"stage":name,"reason":"duplicate URI"})
                else: seen.add(k); keep.append(u)
            records=keep
        elif name == "cluster_analysis":
            groups=defaultdict(list)
            for u in records: groups[cluster_key(u)].append(u)
            threshold=int(st.get("warn_after",3))
            for key, members in groups.items():
                if len(members)>=threshold:
                    report["clusters"].append({"key":key,"count":len(members)})
                    print(f"[CLUSTER] {len(members)} similar configs share endpoint profile: {key}; testing each independently")
        elif name == "xray_probe":
            if not xray_binary or not Path(xray_binary).exists(): raise RuntimeError("Xray binary missing; set XRAY_BINARY or --xray-binary")
            if st.get("core", "xray") != "xray" or st.get("mode", "proxy_get") != "proxy_get" or st.get("request_mode", "keepalive") != "keepalive":
                raise ValueError("This profile requires Xray + proxy_get + keepalive")
            legacy.PING_TYPE="proxy_get"; legacy.PING_MODE="keepalive"
            legacy.PING_URL=str(st.get("test_url","https://www.gstatic.com/generate_204")); legacy.PING_TIMEOUT=float(st.get("timeout_seconds",8))
            legacy.EXPECTED_STATUS_CODES={int(code) for code in st.get("accepted_status_codes", [204])}
            if not legacy.EXPECTED_STATUS_CODES: raise ValueError("accepted_status_codes must not be empty")
            workers=max(1,int(st.get("workers",8))); attempts=max(1,int(st.get("attempts",2))); delay=max(0,float(st.get("retry_delay_seconds",0.5)))
            final={}; pending=list(records)
            for attempt in range(1,attempts+1):
                if not pending: break
                if attempt>1 and delay: time.sleep(delay)
                results=[None]*len(pending)
                with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                    futures={pool.submit(legacy._test_one_with_xray,u,xray_binary):i for i,u in enumerate(pending)}
                    for f in concurrent.futures.as_completed(futures):
                        i=futures[f]
                        try: results[i]=f.result()
                        except Exception as e: results[i]=(False,f"validator-exception: {type(e).__name__}: {e}")
                failed=[]
                for u,res in zip(pending,results):
                    ok,reason=res or (False,"missing validation result")
                    final[u]=(ok,reason,attempt)
                    if not ok: failed.append(u)
                print(f"[XRAY] attempt {attempt}/{attempts}: {len(pending)-len(failed)}/{len(pending)} passed")
                pending=failed
            good=[]; failed_groups=defaultdict(list)
            for u in records:
                ok,reason,attempt=final.get(u,(False,"no result",attempts))
                if ok: good.append(u)
                else:
                    item={"uri":u,"stage":name,"reason":reason,"attempts":attempt,"cluster":cluster_key(u)}
                    rejected.append(item); failed_groups[item["cluster"]].append(item)
            for key, items in failed_groups.items():
                if len(items)>=int(st.get("cluster_failure_warning",3)):
                    print(f"[CLUSTER:FAILED] {len(items)} variants in same cluster failed all probes: {key}")
            records=good
        elif name == "stability_check":
            # Probe stage retries failed nodes; only nodes with a successful tunnel GET remain.
            pass
        report["stages"].append({"name":name,"input":before,"output":len(records),"elapsed_seconds":round(time.monotonic()-t0,2)})
        print(f"[STAGE] {name}: {before} -> {len(records)}")
    if not any(s["name"]=="collect" for s in enabled): raise ValueError("Pipeline requires collect stage")
    initial=max(1,report["stages"][0]["output"] if report["stages"] else len(records)); ratio=len(records)/initial
    if pipeline.get("fail_on_empty",True) and not records: raise RuntimeError("Safety stop: zero working configs; existing subscription preserved")
    min_count=int(pipeline.get("min_output_configs",5)); min_ratio=float(pipeline.get("min_output_ratio",0.03))
    if len(records)<min_count or ratio<min_ratio: raise RuntimeError(f"Safety stop: only {len(records)}/{initial} configs passed ({ratio:.1%}); outputs preserved")
    records=legacy.add_country_labels(records)[:int(outcfg.get("max_configs",1000))]
    paths={k:Path(v) for k,v in outcfg.items() if k in {"working","rejected","report","subscription"}}
    paths={k:(v if v.is_absolute() else ROOT/v) for k,v in paths.items()}
    # Prepare all content first. Replace subscription atomically only after safety checks pass.
    write_lines(paths.get("working",ROOT/"usual-sub/legacy/parsed_proxies.txt"),records)
    write_lines(paths.get("rejected",ROOT/"usual-sub/legacy/rejected_proxies.txt"),[json.dumps(x,ensure_ascii=False) for x in rejected])
    report.update({"accepted":len(records),"rejected":len(rejected),"finished_at":datetime.now(timezone.utc).isoformat()})
    reasons=defaultdict(int)
    for item in rejected: reasons[str(item.get("reason","unknown")).split(":",1)[0]]+=1
    report["rejection_reasons"]=dict(reasons)
    rp=paths.get("report",ROOT/"usual-sub/legacy/validation_report.json"); rp.parent.mkdir(parents=True,exist_ok=True); rp.write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    output=[legacy.rename_uri(u,i) for i,u in enumerate(records,1)]
    updated=(datetime.now(timezone.utc)+timedelta(hours=3)).strftime("%d.%m.%Y %H:%M")
    header=("#subscription-userinfo: upload=0; download=0; total=0; expire=2524608000\n#profile-title: LIKVID VPN\n#profile-update-interval: 1\n"+f"#announce: вся важная информация в канале @LIKVID_VPN // авторы @rudy_bd @cheesyx // обновлено: {updated} | конфигов: {len(output)}")
    result=header+"\n"+legacy.build_happ_routing_link()+"\n"+"\n".join(output)+"\n"
    sp=paths.get("subscription",ROOT/"usual-sub/legacy/proxies.txt"); sp.parent.mkdir(parents=True,exist_ok=True); tmp=sp.with_suffix(sp.suffix+".tmp"); tmp.write_text(result,encoding="utf-8"); tmp.replace(sp)
    print(f"[DONE] accepted={len(output)} rejected={len(rejected)} report={rp}")
    return 0

if __name__=="__main__":
    ap=argparse.ArgumentParser(); ap.add_argument("--config",default="configs/strict.yaml"); ap.add_argument("--xray-binary",default=os.environ.get("XRAY_BINARY","")); args=ap.parse_args()
    cp=Path(args.config); cp=cp if cp.is_absolute() else ROOT/cp
    try: raise SystemExit(run(cp,args.xray_binary))
    except Exception as e: print(f"[PIPELINE:ERROR] {type(e).__name__}: {e}",file=sys.stderr); raise SystemExit(1)
