"""Optional post-proxy-GET Telegram site reachability check."""
from __future__ import annotations
import concurrent.futures
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "usual-sub" / "legacy"))
import proxy_parser as legacy
STAGE_NAME = "telegram_site_check"

def run_stage(records, context):
    """Probe Telegram through Xray after the main HTTP tunnel check.

    Context keys: xray_binary, workers, timeout_seconds, url, accepted_status_codes.
    Failure is recorded as rejected and removed from records only when `required` is true.
    """
    url = str(context.get("url", "https://telegram.org/"))
    timeout = float(context.get("timeout_seconds", 8))
    accepted = {int(x) for x in context.get("accepted_status_codes", [200, 301, 302, 403])}
    required = bool(context.get("required", False))
    legacy.PING_TYPE = "proxy_get"
    legacy.PING_MODE = "keepalive"
    legacy.PING_URL = url
    legacy.PING_TIMEOUT = timeout
    legacy.EXPECTED_STATUS_CODES = accepted
    binary = context["xray_binary"]
    workers = max(1, int(context.get("workers", 4)))
    def check(uri):
        ok, reason = legacy._test_one_with_xray(uri.raw, binary)
        return uri, ok, reason
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(check, records))
    rejected = context.setdefault("rejected", [])
    report = []
    kept = []
    for uri, ok, reason in results:
        report.append({"stage": STAGE_NAME, "ok": bool(ok), "reason": reason})
        if not ok:
            rejected.append({"uri": uri.raw, "stage": STAGE_NAME, "reason": reason})
        if ok or not required: kept.append(uri)
    context.setdefault("plugin_reports", {})[STAGE_NAME] = {
        "url": url, "checked": len(records), "passed": sum(1 for x in report if x["ok"]),
        "required": required,
    }
    return kept
