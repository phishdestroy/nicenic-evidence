"""
Post-scan pipeline runner — runs all steps after phase1_http.py is done.

Usage:
    python scan/run_pipeline.py --groq-key gsk_XXX --ipinfo-token TOK1,TOK2 --scan-ip 1.2.3.4
    python scan/run_pipeline.py --groq-key gsk_XXX --ipinfo-token TOK1 --scan-ip 1.2.3.4 --skip-classify
    python scan/run_pipeline.py --groq-key gsk_XXX --no-screenshots  (skip Playwright)
"""

import argparse
import subprocess
import sys
from pathlib import Path

PY = sys.executable


def run(cmd: list[str], desc: str):
    print(f"\n{'='*60}")
    print(f"[>>] {desc}")
    print(f"{'='*60}")
    result = subprocess.run(cmd, check=False)
    if result.returncode != 0:
        print(f"[!!] Step failed (exit {result.returncode}) — continuing anyway")
    return result.returncode == 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--groq-key",       required=True)
    ap.add_argument("--ipinfo-token",   default="")
    ap.add_argument("--scan-ip",        default="")
    ap.add_argument("--proxy",          default="")
    ap.add_argument("--captcha-key",    default="")
    ap.add_argument("--skip-classify",  action="store_true")
    ap.add_argument("--skip-geoip",     action="store_true")
    ap.add_argument("--skip-screenshots", action="store_true")
    ap.add_argument("--no-screenshots", action="store_true")
    args = ap.parse_args()

    steps_ok = []

    # 1. Classify
    if not args.skip_classify:
        ok = run([
            PY, "scan/classify.py",
            "--groq-key", args.groq_key,
            "--scan",     "data/lambda_results.jsonl",
            "--zone",     "E:/3765_full.csv",
            "--out",      "data/enriched.csv",
            "--resume",
        ], "Step 1 — Groq AI classification")
        steps_ok.append(("classify", ok))

    # 2. GeoIP
    if not args.skip_geoip and args.ipinfo_token:
        ok = run([
            PY, "scan/geoip_enrich.py",
            "--token",    args.ipinfo_token,
            "--enriched", "data/enriched.csv",
        ], "Step 2 — GeoIP enrichment")
        steps_ok.append(("geoip", ok))

    # 3. Merge zone data (fill missing registered_at/expiring_at)
    ok = run([PY, "scan/merge_zone.py"], "Step 3 — Merge zone data")
    steps_ok.append(("merge", ok))

    # 4. Screenshots
    if not (args.skip_screenshots or args.no_screenshots):
        cmd = [PY, "scan/phase2_screenshots.py", "--enriched", "data/enriched.csv", "--resume"]
        if args.proxy:
            cmd += ["--proxy", args.proxy]
        if args.captcha_key:
            cmd += ["--captcha-key", args.captcha_key]
        ok = run(cmd, "Step 4 — Browser screenshots (HIGH/MEDIUM domains)")
        steps_ok.append(("screenshots", ok))

        # compress
        ok = run([PY, "scan/compress_screenshots.py"], "Step 4b — Compress PNG→JPEG")
        steps_ok.append(("compress", ok))

    # 5. Build IOC feeds
    ok = run([PY, "scan/build_ioc.py"], "Step 5 — Build IOC feeds")
    steps_ok.append(("ioc", ok))

    # 6. Redact credentials
    if args.scan_ip:
        ok = run([
            PY, "scan/redact_creds.py",
            "--scan-ip", args.scan_ip,
        ], "Step 6 — Redact credentials")
        steps_ok.append(("redact", ok))

    # 7. Build data.json
    ok = run([PY, "docs/build_datajson.py"], "Step 7 — Build docs/data.json")
    steps_ok.append(("datajson", ok))

    print(f"\n{'='*60}")
    print("[+] Pipeline complete:")
    for step, ok in steps_ok:
        print(f"    {'✓' if ok else '✗'} {step}")


if __name__ == "__main__":
    main()
