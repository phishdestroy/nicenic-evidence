"""
Post-scan finalizer:
1. Merges all scan result files into one clean scan_final.jsonl
2. Adds new alive domains from timeout rescan to classify queue
3. Builds ioc/ feeds and data.json

Usage after all scans complete:
    python scan/finalize.py
    python scan/finalize.py --groq-key gsk_... --resume  (classify newly found alive)
"""

import argparse
import csv
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

DATA = Path("data")
csv.field_size_limit(10_000_000)


def load_jsonl(path: Path, label="") -> dict[str, dict]:
    results = {}
    if not path.exists():
        return results
    n = 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                r = json.loads(line)
                d = r.get("domain", "")
                if not d: continue
                existing = results.get(d)
                if existing is None:
                    results[d] = r
                else:
                    old_alive = existing.get("page_type") not in ("DEAD","TIMEOUT","ERROR")
                    new_alive = r.get("page_type") not in ("DEAD","TIMEOUT","ERROR")
                    old_fav   = bool(existing.get("favicon_mmh3"))
                    new_fav   = bool(r.get("favicon_mmh3"))
                    if (not old_alive and new_alive) or \
                       (old_alive == new_alive and not old_fav and new_fav):
                        results[d] = r
                n += 1
            except: pass
    fav = sum(1 for r in results.values() if r.get("favicon_mmh3"))
    alive = sum(1 for r in results.values() if r.get("page_type") not in ("DEAD","TIMEOUT","ERROR"))
    print(f"  {label}: {n} lines -> {len(results)} unique | alive: {alive} | fav: {fav}")
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--groq-key", default="")
    ap.add_argument("--zone",     default="E:/3765_full.csv")
    ap.add_argument("--resume",   action="store_true")
    args = ap.parse_args()

    print("[1] Merging all scan files...")
    all_results = {}

    # base scan (first Lambda pass)
    for path, label in [
        (DATA / "scan_final.jsonl",            "scan_final (base)"),
        (DATA / "alive_results.jsonl",         "alive_rescan (w/favicons)"),
        (DATA / "missing_results.jsonl",        "missing_rescan"),
        (DATA / "timeout_results.jsonl",        "local_timeout"),
        (DATA / "lambda_timeout_results.jsonl", "lambda_timeout"),
    ]:
        chunk = load_jsonl(path, label)
        for d, r in chunk.items():
            existing = all_results.get(d)
            if existing is None:
                all_results[d] = r
            else:
                old_alive = existing.get("page_type") not in ("DEAD","TIMEOUT","ERROR")
                new_alive = r.get("page_type") not in ("DEAD","TIMEOUT","ERROR")
                old_fav   = bool(existing.get("favicon_mmh3"))
                new_fav   = bool(r.get("favicon_mmh3"))
                if (not old_alive and new_alive) or \
                   (old_alive == new_alive and not old_fav and new_fav):
                    all_results[d] = r

    cats  = Counter(r.get("page_type","?") for r in all_results.values())
    alive = sum(cats.get(x,0) for x in ("LIVE","BLOCKED","REDIRECT","OTHER"))
    fav   = sum(1 for r in all_results.values() if r.get("favicon_mmh3"))
    print(f"\n  TOTAL: {len(all_results)} unique")
    print(f"  Alive: {alive} ({100*alive/len(all_results):.1f}%)")
    print(f"  Favicons: {fav} ({100*fav/len(all_results):.1f}%)")
    print(f"  {dict(cats)}")

    out = DATA / "scan_master.jsonl"
    with open(out, "w", encoding="utf-8") as f:
        for r in all_results.values():
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"\n  Written: {out}")

    # find alive domains not yet in enriched.csv
    enriched_path = DATA / "enriched.csv"
    already_classified = set()
    if enriched_path.exists():
        with open(enriched_path, newline="", encoding="utf-8-sig", errors="replace") as f:
            for row in csv.DictReader(f):
                already_classified.add(row.get("domain",""))
    print(f"\n[2] Already classified: {len(already_classified)}")

    new_alive = [r for r in all_results.values()
                 if r.get("page_type") not in ("DEAD","TIMEOUT","ERROR")
                 and r["domain"] not in already_classified]
    print(f"    New alive to classify: {len(new_alive)}")

    if new_alive:
        # write to a temp jsonl for classify.py
        tmp = DATA / "new_alive_for_classify.jsonl"
        with open(tmp, "w") as f:
            for r in new_alive:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

        if args.groq_key:
            print(f"\n[3] Running classify on {len(new_alive)} new alive domains...")
            subprocess.run([
                sys.executable, "scan/classify.py",
                "--groq-key", args.groq_key,
                "--scan",     str(tmp),
                "--zone",     args.zone,
                "--out",      str(enriched_path),
                "--resume",
            ], check=False)
        else:
            print(f"\n[3] Skip classify — no --groq-key. Run manually:")
            print(f"    python scan/classify.py --groq-key KEY --scan {tmp} --zone {args.zone} --out {enriched_path} --resume")


if __name__ == "__main__":
    main()
