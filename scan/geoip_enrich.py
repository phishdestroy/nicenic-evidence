"""
GeoIP enrichment via ipinfo.io — adds ip_country to enriched.csv.

Usage:
    python scan/geoip_enrich.py --token TOKEN1,TOKEN2,TOKEN3
    python scan/geoip_enrich.py --token TOKEN1 --resume
"""

import argparse
import csv
import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import urllib.request

CACHE_FILE = Path("data/geoip_cache.json")
ENRICHED   = Path("data/enriched.csv")
THREADS    = 8
csv.field_size_limit(10_000_000)


def lookup(ip: str, tokens: list[str], cache: dict, idx: list) -> str:
    if not ip or ip in cache:
        return cache.get(ip, "")
    token = tokens[idx[0] % len(tokens)]
    idx[0] += 1
    try:
        url = f"https://ipinfo.io/{ip}/country?token={token}"
        with urllib.request.urlopen(url, timeout=5) as r:
            country = r.read().decode().strip()
            cache[ip] = country
            return country
    except Exception:
        return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--enriched", default=str(ENRICHED))
    ap.add_argument("--token",    required=True, help="comma-separated ipinfo.io tokens")
    ap.add_argument("--resume",   action="store_true")
    args = ap.parse_args()

    tokens = [t.strip() for t in args.token.split(",") if t.strip()]
    cache  = json.loads(CACHE_FILE.read_text()) if CACHE_FILE.exists() else {}
    print(f"[*] GeoIP cache: {len(cache)} entries, {len(tokens)} tokens")

    path = Path(args.enriched)
    with open(path, newline="", encoding="utf-8-sig", errors="replace") as f:
        rows = list(csv.DictReader(f))
    fieldnames = list(rows[0].keys())
    if "ip_country" not in fieldnames:
        fieldnames.append("ip_country")

    # collect unique IPs without country
    ips = list({r["ip"] for r in rows if r.get("ip") and not r.get("ip_country")})
    print(f"[*] {len(ips)} IPs to look up")

    idx = [0]
    def do_lookup(ip):
        return ip, lookup(ip, tokens, cache, idx)

    done = 0
    with ThreadPoolExecutor(max_workers=THREADS) as pool:
        for ip, country in pool.map(do_lookup, ips):
            cache[ip] = country
            done += 1
            if done % 500 == 0:
                print(f"  [{done}/{len(ips)}] last: {ip} → {country}")
                CACHE_FILE.write_text(json.dumps(cache, ensure_ascii=False))

    CACHE_FILE.write_text(json.dumps(cache, ensure_ascii=False))

    updated = 0
    for r in rows:
        ip = r.get("ip","")
        if ip and not r.get("ip_country") and cache.get(ip):
            r["ip_country"] = cache[ip]
            updated += 1

    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    tmp.replace(path)
    print(f"[+] Updated {updated} rows. Cache: {len(cache)} entries.")


if __name__ == "__main__":
    main()
