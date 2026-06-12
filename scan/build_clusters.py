"""
Operator cluster analysis for NICENIC evidence.
Groups domains by shared server_fp, favicon_mmh3, IP, ASN, registrant.
Outputs clusters to data/clusters.json for the report site.

Usage:
    python scan/build_clusters.py
    python scan/build_clusters.py --min-size 3
"""

import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

csv.field_size_limit(10_000_000)

ENRICHED = Path("data/enriched.csv")
OUT      = Path("data/clusters.json")

CATEGORY_RANK = {
    "PHISHING_FINANCE": 10, "PHISHING_BRAND": 9, "CRYPTO_DRAINER": 9,
    "CARDING": 8, "MALWARE": 8, "GAMBLING": 6, "CRYPTO_EXCHANGE": 6,
    "ADULT": 4, "SPAM_PHARMA": 4, "SPAM_SEO": 3, "UNKNOWN": 1,
    "LEGITIMATE": 0, "DEAD": 0, "PARKING": 0,
}


def top_cat(domains_data: list[dict]) -> str:
    cats = Counter(r.get("category","") for r in domains_data)
    return max(cats, key=lambda c: (CATEGORY_RANK.get(c, 0), cats[c]), default="UNKNOWN")


def top_severity(domains_data: list[dict]) -> int:
    return max((int(r.get("severity") or 0) for r in domains_data), default=0)


def build_cluster(key: str, key_type: str, domain_rows: list[dict]) -> dict:
    sample = domain_rows[0]
    cat = top_cat(domain_rows)
    sev = top_severity(domain_rows)
    countries = Counter(r.get("ip_country","") for r in domain_rows if r.get("ip_country"))
    ips       = Counter(r.get("ip","") for r in domain_rows if r.get("ip"))
    servers   = Counter(r.get("server","") for r in domain_rows if r.get("server"))
    return {
        "key":          key,
        "key_type":     key_type,
        "count":        len(domain_rows),
        "category":     cat,
        "severity":     sev,
        "severity_label": {0:"INFO",1:"LOW",2:"MEDIUM",3:"HIGH",4:"CRITICAL"}.get(sev,"INFO"),
        "top_country":  countries.most_common(1)[0][0] if countries else "",
        "top_ip":       ips.most_common(1)[0][0] if ips else "",
        "top_server":   servers.most_common(1)[0][0] if servers else "",
        "domains":      sorted(r["domain"] for r in domain_rows)[:50],
        "sample_title": sample.get("title","")[:80],
        "sample_groq":  sample.get("groq_desc","")[:80],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--enriched",  default=str(ENRICHED))
    ap.add_argument("--out",       default=str(OUT))
    ap.add_argument("--min-size",  type=int, default=3)
    args = ap.parse_args()

    print(f"[*] Loading {args.enriched}…")
    with open(args.enriched, newline="", encoding="utf-8-sig", errors="replace") as f:
        rows = list(csv.DictReader(f))
    print(f"    {len(rows)} rows")

    # filter out dead/parked
    alive = [r for r in rows if r.get("page_type") not in ("DEAD","TIMEOUT")
             and r.get("category") not in ("DEAD","LEGITIMATE","PARKING")]

    clusters = []

    # — server fingerprint clusters
    fp_map = defaultdict(list)
    for r in alive:
        fp = r.get("server_fp","").strip()
        if fp and fp not in ("","None","|","|"):
            fp_map[fp].append(r)
    for fp, dom_rows in fp_map.items():
        if len(dom_rows) >= args.min_size:
            clusters.append(build_cluster(fp, "server_fp", dom_rows))

    # — favicon mmh3 clusters
    fav_map = defaultdict(list)
    for r in alive:
        fv = r.get("favicon_mmh3","").strip()
        if fv and fv not in ("","0","None"):
            fav_map[fv].append(r)
    for fv, dom_rows in fav_map.items():
        if len(dom_rows) >= args.min_size:
            clusters.append(build_cluster(fv, "favicon_mmh3", dom_rows))

    # — IP clusters (same hosting IP = likely same operator)
    ip_map = defaultdict(list)
    for r in alive:
        ip = r.get("ip","").strip()
        if ip and ip not in ("","None"):
            ip_map[ip].append(r)
    for ip, dom_rows in ip_map.items():
        if len(dom_rows) >= args.min_size:
            clusters.append(build_cluster(ip, "ip", dom_rows))

    # — ASN/title keyword clusters for known brands
    title_kw_map = defaultdict(list)
    for r in alive:
        title = (r.get("title","") + " " + r.get("groq_desc","")).lower()
        for brand in ["metamask","paypal","amazon","microsoft","apple","netflix",
                      "coinbase","binance","bahis","casino","carding","cvv","dumps"]:
            if brand in title:
                title_kw_map[brand].append(r)
    for kw, dom_rows in title_kw_map.items():
        if len(dom_rows) >= args.min_size:
            clusters.append(build_cluster(kw, "brand_keyword", dom_rows))

    # deduplicate by key
    seen_keys = set()
    unique_clusters = []
    for c in clusters:
        if c["key"] not in seen_keys:
            seen_keys.add(c["key"])
            unique_clusters.append(c)

    # sort by count desc, then severity desc
    unique_clusters.sort(key=lambda c: (-c["count"], -c["severity"]))

    out_path = Path(args.out)
    out_path.parent.mkdir(exist_ok=True)
    out_path.write_text(json.dumps(unique_clusters, ensure_ascii=False, indent=None), encoding="utf-8")
    print(f"[+] {len(unique_clusters)} clusters -> {out_path}")

    # summary
    top10 = unique_clusters[:10]
    print("\nTop 10 clusters:")
    for c in top10:
        print(f"  [{c['key_type']:12s}] {c['count']:>5} domains  {c['category']:20s}  {c['key'][:50]}")


if __name__ == "__main__":
    main()
