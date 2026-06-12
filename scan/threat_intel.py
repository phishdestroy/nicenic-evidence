"""
Threat intelligence cross-reference using publicly available GitHub-hosted lists.
No API keys required — downloads lists once, then does fast local lookups.

Sources:
  - URLhaus (downloadable text, no auth)
  - OpenPhish feed
  - MetaMask ETH phishing detect (blacklist.json)
  - Phishing.Database by Mitchell Krog
  - The Blocklist Project (phishing, malware, fraud, redirect, scam)
  - Hagezi DNS blocklists (pro)
  - OISD blocklist (full)

Usage:
    python scan/threat_intel.py
    python scan/threat_intel.py --refresh  (re-download lists)
"""

import csv
import json
import os
import re
import time
from pathlib import Path
from urllib.request import urlopen, Request

csv.field_size_limit(10_000_000)

CACHE_DIR    = Path("data/ti_cache")
ENRICHED     = Path("data/enriched.csv")

LISTS = {
    "urlhaus_domains": {
        "url": "https://urlhaus.abuse.ch/downloads/text_online/",
        "parse": "lines",
        "extract": lambda line: re.search(r'https?://([^/\s]+)', line).group(1).lower()
                                if re.search(r'https?://', line) else None,
    },
    "openphish": {
        "url": "https://openphish.com/feed.txt",
        "parse": "lines",
        "extract": lambda line: re.search(r'https?://([^/\s]+)', line).group(1).lower()
                                if re.search(r'https?://', line) else None,
    },
    "metamask_blacklist": {
        "url": "https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/main/src/config.json",
        "parse": "json_key",
        "key": "blacklist",
    },
    "phishing_database": {
        "url": "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
        "parse": "lines",
        "extract": lambda line: line.strip().lower() if line.strip() and not line.startswith('#') else None,
    },
    "blocklist_phishing": {
        "url": "https://blocklistproject.github.io/Lists/phishing.txt",
        "parse": "lines",
        "extract": lambda line: line.split()[-1].lower() if line.strip() and not line.startswith('#') and line.strip() else None,
    },
    "blocklist_fraud": {
        "url": "https://blocklistproject.github.io/Lists/fraud.txt",
        "parse": "lines",
        "extract": lambda line: line.split()[-1].lower() if line.strip() and not line.startswith('#') and line.strip() else None,
    },
    "blocklist_scam": {
        "url": "https://blocklistproject.github.io/Lists/scam.txt",
        "parse": "lines",
        "extract": lambda line: line.split()[-1].lower() if line.strip() and not line.startswith('#') and line.strip() else None,
    },
    "blocklist_malware": {
        "url": "https://blocklistproject.github.io/Lists/malware.txt",
        "parse": "lines",
        "extract": lambda line: line.split()[-1].lower() if line.strip() and not line.startswith('#') and line.strip() else None,
    },
    "hagezi_pro": {
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt",
        "parse": "lines",
        "extract": lambda line: line.strip().lower() if line.strip() and not line.startswith('#') else None,
    },
}


def download_list(name: str, info: dict, refresh: bool) -> set[str]:
    cache_file = CACHE_DIR / f"{name}.txt"
    if cache_file.exists() and not refresh:
        print(f"  [cache] {name}")
        domains = set(cache_file.read_text(encoding="utf-8", errors="replace").splitlines())
        return domains

    print(f"  [download] {name} <- {info['url'][:60]}…")
    try:
        req = Request(info["url"], headers={"User-Agent": "Mozilla/5.0"})
        with urlopen(req, timeout=30) as r:
            content = r.read().decode("utf-8", errors="replace")
    except Exception as e:
        print(f"    [!] failed: {e}")
        return set()

    domains = set()
    parse = info["parse"]

    if parse == "lines":
        extract = info.get("extract", lambda x: x.strip().lower() if x.strip() else None)
        for line in content.splitlines():
            try:
                d = extract(line)
                if d and "." in d and len(d) < 200:
                    # strip wildcards and www
                    d = d.lstrip("*.")
                    d = d.strip("/")
                    if d:
                        domains.add(d)
            except Exception:
                pass

    elif parse == "json_key":
        try:
            data = json.loads(content)
            key = info.get("key", "blacklist")
            for d in data.get(key, []):
                if isinstance(d, str) and "." in d:
                    domains.add(d.lower().lstrip("*.").strip("/"))
        except Exception as e:
            print(f"    [!] JSON parse error: {e}")

    cache_file.write_text("\n".join(sorted(domains)), encoding="utf-8")
    print(f"    -> {len(domains)} domains")
    return domains


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--enriched", default=str(ENRICHED))
    ap.add_argument("--refresh",  action="store_true", help="Re-download all lists")
    args = ap.parse_args()

    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    print("[1] Downloading threat intel lists…")
    all_hits: dict[str, set[str]] = {}   # domain -> set of source names

    for name, info in LISTS.items():
        domains = download_list(name, info, args.refresh)
        for d in domains:
            all_hits.setdefault(d, set()).add(name)

    total_unique = len(all_hits)
    print(f"\n  Total unique domains in all lists: {total_unique:,}")

    print("\n[2] Cross-referencing with enriched.csv…")
    path = Path(args.enriched)
    with open(path, newline="", encoding="utf-8-sig", errors="replace") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        rows = list(reader)

    # add new fields if needed
    for field in ("threat_hits", "threat_sources", "urlhaus_urls", "threatfox_malware"):
        if field not in fieldnames:
            fieldnames = list(fieldnames) + [field]

    hit_count = 0
    source_counts: dict[str, int] = {}

    for row in rows:
        d = row.get("domain","").lower()
        # also try root domain (strip subdomain)
        root = ".".join(d.rsplit(".")[-2:]) if d.count(".") > 1 else d

        sources = set()
        if d in all_hits:
            sources |= all_hits[d]
        if root in all_hits:
            sources |= all_hits[root]

        if sources:
            row["threat_hits"]    = len(sources)
            row["threat_sources"] = ",".join(sorted(sources))
            hit_count += 1
            for s in sources:
                source_counts[s] = source_counts.get(s, 0) + 1
        else:
            row.setdefault("threat_hits", 0)
            row.setdefault("threat_sources", "")

    print(f"  Matched: {hit_count}/{len(rows)} ({100*hit_count/len(rows):.1f}%)")

    # write back
    tmp = path.with_suffix(".ti_tmp")
    with open(tmp, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    import shutil
    shutil.copy2(tmp, path)
    os.remove(tmp)

    print("\n[+] Source breakdown:")
    for src, cnt in sorted(source_counts.items(), key=lambda x: -x[1]):
        print(f"    {src:<30} {cnt:>7}")


if __name__ == "__main__":
    main()
