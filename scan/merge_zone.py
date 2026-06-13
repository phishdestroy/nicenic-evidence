"""
Merges zone CSV (registered_at, expiring_at, ip) into enriched.csv.
Run this if classify.py was run before zone data was joined properly.

Usage:
    python scan/merge_zone.py
"""

import csv
from pathlib import Path

ZONE_CSV     = Path("3765_full.csv")
ENRICHED_CSV = Path("data/enriched.csv")
OUT_CSV      = Path("data/enriched.csv")

csv.field_size_limit(10_000_000)


def load_zone(path: Path) -> dict[str, dict]:
    zone = {}
    with open(path, newline="", encoding="utf-8-sig", errors="replace") as f:
        for row in csv.DictReader(f):
            domain = (row.get("url") or row.get("domain","")).strip().lower()
            if domain:
                zone[domain] = {
                    "registered_at": row.get("registered_at",""),
                    "expiring_at":   row.get("expiring_at",""),
                    "ip":            row.get("ip",""),
                    "ip_country":    row.get("ip_country",""),
                }
    return zone


def main():
    zone = load_zone(ZONE_CSV)
    print(f"[*] Zone: {len(zone)} entries")

    with open(ENRICHED_CSV, newline="", encoding="utf-8-sig", errors="replace") as f:
        rows = list(csv.DictReader(f))
    print(f"[*] Enriched: {len(rows)} rows")

    fieldnames = list(rows[0].keys())
    updated = 0
    for r in rows:
        z = zone.get(r.get("domain",""), {})
        if z:
            for k in ("registered_at","expiring_at","ip","ip_country"):
                if not r.get(k) and z.get(k):
                    r[k] = z[k]
                    updated += 1

    tmp = OUT_CSV.with_suffix(".tmp")
    with open(tmp, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    tmp.replace(OUT_CSV)
    print(f"[+] Updated {updated} fields. Written: {OUT_CSV}")


if __name__ == "__main__":
    main()
