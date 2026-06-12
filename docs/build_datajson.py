"""
Converts enriched.csv → docs/data.json for GitHub Pages report (NICENIC investigation).

Usage:
  python docs/build_datajson.py
  python docs/build_datajson.py --ss-base https://my-bucket.s3.amazonaws.com/screenshots/
"""

import argparse
import csv
import gzip
import json
import shutil
from collections import Counter, defaultdict
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

HERE      = Path(__file__).parent.parent
DATA_DIR  = HERE / "data"
SS_S3     = ""   # override with --ss-base


def load_enriched(path: Path) -> list[dict]:
    csv.field_size_limit(10_000_000)
    with open(path, newline="", encoding="utf-8-sig", errors="replace") as f:
        rows = list(csv.DictReader(f))
    # coerce types
    for r in rows:
        r["severity"]    = int(r.get("severity") or 0)
        r["status_code"] = int(r["status_code"]) if str(r.get("status_code","")).isdigit() else None
        r["is_cloudflare"] = r.get("is_cloudflare","").lower() in ("true","1","yes")
        r["threat_hits"] = int(r.get("threat_hits") or 0)
        r["form_count"]  = int(r.get("form_count") or 0)
    return rows


def build_clusters(rows: list[dict]) -> list[dict]:
    clusters = []

    # server fingerprint clusters
    fp_map = defaultdict(list)
    for r in rows:
        fp = r.get("server_fp","")
        if fp and fp not in ("","None"):
            fp_map[fp].append(r["domain"])
    for fp, doms in fp_map.items():
        if len(doms) >= 3:
            cats = Counter(r.get("category","") for r in rows if r["domain"] in set(doms))
            top_cat = cats.most_common(1)[0][0] if cats else ""
            clusters.append({"key": fp, "label": "server_fp", "count": len(doms),
                             "domains": sorted(doms)[:20], "category": top_cat})

    # favicon mmh3 clusters
    fav_map = defaultdict(list)
    for r in rows:
        fv = r.get("favicon_mmh3","")
        if fv and fv not in ("","None","0"):
            fav_map[fv].append(r["domain"])
    for fv, doms in fav_map.items():
        if len(doms) >= 3:
            cats = Counter(r.get("category","") for r in rows if r["domain"] in set(doms))
            top_cat = cats.most_common(1)[0][0] if cats else ""
            clusters.append({"key": str(fv), "label": "favicon_mmh3", "count": len(doms),
                             "domains": sorted(doms)[:20], "category": top_cat})

    clusters.sort(key=lambda c: -c["count"])
    return clusters[:30]


SS_DIR = Path(__file__).parent / "screenshots"

def screenshot_url(domain: str, local_path: str, ss_base: str) -> str:
    if ss_base:
        return ss_base.rstrip("/") + "/" + domain + ".jpg"
    # relative path used by docs/index.html and docs/domains.html
    if (SS_DIR / (domain + ".jpg")).exists():
        return "screenshots/" + domain + ".jpg"
    return ""


def slim_row(r: dict, ss_base: str) -> dict:
    """Keep only columns needed by the report."""
    return {
        "domain":         r.get("domain",""),
        "registered_at":  r.get("registered_at",""),
        "expiring_at":    r.get("expiring_at",""),
        "ip":             r.get("ip",""),
        "ip_country":     r.get("ip_country",""),
        "status_code":    r.get("status_code"),
        "page_type":      r.get("page_type",""),
        "final_url":      r.get("final_url",""),
        "server":         r.get("server",""),
        "server_fp":      r.get("server_fp",""),
        "is_cloudflare":  r.get("is_cloudflare", False),
        "favicon_mmh3":   r.get("favicon_mmh3",""),
        "title":          r.get("title",""),
        "h1":             (r.get("h1","") or "")[:100],
        "meta_desc":      (r.get("meta_desc","") or "")[:120],
        "lang":           r.get("lang",""),
        "form_labels":    r.get("form_labels",""),
        "captcha":        r.get("captcha",""),
        "threat_hits":    r.get("threat_hits", 0),
        "threat_sources": r.get("threat_sources",""),
        "category":       r.get("category",""),
        "severity":       r.get("severity", 0),
        "severity_label": r.get("severity_label","INFO"),
        "brand":          r.get("brand",""),
        "screenshot_url": screenshot_url(r.get("domain",""), r.get("screenshot",""), ss_base),
        "groq_desc":      r.get("groq_desc",""),
    }


def screenshot_count(rows: list[dict]) -> int:
    hash_manifest = HERE / "evidence" / "HASHES.txt"
    if hash_manifest.exists():
        with open(hash_manifest, encoding="utf-8", errors="replace") as f:
            return sum(1 for line in f if line.strip())
    if SS_DIR.exists():
        return sum(1 for _ in SS_DIR.glob("*.png"))
    return sum(1 for r in rows if r.get("screenshot"))


def build_stats(rows: list[dict]) -> dict:
    cats = Counter(r.get("category","") for r in rows)
    return {
        "total":    len(rows),
        "high":     sum(1 for r in rows if r.get("severity_label") == "HIGH"),
        "medium":   sum(1 for r in rows if r.get("severity_label") == "MEDIUM"),
        "alive":    sum(1 for r in rows if r.get("status_code") and r["status_code"] < 400),
        "dead":     sum(1 for r in rows if r.get("category") in ("DEAD","ERROR","PARKING")),
        "cloudflare": sum(1 for r in rows if r.get("is_cloudflare")),
        "with_forms": sum(1 for r in rows if r.get("form_labels")),
        "screenshots": screenshot_count(rows),
        "categories": dict(cats.most_common()),
    }


def compress_raw(src: Path, dest: Path):
    if not src.exists():
        return
    with open(src, "rb") as f_in, open(dest, "wb") as raw_out:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw_out, mtime=0) as f_out:
            shutil.copyfileobj(f_in, f_out)
    print(f"  compressed → {dest.name}  ({dest.stat().st_size//1024} KB)")


def generate_hashes(ss_dir: Path, out: Path):
    if not ss_dir.exists():
        return
    lines = []
    for f in sorted(ss_dir.glob("*.png")):
        h = sha256(f.read_bytes()).hexdigest()
        lines.append(f"{h}  {f.name}")
    out.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(f"  hashes → {out.name}  ({len(lines)} files)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--enriched",   default=str(DATA_DIR / "enriched.csv"))
    ap.add_argument("--ss-base",    default=SS_S3, help="S3 base URL for screenshots")
    ap.add_argument("--out",        default=str(Path(__file__).parent / "data.json"))
    args = ap.parse_args()

    enriched_path = Path(args.enriched)
    if not enriched_path.exists():
        print(f"[!] {enriched_path} not found — run build_evidence.py first")
        return

    print(f"[*] Loading {enriched_path.name}…")
    rows = load_enriched(enriched_path)
    print(f"    {len(rows)} rows")

    slim   = [slim_row(r, args.ss_base) for r in rows]
    stats  = build_stats(rows)
    clusters = build_clusters(rows)

    out = {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "stats":     stats,
        "clusters":  clusters,
        "domains":   slim,
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, separators=(",",":"))
    size = out_path.stat().st_size
    print(f"[+] data.json → {out_path}  ({size//1024} KB,  {len(slim)} domains)")

    # compress raw data for download
    raw_dir = HERE / "pkg" / "raw_data"
    raw_dir.mkdir(parents=True, exist_ok=True)
    for src_name, dest_name in [
        ("lambda_results.jsonl", "lambda_results.jsonl.gz"),
        ("deep_results.jsonl",   "deep_results.jsonl.gz"),
        ("enriched.csv",         "enriched.csv.gz"),
    ]:
        compress_raw(DATA_DIR / src_name, raw_dir / dest_name)

    # evidence hashes
    ss_dir   = HERE / "evidence" / "screenshots"
    hash_out = HERE / "evidence" / "HASHES.txt"
    if ss_dir.exists():
        generate_hashes(ss_dir, hash_out)

    print(f"\n[+] Stats:")
    print(f"    Total: {stats['total']}  HIGH: {stats['high']}  MEDIUM: {stats['medium']}")
    print(f"    Cloudflare: {stats['cloudflare']}  w/Forms: {stats['with_forms']}")
    print(f"\n[+] Top categories:")
    for cat, cnt in list(stats['categories'].items())[:8]:
        print(f"    {cat:<28} {cnt:>5}")


if __name__ == "__main__":
    main()
