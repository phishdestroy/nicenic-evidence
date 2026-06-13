"""
Groq Llama classification for NICENIC scan results.
Reads data/lambda_results.jsonl, enriches with AI category + groq_desc,
writes data/enriched.csv.

Usage:
    python scan/classify.py --groq-key gsk_XXXX
    python scan/classify.py --groq-key gsk_XXXX --resume  (skip already-classified)
    python scan/classify.py --groq-key gsk_XXXX --skip-dead  (skip DEAD/TIMEOUT/ERROR)
"""

import argparse
import csv
import json
import sys
import time
from pathlib import Path

try:
    from groq import Groq
except ImportError:
    print("[!] pip install groq")
    sys.exit(1)

# ── config ────────────────────────────────────────────────────────────────────
CATEGORIES = [
    "PHISHING_FINANCE",   # banking/payment phishing
    "PHISHING_BRAND",     # brand impersonation (amazon, microsoft, etc.)
    "CARDING",            # stolen CC shop
    "CRYPTO_DRAINER",     # wallet drainer / fake airdrop
    "CRYPTO_EXCHANGE",    # fake exchange / investment scam
    "GAMBLING",           # illegal gambling / bahis
    "ADULT",              # adult / escort / cam
    "MALWARE",            # malware distribution
    "SPAM_PHARMA",        # pharma spam
    "SPAM_SEO",           # SEO spam / link farm
    "PARKING",            # domain parking / expired
    "DEAD",               # unreachable
    "LEGITIMATE",         # appears legitimate
    "UNKNOWN",            # cannot determine
]

SEVERITY_MAP = {
    "PHISHING_FINANCE": 4,
    "PHISHING_BRAND":   4,
    "CARDING":          4,
    "CRYPTO_DRAINER":   4,
    "CRYPTO_EXCHANGE":  3,
    "GAMBLING":         3,
    "ADULT":            2,
    "MALWARE":          4,
    "SPAM_PHARMA":      3,
    "SPAM_SEO":         2,
    "PARKING":          0,
    "DEAD":             0,
    "LEGITIMATE":       0,
    "UNKNOWN":          1,
}

SEVERITY_LABELS = {0: "INFO", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}

SYSTEM_PROMPT = f"""You are a malicious-domain classifier for a security researcher.
Given HTTP fingerprint data for a domain, classify it into exactly one category and provide a short description.

Categories: {", ".join(CATEGORIES)}

Rules:
- Return ONLY valid JSON: {{"category": "...", "desc": "..."}}
- desc: max 80 characters, factual, what the site does
- If status_code is null or page_type is DEAD/TIMEOUT: category=DEAD, desc="Unreachable"
- Be decisive. If ambiguous but suspicious, lean toward the threat category.
"""

BATCH_SIZE = 20   # domains per Groq call
RPM_LIMIT  = 28   # stay under 30 RPM (free tier)


def build_prompt(rows: list[dict]) -> str:
    items = []
    for i, r in enumerate(rows, 1):
        items.append(
            f"{i}. domain={r['domain']} status={r.get('status_code')} "
            f"title={r.get('title','')[:80]} h1={r.get('h1','')[:60]} "
            f"server={r.get('server','')} cf={r.get('is_cloudflare',False)} "
            f"captcha={r.get('captcha','')} body={r.get('body_text','')[:200]}"
        )
    joined = "\n".join(items)
    return (
        f"Classify each domain. Return a JSON array with {len(rows)} objects "
        f"(same order), each: {{\"category\": \"...\", \"desc\": \"...\"}}.\n\n{joined}"
    )


def classify_batch(client: Groq, rows: list[dict]) -> list[dict]:
    prompt = build_prompt(rows)
    for attempt in range(3):
        try:
            resp = client.chat.completions.create(
                model="llama-3.1-8b-instant",
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user",   "content": prompt},
                ],
                temperature=0.1,
                max_tokens=BATCH_SIZE * 40,
            )
            text = resp.choices[0].message.content.strip()
            # extract JSON array
            start = text.find("[")
            end   = text.rfind("]") + 1
            if start == -1:
                raise ValueError("No JSON array in response")
            parsed = json.loads(text[start:end])
            if len(parsed) != len(rows):
                raise ValueError(f"Expected {len(rows)} items, got {len(parsed)}")
            return parsed
        except Exception as e:
            print(f"  [warn] Groq attempt {attempt+1}: {e}")
            time.sleep(2 ** attempt)
    # fallback
    return [{"category": "UNKNOWN", "desc": "classification_failed"}] * len(rows)


CSV_COLS = [
    "domain", "registered_at", "expiring_at", "ip", "ip_country",
    "status_code", "final_url", "server", "server_fp", "is_cloudflare",
    "favicon_mmh3", "title", "h1", "meta_desc", "lang",
    "form_count", "form_labels", "captcha", "body_text",
    "page_type", "category", "severity", "severity_label", "brand",
    "threat_hits", "threat_sources", "groq_desc", "screenshot",
]


def load_zone(zone_csv: Path) -> dict[str, dict]:
    zone = {}
    with open(zone_csv, newline="", encoding="utf-8-sig", errors="replace") as f:
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


def load_scan(jsonl_path: Path) -> list[dict]:
    rows = []
    with open(jsonl_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except Exception:
                    pass
    return rows


def load_existing(out_csv: Path) -> set[str]:
    done = set()
    if not out_csv.exists():
        return done
    with open(out_csv, newline="", encoding="utf-8-sig", errors="replace") as f:
        for row in csv.DictReader(f):
            done.add(row.get("domain",""))
    print(f"  [resume] {len(done)} already classified")
    return done


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--groq-key", required=True)
    ap.add_argument("--scan",     default="data/lambda_results.jsonl")
    ap.add_argument("--zone",     default="3765_full.csv")
    ap.add_argument("--out",      default="data/enriched.csv")
    ap.add_argument("--resume",   action="store_true")
    ap.add_argument("--skip-dead",action="store_true", help="Skip DEAD/TIMEOUT/ERROR")
    ap.add_argument("--batch",    type=int, default=BATCH_SIZE)
    args = ap.parse_args()

    client    = Groq(api_key=args.groq_key)
    zone      = load_zone(Path(args.zone))
    scan_rows = load_scan(Path(args.scan))
    print(f"[*] Loaded {len(scan_rows)} scan rows, {len(zone)} zone entries")

    out_path = Path(args.out)
    done_set = load_existing(out_path) if args.resume else set()

    # filter
    to_classify = [r for r in scan_rows if r["domain"] not in done_set]
    if args.skip_dead:
        to_classify = [r for r in to_classify
                       if r.get("page_type") not in ("DEAD","TIMEOUT","ERROR")]
    print(f"[*] Classifying {len(to_classify)} domains")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    write_header = not (args.resume and out_path.exists())

    with open(out_path, "a", newline="", encoding="utf-8-sig") as fout:
        writer = csv.DictWriter(fout, fieldnames=CSV_COLS, extrasaction="ignore")
        if write_header:
            writer.writeheader()

        batches   = [to_classify[i:i+args.batch] for i in range(0, len(to_classify), args.batch)]
        t0        = time.time()
        n_done    = 0
        last_call = 0.0

        for batch_idx, batch in enumerate(batches):
            # rate-limit
            gap = (60 / RPM_LIMIT) - (time.time() - last_call)
            if gap > 0:
                time.sleep(gap)
            last_call = time.time()

            classifications = classify_batch(client, batch)

            for row, cl in zip(batch, classifications):
                cat   = cl.get("category", "UNKNOWN")
                desc  = cl.get("desc","")
                sev   = SEVERITY_MAP.get(cat, 1)
                z     = zone.get(row["domain"], {})

                out_row = {
                    "domain":        row["domain"],
                    "registered_at": z.get("registered_at", ""),
                    "expiring_at":   z.get("expiring_at",""),
                    "ip":            row.get("ip","") or z.get("ip",""),
                    "ip_country":    z.get("ip_country",""),
                    "status_code":   row.get("status_code",""),
                    "final_url":     row.get("final_url",""),
                    "server":        row.get("server",""),
                    "server_fp":     row.get("server_fp",""),
                    "is_cloudflare": row.get("is_cloudflare", False),
                    "favicon_mmh3":  row.get("favicon_mmh3",""),
                    "title":         row.get("title",""),
                    "h1":            row.get("h1",""),
                    "meta_desc":     row.get("meta_desc",""),
                    "lang":          row.get("lang",""),
                    "form_count":    row.get("form_count", 0),
                    "form_labels":   row.get("form_labels",""),
                    "captcha":       row.get("captcha",""),
                    "body_text":     row.get("body_text","")[:300],
                    "page_type":     row.get("page_type",""),
                    "category":      cat,
                    "severity":      sev,
                    "severity_label": SEVERITY_LABELS.get(sev,"INFO"),
                    "brand":         "",
                    "threat_hits":   0,
                    "threat_sources":"",
                    "groq_desc":     desc,
                    "screenshot":    "",
                }
                writer.writerow(out_row)
                n_done += 1

            fout.flush()

            if (batch_idx + 1) % 10 == 0:
                elapsed = time.time() - t0
                rate    = n_done / elapsed
                remain  = (len(to_classify) - n_done) / rate if rate else 0
                print(f"  [{n_done:>7}/{len(to_classify)}]  {rate:.1f}/s  ETA {remain/60:.0f} min")

    print(f"\n[+] Enriched CSV: {out_path}  ({n_done} rows written)")


if __name__ == "__main__":
    main()
