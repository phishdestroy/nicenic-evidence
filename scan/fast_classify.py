"""
Fast rule-based classification for remaining unclassified domains.
Uses keyword matching on title/h1/body_text/domain name.
No API needed — runs in seconds.
Then optionally re-classifies UNKNOWN with high content via Groq.
"""

import csv
import json
import re
from collections import Counter
from pathlib import Path

csv.field_size_limit(10_000_000)

RULES = [
    # category, severity, keywords (any match)
    ("PHISHING_FINANCE",  4, ["bank","paypal","chase","wellsfargo","barclays","hsbc","santander",
                               "login","sign in","verify account","confirm identity","suspended",
                               "unusual activity","blocked account","credit card"]),
    ("PHISHING_BRAND",    4, ["microsoft","apple","amazon","netflix","facebook","instagram",
                               "google","dropbox","office 365","outlook","icloud","steam",
                               "account security","verify email","confirm email"]),
    ("CRYPTO_DRAINER",    4, ["metamask","connect wallet","web3","wallet connect","nft mint",
                               "claim reward","airdrop","free crypto","approve","revoke"]),
    ("CARDING",           4, ["cvv","dumps","fullz","cc shop","carding","stolen cards",
                               "buy cc","fresh cards","bin checker","checker tool"]),
    ("MALWARE",           4, ["download now","crack","keygen","serial key","activate windows",
                               "free download","loader","crypter","stealer","rat tool"]),
    ("GAMBLING",          3, ["casino","bet","poker","slots","roulette","bahis","kumarhane",
                               "sportsbook","jackpot","spin","wager","bookmaker","betting"]),
    ("CRYPTO_EXCHANGE",   3, ["crypto","bitcoin","ethereum","trade","exchange","invest",
                               "profit","btc","usdt","binance","coinbase","defi","staking"]),
    ("ADULT",             2, ["xxx","porn","nude","escort","cam","onlyfans","adult content",
                               "18+","sex","milf","amateur"]),
    ("SPAM_PHARMA",       3, ["viagra","cialis","pharmacy","pills","cheapest","order now",
                               "no prescription","weight loss","diet pills"]),
    ("SPAM_SEO",          2, ["seo","backlink","guest post","directory","link building",
                               "buy traffic","web hosting deal"]),
    ("PARKING",           0, ["domain for sale","parked","coming soon","under construction",
                               "this domain","godaddy","namecheap","sedo","afternic"]),
]

SEVERITY_LABELS = {0:"INFO",1:"LOW",2:"MEDIUM",3:"HIGH",4:"CRITICAL"}


def classify_rule(row: dict) -> tuple[str, int]:
    text = " ".join([
        row.get("title",""), row.get("h1",""), row.get("meta_desc",""),
        row.get("body_text",""), row.get("form_labels",""),
        row.get("domain","").replace("-"," ").replace("."," ")
    ]).lower()

    best_cat, best_sev = "UNKNOWN", 0

    for cat, sev, keywords in RULES:
        if any(kw in text for kw in keywords):
            if sev > best_sev:
                best_cat, best_sev = cat, sev

    # captcha present = likely real content behind it → don't mark as dead
    if row.get("captcha") and best_cat == "UNKNOWN":
        best_sev = 1

    # CF challenge pages with "Suspected Phishing" title
    if "suspected phishing" in text or "phishing" in row.get("title","").lower():
        best_cat, best_sev = "PHISHING_BRAND", 4

    return best_cat, best_sev


def main():
    enriched = Path("data/enriched.csv")
    master   = Path("data/scan_master.jsonl")
    zone_csv = Path("E:/3765_full.csv")

    # load already classified
    classified = {}
    with open(enriched, newline="", encoding="utf-8-sig", errors="replace") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        for row in reader:
            classified[row["domain"]] = row
    print(f"[*] Already classified: {len(classified)}")

    # load zone dates
    zone = {}
    with open(zone_csv, newline="", encoding="utf-8-sig", errors="replace") as f:
        for row in csv.DictReader(f):
            d = (row.get("url") or row.get("domain","")).strip().lower()
            if d:
                zone[d] = {"registered_at": row.get("registered_at",""),
                           "expiring_at":   row.get("expiring_at",""),
                           "ip":            row.get("ip",""),
                           "ip_country":    row.get("ip_country","")}

    # load master scan to find unclassified
    new_rows = []
    with open(master, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                r = json.loads(line)
                d = r.get("domain","")
                if not d or d in classified: continue
                if r.get("page_type") in ("DEAD","TIMEOUT"): continue
                cat, sev = classify_rule(r)
                z = zone.get(d, {})
                new_rows.append({
                    "domain":         d,
                    "registered_at":  z.get("registered_at",""),
                    "expiring_at":    z.get("expiring_at",""),
                    "ip":             r.get("ip","") or z.get("ip",""),
                    "ip_country":     z.get("ip_country",""),
                    "status_code":    r.get("status_code",""),
                    "final_url":      r.get("final_url",""),
                    "server":         r.get("server",""),
                    "server_fp":      r.get("server_fp",""),
                    "is_cloudflare":  r.get("is_cloudflare",False),
                    "favicon_mmh3":   r.get("favicon_mmh3",""),
                    "title":          r.get("title",""),
                    "h1":             r.get("h1",""),
                    "meta_desc":      r.get("meta_desc",""),
                    "lang":           r.get("lang",""),
                    "form_count":     r.get("form_count",0),
                    "form_labels":    r.get("form_labels",""),
                    "captcha":        r.get("captcha",""),
                    "body_text":      r.get("body_text","")[:300],
                    "page_type":      r.get("page_type",""),
                    "category":       cat,
                    "severity":       sev,
                    "severity_label": SEVERITY_LABELS.get(sev,"INFO"),
                    "brand":          "",
                    "threat_hits":    0,
                    "threat_sources": "",
                    "groq_desc":      "",
                    "screenshot":     "",
                })
            except: pass

    print(f"[*] New domains to add: {len(new_rows)}")

    # append to enriched.csv
    with open(enriched, "a", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writerows(new_rows)

    print(f"[+] Done. Total rows: {len(classified) + len(new_rows)}")
    cats = Counter(r["category"] for r in new_rows)
    sevs = Counter(r["severity_label"] for r in new_rows)
    print("New cats:", dict(cats.most_common(10)))
    print("New sevs:", dict(sevs))


if __name__ == "__main__":
    main()
