"""
Phase 1 — Mass HTTP fingerprinting for NICENIC zone (343K domains).

Usage:
    python scan/phase1_http.py --input 3765_full.csv --out data/lambda_results.jsonl
    python scan/phase1_http.py --input 3765_full.csv --out data/lambda_results.jsonl --proxy socks5://user:pass@host:port
    python scan/phase1_http.py --resume  (skip already-done domains)

Output: JSONL, one JSON object per domain, append-safe (resume-friendly).
"""

import argparse
import asyncio
import csv
import json
import re
import sys
import time
from pathlib import Path

import aiohttp
from aiohttp_socks import ProxyConnector

# ── tunables ──────────────────────────────────────────────────────────────────
CONCURRENCY  = 600      # simultaneous connections
TIMEOUT_CONN = 5        # seconds
TIMEOUT_READ = 8
MAX_BODY     = 65_536   # bytes to read for title/form extraction
BATCH_LOG    = 2000     # log progress every N domains
USER_AGENTS  = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
]

# ── helpers ───────────────────────────────────────────────────────────────────
_title_re   = re.compile(r"<title[^>]*>(.*?)</title>", re.S | re.I)
_h1_re      = re.compile(r"<h1[^>]*>(.*?)</h1>", re.S | re.I)
_meta_re    = re.compile(r'<meta[^>]+name=["\']description["\'][^>]+content=["\'](.*?)["\']', re.I)
_form_re    = re.compile(r"<form[\s>]", re.I)
_input_re   = re.compile(r'<input[^>]+(?:name|placeholder)=["\']([^"\']{1,60})["\']', re.I)
_script_re  = re.compile(r"<script[^>]*>.*?</script>", re.S | re.I)
_tag_re     = re.compile(r"<[^>]+>")
_cf_re      = re.compile(r"cloudflare|cf-ray|cf_clearance|__cf_bm", re.I)
_captcha_re = re.compile(r"hcaptcha|recaptcha|turnstile", re.I)

THREAT_KEYWORDS = {
    "PHISHING":     ["login", "signin", "verify", "account", "password", "secure", "bank",
                     "paypal", "amazon", "apple", "microsoft", "netflix"],
    "CARDING":      ["carding", "dumps", "cvv", "fullz", "cc shop", "carder"],
    "CRYPTO":       ["crypto", "bitcoin", "ethereum", "wallet", "drainer", "airdrop",
                     "claim", "metamask", "connect wallet"],
    "GAMBLING":     ["casino", "bet", "poker", "slots", "bahis", "kumarhane", "bukme"],
    "ADULT":        ["xxx", "porn", "onlyfans", "nude", "escort", "adult"],
    "MALWARE":      ["download", "crack", "keygen", "serial", "patch", "torrent"],
    "SPAM":         ["pharmaceutical", "viagra", "cialis", "pharmacy"],
}


def strip_tags(html: str) -> str:
    html = _script_re.sub(" ", html)
    return _tag_re.sub(" ", html)


def extract_meta(body: str) -> dict:
    t  = (_title_re.search(body) or ["", ""])[1] if _title_re.search(body) else ""
    h1 = (_h1_re.search(body) or ["", ""])[1]   if _h1_re.search(body) else ""
    md = (_meta_re.search(body) or ["", ""])[1]  if _meta_re.search(body) else ""
    m  = _title_re.search(body)
    t  = strip_tags(m.group(1)).strip()[:200] if m else ""
    m  = _h1_re.search(body)
    h1 = strip_tags(m.group(1)).strip()[:200] if m else ""
    m  = _meta_re.search(body)
    md = strip_tags(m.group(1)).strip()[:300] if m else ""
    forms = len(_form_re.findall(body))
    inputs = ",".join(_input_re.findall(body))[:300]
    return {"title": t, "h1": h1, "meta_desc": md, "form_count": forms, "form_labels": inputs}


def detect_lang(body: str) -> str:
    m = re.search(r'<html[^>]+lang=["\']([a-z]{2,5})["\']', body, re.I)
    return m.group(1).lower() if m else ""


def naive_category(meta: dict, body: str) -> tuple[str, int]:
    text = (meta.get("title","") + " " + meta.get("h1","") + " " + body[:2000]).lower()
    for cat, kws in THREAT_KEYWORDS.items():
        if any(kw in text for kw in kws):
            return cat, 2
    return "UNKNOWN", 0


def severity_label(sev: int) -> str:
    return {0: "INFO", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}.get(sev, "INFO")


async def fetch_domain(session: aiohttp.ClientSession, domain: str, ua_idx: int) -> dict:
    result = {
        "domain": domain, "status_code": None, "final_url": "", "server": "",
        "server_fp": "", "is_cloudflare": False, "favicon_mmh3": "",
        "title": "", "h1": "", "meta_desc": "", "lang": "",
        "form_count": 0, "form_labels": "", "captcha": "",
        "body_text": "", "page_type": "UNKNOWN",
        "category": "UNKNOWN", "severity": 0, "severity_label": "INFO",
        "error": "",
    }
    url = f"https://{domain}"
    headers = {
        "User-Agent": USER_AGENTS[ua_idx % len(USER_AGENTS)],
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.9",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
    }
    try:
        async with session.get(url, headers=headers, allow_redirects=True,
                               max_redirects=10, ssl=False) as resp:
            result["status_code"] = resp.status
            result["final_url"]   = str(resp.url)
            result["server"]      = resp.headers.get("Server", "")

            srv_parts = sorted([
                resp.headers.get("Server",""),
                resp.headers.get("X-Powered-By",""),
                resp.headers.get("X-Generator",""),
            ])
            result["server_fp"] = "|".join(p for p in srv_parts if p)

            body = await resp.content.read(MAX_BODY)
            try:
                body_str = body.decode("utf-8", errors="replace")
            except Exception:
                body_str = ""

            result["is_cloudflare"] = bool(_cf_re.search(body_str) or
                                           "cloudflare" in result["server"].lower())
            cap = []
            if "hcaptcha" in body_str.lower():   cap.append("hcaptcha")
            if "recaptcha" in body_str.lower():  cap.append("recaptcha")
            if "turnstile" in body_str.lower():  cap.append("turnstile")
            result["captcha"] = ",".join(cap)

            meta = extract_meta(body_str)
            result.update(meta)
            result["lang"] = detect_lang(body_str)

            # page_type
            if resp.status in (301, 302, 307, 308):
                result["page_type"] = "REDIRECT"
            elif resp.status == 200:
                result["page_type"] = "LIVE"
            elif resp.status in (403, 429):
                result["page_type"] = "BLOCKED"
            elif resp.status >= 400:
                result["page_type"] = "ERROR"
            else:
                result["page_type"] = "OTHER"

            # naive category from HTTP data (Groq will refine later)
            cat, sev = naive_category(meta, body_str)
            result["category"]       = cat
            result["severity"]       = sev
            result["severity_label"] = severity_label(sev)

            # body snippet for groq
            plain = " ".join(strip_tags(body_str).split())[:500]
            result["body_text"] = plain

    except aiohttp.ClientConnectorError:
        result["status_code"] = None
        result["page_type"]   = "DEAD"
        result["category"]    = "DEAD"
        result["error"]       = "connect_error"
    except asyncio.TimeoutError:
        result["status_code"] = None
        result["page_type"]   = "TIMEOUT"
        result["category"]    = "DEAD"
        result["error"]       = "timeout"
    except Exception as e:
        result["error"] = str(e)[:100]
        result["page_type"] = "ERROR"
        result["category"]  = "ERROR"

    return result


async def run(domains: list[str], out_path: Path, proxy: str | None, resume_set: set[str]):
    done = 0
    skipped = 0
    sem = asyncio.Semaphore(CONCURRENCY)
    t0  = time.time()

    if proxy:
        connector = ProxyConnector.from_url(proxy, ssl=False, limit=CONCURRENCY + 50)
    else:
        connector = aiohttp.TCPConnector(ssl=False, limit=CONCURRENCY + 50)

    timeout = aiohttp.ClientTimeout(connect=TIMEOUT_CONN, sock_read=TIMEOUT_READ)

    with open(out_path, "a", encoding="utf-8") as fout:
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:

            async def bounded(domain: str, idx: int):
                nonlocal done, skipped
                if domain in resume_set:
                    skipped += 1
                    return
                async with sem:
                    res = await fetch_domain(session, domain, idx)
                    fout.write(json.dumps(res, ensure_ascii=False) + "\n")
                    fout.flush()
                    done += 1
                    if done % BATCH_LOG == 0:
                        elapsed = time.time() - t0
                        rate    = done / elapsed
                        remain  = (len(domains) - done - skipped) / rate if rate else 0
                        print(f"  [{done:>7}/{len(domains)}] {rate:.0f}/s  ETA {remain/60:.0f} min")

            tasks = [asyncio.create_task(bounded(d, i)) for i, d in enumerate(domains)]
            await asyncio.gather(*tasks)

    elapsed = time.time() - t0
    print(f"\n[+] Done: {done} scanned, {skipped} skipped. Total: {elapsed/60:.1f} min")


def load_domains(csv_path: Path) -> list[str]:
    csv.field_size_limit(1_000_000)
    domains = []
    with open(csv_path, newline="", encoding="utf-8-sig", errors="replace") as f:
        for row in csv.DictReader(f):
            domain = (row.get("url") or row.get("domain") or "").strip().lower()
            domain = re.sub(r"^https?://", "", domain).strip("/")
            if domain:
                domains.append(domain)
    return domains


def load_resume(jsonl_path: Path) -> set[str]:
    done = set()
    if not jsonl_path.exists():
        return done
    with open(jsonl_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                done.add(obj.get("domain",""))
            except Exception:
                pass
    print(f"  [resume] {len(done)} already done, skipping")
    return done


def main():
    global CONCURRENCY
    ap = argparse.ArgumentParser()
    ap.add_argument("--input",  default="3765_full.csv")
    ap.add_argument("--out",    default="data/lambda_results.jsonl")
    ap.add_argument("--proxy",  default="", help="socks5://user:pass@host:port")
    ap.add_argument("--resume", action="store_true", help="Skip already-done domains")
    ap.add_argument("--limit",  type=int, default=0, help="Scan only first N (0=all)")
    ap.add_argument("--concurrency", type=int, default=CONCURRENCY)
    args = ap.parse_args()

    CONCURRENCY = args.concurrency

    domains = load_domains(Path(args.input))
    if args.limit:
        domains = domains[:args.limit]
    print(f"[*] Loaded {len(domains)} domains from {args.input}")

    out_path   = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    resume_set = load_resume(out_path) if args.resume else set()

    proxy = args.proxy or None
    asyncio.run(run(domains, out_path, proxy, resume_set))


if __name__ == "__main__":
    main()
