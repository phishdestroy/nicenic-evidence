"""
AWS Lambda handler — HTTP fingerprinting + favicon MurmurHash3 for NICENIC zone.
"""

import asyncio
import hashlib
import json
import re
import struct

import aiohttp

CONCURRENCY  = 80
TIMEOUT_CONN = 12
TIMEOUT_READ = 18
MAX_BODY     = 65_536
MAX_FAV      = 65_536

UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"

_title_re   = re.compile(r"<title[^>]*>(.*?)</title>", re.S | re.I)
_h1_re      = re.compile(r"<h1[^>]*>(.*?)</h1>", re.S | re.I)
_meta_re    = re.compile(r'<meta[^>]+name=["\']description["\'][^>]+content=["\'](.*?)["\']', re.I)
_form_re    = re.compile(r"<form[\s>]", re.I)
_input_re   = re.compile(r'<input[^>]+(?:name|placeholder)=["\']([^"\']{1,60})["\']', re.I)
_script_re  = re.compile(r"<script[^>]*>.*?</script>", re.S | re.I)
_tag_re     = re.compile(r"<[^>]+>")
_cf_re      = re.compile(r"cloudflare|cf-ray|cf_clearance|__cf_bm", re.I)
_fav_link   = re.compile(r'<link[^>]+rel=["\'][^"\']*icon[^"\']*["\'][^>]+href=["\']([^"\']+)["\']', re.I)

THREAT_KW = {
    "PHISHING_FINANCE": ["login","signin","verify","account","password","bank","paypal","amazon","apple","microsoft","netflix","wallet","chase","wellsfargo"],
    "CARDING":          ["carding","dumps","cvv","fullz","cc shop","carder","shop"],
    "CRYPTO_DRAINER":   ["drainer","airdrop","claim","metamask","connect wallet","web3","nft","mint"],
    "CRYPTO_EXCHANGE":  ["crypto","bitcoin","ethereum","trade","exchange","invest","profit"],
    "GAMBLING":         ["casino","bet","poker","slots","bahis","kumarhane","sportsbook","jackpot"],
    "ADULT":            ["xxx","porn","onlyfans","nude","escort","adult","cam","sex"],
    "MALWARE":          ["download","crack","keygen","serial","patch","loader","stealer"],
    "SPAM_PHARMA":      ["viagra","cialis","pharmacy","pills","cheap meds"],
}


# ── MurmurHash3 (32-bit, Shodan-compatible) ───────────────────────────────────
def _mmh3_32(data: bytes, seed: int = 0) -> int:
    c1, c2, r1, r2, m, n = 0xcc9e2d51, 0x1b873593, 15, 13, 5, 0xe6546b64
    length = len(data)
    h = seed
    for chunk_start in range(0, length - length % 4, 4):
        k = struct.unpack('<I', data[chunk_start:chunk_start+4])[0]
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << r1) | (k >> (32 - r1))) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = ((h << r2) | (h >> (32 - r2))) & 0xFFFFFFFF
        h = (h * m + n) & 0xFFFFFFFF
    tail = data[length - length % 4:]
    k = 0
    for i, byte in enumerate(reversed(tail)):
        k ^= byte << (8 * (len(tail) - 1 - i))
    if tail:
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << r1) | (k >> (32 - r1))) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
    h ^= length
    h ^= (h >> 16)
    h = (h * 0x85ebca6b) & 0xFFFFFFFF
    h ^= (h >> 13)
    h = (h * 0xc2b2ae35) & 0xFFFFFFFF
    h ^= (h >> 16)
    return struct.unpack('<i', struct.pack('<I', h))[0]  # signed


def mmh3_favicon(data: bytes) -> int:
    import base64
    b64 = base64.encodebytes(data)
    return _mmh3_32(b64)


# ── helpers ───────────────────────────────────────────────────────────────────
def strip_tags(html: str) -> str:
    return _tag_re.sub(" ", _script_re.sub(" ", html))


def extract(body: str) -> dict:
    m = _title_re.search(body)
    title = strip_tags(m.group(1)).strip()[:200] if m else ""
    m = _h1_re.search(body)
    h1 = strip_tags(m.group(1)).strip()[:200] if m else ""
    m = _meta_re.search(body)
    md = strip_tags(m.group(1)).strip()[:300] if m else ""
    forms  = len(_form_re.findall(body))
    inputs = ",".join(_input_re.findall(body))[:300]
    m = re.search(r'<html[^>]+lang=["\']([a-z]{2,5})["\']', body, re.I)
    lang = m.group(1).lower() if m else ""
    # favicon link from HTML
    m = _fav_link.search(body)
    fav_href = m.group(1) if m else ""
    return {"title": title, "h1": h1, "meta_desc": md,
            "form_count": forms, "form_labels": inputs,
            "lang": lang, "fav_href": fav_href}


def naive_cat(meta: dict, body: str) -> tuple[str, int]:
    text = (meta.get("title","") + " " + meta.get("h1","") + " " + body[:2000]).lower()
    for cat, kws in THREAT_KW.items():
        if any(kw in text for kw in kws):
            return cat, 2
    return "UNKNOWN", 0


async def fetch_favicon(session: aiohttp.ClientSession, domain: str, fav_href: str) -> int:
    candidates = []
    if fav_href:
        if fav_href.startswith("http"):
            candidates.append(fav_href)
        elif fav_href.startswith("//"):
            candidates.append("https:" + fav_href)
        elif fav_href.startswith("/"):
            candidates.append(f"https://{domain}{fav_href}")
        else:
            candidates.append(f"https://{domain}/{fav_href}")
    candidates.append(f"https://{domain}/favicon.ico")

    hdrs = {"User-Agent": UA}
    for url in candidates:
        try:
            async with session.get(url, headers=hdrs, ssl=False,
                                   allow_redirects=True, max_redirects=5) as resp:
                if resp.status == 200:
                    data = await resp.content.read(MAX_FAV)
                    if data and len(data) > 20:
                        return mmh3_favicon(data)
        except Exception:
            continue
    return 0


async def fetch_one(session: aiohttp.ClientSession, domain: str) -> dict:
    r = {"domain": domain, "status_code": None, "final_url": "", "server": "",
         "server_fp": "", "is_cloudflare": False, "favicon_mmh3": "",
         "captcha": "", "title": "", "h1": "", "meta_desc": "", "lang": "",
         "form_count": 0, "form_labels": "", "body_text": "",
         "page_type": "UNKNOWN", "category": "UNKNOWN", "severity": 0,
         "severity_label": "INFO", "error": ""}
    try:
        hdrs = {"User-Agent": UA, "Accept": "text/html,*/*;q=0.9",
                "Accept-Language": "en-US,en;q=0.9"}
        async with session.get(f"https://{domain}", headers=hdrs,
                               allow_redirects=True, max_redirects=10, ssl=False) as resp:
            r["status_code"] = resp.status
            r["final_url"]   = str(resp.url)
            r["server"]      = resp.headers.get("Server", "")
            parts = sorted([resp.headers.get("Server",""),
                            resp.headers.get("X-Powered-By",""),
                            resp.headers.get("X-Generator","")])
            r["server_fp"] = "|".join(p for p in parts if p)

            body = await resp.content.read(MAX_BODY)
            bs   = body.decode("utf-8", errors="replace")

            r["is_cloudflare"] = bool(_cf_re.search(bs) or "cloudflare" in r["server"].lower())
            cap = []
            if "hcaptcha"  in bs.lower(): cap.append("hcaptcha")
            if "recaptcha" in bs.lower(): cap.append("recaptcha")
            if "turnstile" in bs.lower(): cap.append("turnstile")
            r["captcha"] = ",".join(cap)

            meta = extract(bs)
            fav_href = meta.pop("fav_href", "")
            r.update(meta)

            # favicon
            fav_hash = await fetch_favicon(session, domain, fav_href)
            r["favicon_mmh3"] = str(fav_hash) if fav_hash else ""

            pt = ("LIVE"    if resp.status == 200 else
                  "BLOCKED" if resp.status in (403, 429) else
                  "REDIRECT"if resp.status in (301,302,307,308) else
                  "OTHER")
            r["page_type"] = pt
            cat, sev = naive_cat(meta, bs)
            r["category"]      = cat
            r["severity"]      = sev
            r["severity_label"]= {0:"INFO",1:"LOW",2:"MEDIUM",3:"HIGH",4:"CRITICAL"}.get(sev,"INFO")
            r["body_text"]     = " ".join(strip_tags(bs).split())[:500]

    except aiohttp.ClientConnectorError:
        r["page_type"] = "DEAD"; r["category"] = "DEAD"; r["error"] = "connect"
    except asyncio.TimeoutError:
        r["page_type"] = "TIMEOUT"; r["category"] = "DEAD"; r["error"] = "timeout"
    except Exception as e:
        r["page_type"] = "ERROR"; r["category"] = "ERROR"; r["error"] = str(e)[:80]
    return r


async def scan_batch(domains: list[str]) -> list[dict]:
    sem  = asyncio.Semaphore(CONCURRENCY)
    conn = aiohttp.TCPConnector(ssl=False, limit=CONCURRENCY + 10)
    to   = aiohttp.ClientTimeout(connect=TIMEOUT_CONN, sock_read=TIMEOUT_READ)
    async with aiohttp.ClientSession(connector=conn, timeout=to) as session:
        async def bounded(d):
            async with sem:
                return await fetch_one(session, d)
        return await asyncio.gather(*[asyncio.create_task(bounded(d)) for d in domains])


def lambda_handler(event, context):
    domains = event.get("domains", [])
    if not domains:
        return {"statusCode": 400, "body": "no domains"}
    results = asyncio.run(scan_batch(domains))
    return {"statusCode": 200, "batch_id": event.get("batch_id", 0),
            "count": len(results), "results": results}


if __name__ == "__main__":
    test = ["2krn.academy", "google.com", "amazon.com"]
    res  = asyncio.run(scan_batch(test))
    for r in res:
        print(r["domain"], r["status_code"], r["favicon_mmh3"], r["title"][:40])
