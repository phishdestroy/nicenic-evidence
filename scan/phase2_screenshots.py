"""
Phase 2 — Browser screenshots for HIGH/MEDIUM domains.
Uses Playwright + stealth, 2captcha for CAPTCHA bypass, SOCKS5 proxy pool.

Usage:
    pip install playwright playwright-stealth twocaptcha
    playwright install chromium

    python scan/phase2_screenshots.py --enriched data/enriched.csv --proxy socks5://... --captcha-key KEY
    python scan/phase2_screenshots.py --enriched data/enriched.csv --proxy socks5://... --captcha-key KEY --resume
    python scan/phase2_screenshots.py --enriched data/enriched.csv --no-captcha --workers 10  (no captcha solving)
"""

import argparse
import asyncio
import csv
import json
import sys
from pathlib import Path

try:
    from playwright.async_api import async_playwright, Page, BrowserContext
except ImportError:
    print("[!] pip install playwright && playwright install chromium")
    sys.exit(1)

try:
    from playwright_stealth import Stealth
    HAS_STEALTH = True
except ImportError:
    try:
        from playwright_stealth import stealth_async
        HAS_STEALTH = True
        Stealth = None
    except ImportError:
        HAS_STEALTH = False
        Stealth = None
        print("[warn] playwright-stealth not installed — running without stealth")

try:
    from twocaptcha import TwoCaptcha
    HAS_2CAP = True
except ImportError:
    HAS_2CAP = False

# ── config ────────────────────────────────────────────────────────────────────
WORKERS       = 5        # parallel browser contexts (RAM-limited)
VIEWPORT_W    = 1280
VIEWPORT_H    = 800
SETTLE_SECS   = 2.5      # wait after load
CF_EXTRA_SECS = 5        # extra wait for CF JS challenge
MAX_RETRIES   = 2
SS_DIR        = Path("docs/screenshots")

TARGET_CATEGORIES = {
    "PHISHING_FINANCE", "PHISHING_BRAND", "CARDING", "CRYPTO_DRAINER",
    "CRYPTO_EXCHANGE", "GAMBLING", "ADULT", "MALWARE", "SPAM_PHARMA",
    "UNKNOWN",  # include unknowns so we can visually classify
}
TARGET_SEVERITY = 2  # include severity >= MEDIUM


def load_targets(enriched_csv: Path, resume_set: set[str]) -> list[dict]:
    rows = []
    csv.field_size_limit(10_000_000)
    with open(enriched_csv, newline="", encoding="utf-8-sig", errors="replace") as f:
        for row in csv.DictReader(f):
            domain = row.get("domain","").strip()
            if not domain or domain in resume_set:
                continue
            sev = int(row.get("severity") or 0)
            cat = row.get("category","")
            pt  = row.get("page_type","")
            if pt in ("DEAD","TIMEOUT") and sev == 0:
                continue
            if cat in TARGET_CATEGORIES or sev >= TARGET_SEVERITY:
                rows.append({"domain": domain, "is_cloudflare": row.get("is_cloudflare","").lower() in ("true","1","yes")})
    return rows


def load_resume(ss_dir: Path) -> set[str]:
    done = set()
    if ss_dir.exists():
        for f in ss_dir.glob("*.jpg"):
            done.add(f.stem)
        for f in ss_dir.glob("*.png"):
            done.add(f.stem)
    print(f"  [resume] {len(done)} screenshots already done")
    return done


async def solve_captcha_cf(solver: "TwoCaptcha", page: Page, domain: str) -> bool:
    """Try to solve hCaptcha / Turnstile / reCAPTCHA via 2captcha."""
    try:
        content = await page.content()
        if "hcaptcha" in content.lower():
            site_key_match = __import__("re").search(r'data-sitekey=["\']([^"\']+)["\']', content)
            if site_key_match:
                token = solver.hcaptcha(
                    sitekey=site_key_match.group(1),
                    url=f"https://{domain}"
                )
                if token:
                    await page.evaluate(f"document.querySelector('[name=\"h-captcha-response\"]').value = '{token['code']}'")
                    await page.evaluate("document.querySelector('[data-callback]')?.click() || document.forms[0]?.submit()")
                    await page.wait_for_load_state("domcontentloaded", timeout=15000)
                    return True
    except Exception as e:
        print(f"  [captcha] {domain}: {e}")
    return False


async def screenshot_domain(
    context: BrowserContext,
    domain: str,
    is_cf: bool,
    solver,
    ss_dir: Path,
) -> str:
    """Returns path to screenshot or empty string."""
    url  = f"https://{domain}"
    page = await context.new_page()
    try:
        if HAS_STEALTH and Stealth:
            await Stealth().apply_stealth_async(page)
        elif HAS_STEALTH:
            await stealth_async(page)
        await page.set_viewport_size({"width": VIEWPORT_W, "height": VIEWPORT_H})

        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=20000)
        except Exception:
            try:
                await page.goto(f"http://{domain}", wait_until="domcontentloaded", timeout=15000)
            except Exception:
                return ""

        await page.wait_for_timeout(int(SETTLE_SECS * 1000))

        if is_cf:
            await page.wait_for_timeout(int(CF_EXTRA_SECS * 1000))
            if solver:
                await solve_captcha_cf(solver, page, domain)
                await page.wait_for_timeout(2000)

        out_path = ss_dir / f"{domain}.jpg"
        await page.screenshot(path=str(out_path), full_page=False, type="jpeg", quality=80)
        return str(out_path)

    except Exception as e:
        print(f"  [ss] {domain}: {e}")
        return ""
    finally:
        await page.close()


async def worker(
    queue: asyncio.Queue,
    playwright,
    proxy: str | None,
    captcha_key: str | None,
    ss_dir: Path,
    counter: dict,
):
    solver = TwoCaptcha(captcha_key) if (captcha_key and HAS_2CAP) else None

    launch_args = ["--no-sandbox", "--disable-dev-shm-usage"]
    proxy_cfg   = {"server": proxy} if proxy else None

    browser = await playwright.chromium.launch(headless=True, args=launch_args, proxy=proxy_cfg)

    while True:
        try:
            item = queue.get_nowait()
        except asyncio.QueueEmpty:
            break

        domain = item["domain"]
        is_cf  = item.get("is_cloudflare", False)

        context = await browser.new_context(
            viewport={"width": VIEWPORT_W, "height": VIEWPORT_H},
            java_script_enabled=True,
            ignore_https_errors=True,
        )
        try:
            path = await screenshot_domain(context, domain, is_cf, solver, ss_dir)
            if path:
                counter["done"] += 1
            else:
                counter["failed"] += 1
        except Exception as e:
            print(f"  [worker] {domain}: {e}")
            counter["failed"] += 1
        finally:
            await context.close()

        queue.task_done()

        if (counter["done"] + counter["failed"]) % 100 == 0:
            total = counter["total"]
            done  = counter["done"] + counter["failed"]
            print(f"  [{done:>6}/{total}] screenshots: {counter['done']} ok, {counter['failed']} failed")

    await browser.close()


async def run(targets: list[dict], proxy: str | None, captcha_key: str | None, ss_dir: Path):
    ss_dir.mkdir(parents=True, exist_ok=True)

    queue   = asyncio.Queue()
    counter = {"done": 0, "failed": 0, "total": len(targets)}

    for t in targets:
        await queue.put(t)

    print(f"[*] {len(targets)} domains to screenshot, {WORKERS} workers")

    async with async_playwright() as pw:
        tasks = [
            asyncio.create_task(worker(queue, pw, proxy, captcha_key, ss_dir, counter))
            for _ in range(WORKERS)
        ]
        await asyncio.gather(*tasks)

    print(f"\n[+] Screenshots: {counter['done']} ok, {counter['failed']} failed")


def main():
    global WORKERS
    ap = argparse.ArgumentParser()
    ap.add_argument("--enriched",    default="data/enriched.csv")
    ap.add_argument("--proxy",       default="", help="socks5://user:pass@host:port")
    ap.add_argument("--captcha-key", default="", help="2captcha API key")
    ap.add_argument("--no-captcha",  action="store_true")
    ap.add_argument("--resume",      action="store_true")
    ap.add_argument("--workers",     type=int, default=WORKERS)
    ap.add_argument("--limit",       type=int, default=0)
    args = ap.parse_args()

    WORKERS = args.workers

    resume_set = load_resume(SS_DIR) if args.resume else set()
    targets    = load_targets(Path(args.enriched), resume_set)
    if args.limit:
        targets = targets[:args.limit]

    print(f"[*] Targeting {len(targets)} HIGH/MEDIUM/UNKNOWN domains for screenshots")

    proxy       = args.proxy or None
    captcha_key = None if args.no_captcha else (args.captcha_key or None)

    asyncio.run(run(targets, proxy, captcha_key, SS_DIR))


if __name__ == "__main__":
    main()
