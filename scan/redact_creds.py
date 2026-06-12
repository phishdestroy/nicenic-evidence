"""
Redacts credentials and sensitive data from all published files.
Run BEFORE committing to git.

Patterns redacted:
  - Scan-server IP (set via --scan-ip)
  -  or  filesystem paths
  - Groq API keys (gsk_...)
  - 2captcha keys (40-char hex)
  - ipinfo.io tokens (15-char hex)
  - Proxy tokens (UUID-like)

Usage:
    python scan/redact_creds.py --scan-ip 1.2.3.4
    python scan/redact_creds.py --scan-ip 1.2.3.4 --dry-run
"""

import argparse
import re
from pathlib import Path

TARGETS = [
    "data/enriched.csv",
    "data/high_severity.csv",
    "docs/data.json",
    "docs/index.html",
    "docs/domains.html",
]
EXTS = {".csv", ".json", ".html", ".md", ".txt", ".py", ".jsonl"}


def build_patterns(scan_ip: str) -> list[tuple[re.Pattern, str]]:
    pats = [
        (re.compile(r"gsk_[A-Za-z0-9]{20,}"),    "[REDACTED-GROQ-KEY]"),
        (re.compile(r"xai-[A-Za-z0-9]{40,}"),    "[REDACTED-XAI-KEY]"),
        (re.compile(r"[0-9a-f]{32}(?=[,\s\"']|$)"), "[REDACTED-2CAPTCHA]"),
        (re.compile(r"[0-9a-f]{15}(?=[,\s\"']|$)"), "[REDACTED-IPINFO-TOKEN]"),
        (re.compile(r""',]+"),          ""),
        (re.compile(r""',]+"),          ""),
    ]
    if scan_ip:
        pats.insert(0, (re.compile(re.escape(scan_ip)), "[REDACTED-SCAN-IP]"))
    return pats


def redact_file(path: Path, patterns: list, dry_run: bool) -> int:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return 0
    orig  = text
    count = 0
    for pat, replacement in patterns:
        new, n = pat.subn(replacement, text)
        count += n
        text   = new
    if count and not dry_run:
        path.write_text(text, encoding="utf-8")
    return count


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scan-ip",  default="", help="Scan server IP to redact")
    ap.add_argument("--dry-run",  action="store_true")
    ap.add_argument("--dir",      default=".", help="Root directory to scan")
    args = ap.parse_args()

    patterns = build_patterns(args.scan_ip)
    root     = Path(args.dir)
    total    = 0

    for ext in EXTS:
        for path in root.rglob(f"*{ext}"):
            if ".git" in path.parts or "node_modules" in path.parts:
                continue
            n = redact_file(path, patterns, args.dry_run)
            if n:
                print(f"  {path}  ({n} replacements)")
                total += n

    action = "Would replace" if args.dry_run else "Replaced"
    print(f"\n[+] {action} {total} occurrences across all files")


if __name__ == "__main__":
    main()
