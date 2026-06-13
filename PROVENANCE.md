# Provenance & Chain of Custody

Complete origin, transformation, and verification record for all artefacts in this repository.

---

## 1 · Investigation Lifecycle

```
┌────────────────────────────────────────────────────────────────────────────┐
│                    NICENIC Evidence Generation Pipeline                     │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│    [Registrar Zone List — 343,107 domains, June 2026]                      │
│           │                                                                │
│           ▼                                                                │
│    ┌──────────────────┐   Python 3.14 + aiohttp, 600 concurrent           │
│    │  Phase 1 — HTTP  │   Googlebot UA, timeout 5s/8s                     │
│    │  Fingerprint     │   output: lambda_results.jsonl                    │
│    └──────────────────┘                                                   │
│           │                                                                │
│           ▼                                                                │
│    ┌──────────────────┐   Playwright + stealth v2, headless Chromium      │
│    │  Phase 2 — Render│   Per-domain isolated context, form analysis      │
│    │  + Screenshots   │   2captcha (hCaptcha/reCAPTCHA/Turnstile)         │
│    └──────────────────┘   output: screenshots/*.jpg                       │
│           │                                                                │
│           ▼                                                                │
│    ┌──────────────────┐   Llama 3.1 8B Instant (Groq API)                 │
│    │  Phase 3 — AI    │   Batch classification + descriptions             │
│    │  Classification  │   output: enriched.csv                            │
│    └──────────────────┘                                                   │
│           │                                                                │
│           ▼                                                                │
│    ┌──────────────────┐   ipinfo.io API                                   │
│    │  Phase 4 — GeoIP │   Country code + ASN per responding IP            │
│    └──────────────────┘                                                   │
│           │                                                                │
│           ▼                                                                │
│    ┌──────────────────┐   Redaction pass:                                 │
│    │  Phase 5 — PII   │   • scan-server IP address                        │
│    │  Redaction       │   • local filesystem paths                         │
│    │                  │   • API tokens (Groq, 2captcha, proxy, ipinfo)    │
│    └──────────────────┘                                                   │
│           │                                                                │
│           ▼                                                                │
│    ┌──────────────────┐   enriched.csv → data.json, ioc/*.txt             │
│    │  Phase 6 — Build │   SHA-256 screenshot manifest                     │
│    │  & Publication   │   Compressed pkg/raw_data/*.gz                    │
│    └──────────────────┘                                                   │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 2 · Artefact Inventory

| File | Description |
|---|---|
| `data/enriched.csv` | Canonical dataset — all domains with classification, IPs, GeoIP, AI descriptions |
| `data/high_severity.csv` | HIGH-only filtered subset |
| `ioc/domains_high.txt` | Blocklist — HIGH severity domains |
| `ioc/domains_all_malicious.txt` | Blocklist — HIGH + MEDIUM domains |
| `ioc/indicators.csv` | SIEM-ready indicators (domain, ip, server_fp, favicon_mmh3, category, severity) |
| `evidence/HASHES.txt` | SHA-256 manifest of all screenshots |
| `docs/data.json` | Slim per-domain dataset for GitHub Pages report |
| `pkg/raw_data/lambda_results.jsonl.gz` | Compressed Phase 1 raw output |
| `pkg/raw_data/enriched.csv.gz` | Compressed enriched dataset |

---

## 3 · Screenshot Capture Parameters

| Parameter | Value |
|---|---|
| Engine | Playwright 1.40 + headless Chromium |
| Stealth | `playwright-stealth` v2 |
| Viewport | 1280 × 800 |
| Settle delay | 2.5 s post-`domcontentloaded`; +5 s on Cloudflare JS challenge |
| Captcha solving | 2captcha — hCaptcha, reCAPTCHA v2/v3, Cloudflare Turnstile |
| Proxy pool | 2,600+ SOCKS5 exits, round-robin |
| Browser context | Isolated per domain |
| Format | JPEG 80% quality, max 1280 px wide |
| Naming | `<domain>.jpg` — 1:1 mapping with `data/enriched.csv` domain column |

---

## 4 · Redaction Disclosure

| Class | Pattern | Replacement |
|---|---|---|
| Scan-server IPv4 | Internal scan address | `[REDACTED-SCAN-IP]` |
| Local filesystem paths | Scanner working directories | (removed) |
| Groq API tokens | Provider API keys | `[REDACTED-GROQ-KEY]` |
| 2captcha API token | Provider API key | `[REDACTED-2CAPTCHA]` |
| Proxy provider tokens | Provider API keys | `[REDACTED-PROXY-TOKEN]` |
| ipinfo.io tokens | Provider API keys | `[REDACTED-IPINFO-TOKEN]` |

---

## 5 · Verification

```bash
# Regenerate data.json from canonical source
python docs/build_datajson.py

# Screenshots not published in repo (size constraints)

# Verify SHA-256 manifest
sha256sum -c SHA256SUMS.txt

# Verify SSH signature on SHA256SUMS.txt
ssh-keygen -Y verify -f allowed_signers -I phishdestroy@phishdestroy.io \
    -n evidence -s SHA256SUMS.txt.sig < SHA256SUMS.txt
# Expected: Good "evidence" signature for phishdestroy@phishdestroy.io with ED25519 key SHA256:...
```

---

## 6 · Reproducibility

| Component | Version |
|---|---|
| Python | 3.14 (local scan) |
| aiohttp | ≥ 3.13 |
| Playwright | 1.40 |
| playwright-stealth | v2 |
| Groq SDK | latest at scan time |
| ipinfo.io | API v1 |

Scan window: **June 2026.** Data reflects NICENIC zone state at time of capture.

---

## 7 · Contact

Technical or evidentiary questions: [phishdestroy.io](https://phishdestroy.io)

---

*PhishDestroy Research · TLP:CLEAR · MIT License · June 2026*
