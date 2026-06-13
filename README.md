<div align="center">

<img src="docs/assets/hero.jpg" alt="NICENIC Zone Scan — PhishDestroy Investigation" width="100%">

<br>

[![Domains](https://img.shields.io/badge/Domains_Scanned-343%2C107-red?style=for-the-badge&logo=databricks&logoColor=white)](https://phishdestroy.github.io/nicenic-evidence/)
[![Registrar](https://img.shields.io/badge/IANA_%233765-NICENIC-orange?style=for-the-badge&logo=icann&logoColor=white)](https://www.iana.org/assignments/registrar-ids/registrar-ids.xhtml)
[![TLP](https://img.shields.io/badge/TLP-CLEAR-brightgreen?style=for-the-badge)](https://www.cisa.gov/tlp)
[![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)
[![Pages](https://img.shields.io/badge/Live_Report-GitHub_Pages-purple?style=for-the-badge&logo=github)](https://phishdestroy.github.io/nicenic-evidence/)

<br>

# NICENIC Zone Scan — Complete Registrar Investigation

**Phase I · NICENIC INTERNATIONAL GROUP CO., LIMITED · IANA #3765**

*Complete-zone scan of a Chinese registrar enabling industrial-scale domain abuse*

</div>

---

## Table of Contents

| Section | |
|---|---|
| [Background](#background) | Why NICENIC, methodology overview |
| [Subject](#subject) | Registrar profile |
| [Scope](#scope) | Zone composition |
| [Methodology](#methodology) | Technical pipeline |
| [Findings](#headline-findings) | Key statistics |
| [Operator Clusters](#operator-clusters) | Infrastructure groupings |
| [Evidence Archive](#evidence-archive) | Files and hashes |
| [IOC Feed](#ioc-feed) | Blocklist downloads |
| [Enforcement Posture](#enforcement-posture) | Who needs to act |
| [Repository Structure](#repository-structure) | File layout |

---

## Background

NICENIC INTERNATIONAL GROUP CO., LIMITED (IANA registrar #3765) is a Chinese domain registrar with a long-documented track record of slow abuse response, permissive registration policies, and infrastructure that is systematically exploited by phishing operators, carding shops, crypto drainers, illegal gambling networks, and malware distributors.

While NICENIC holds significantly more domains than the average registrar under investigation, the scale is itself the signal: fast, cheap, anonymous registration at volume is the product. The registrar's zone composition reflects a portfolio optimised for abuse enablement rather than legitimate hosting.

This investigation enumerates every domain in NICENIC's zone, classifies content using AI-assisted analysis and threat-intelligence cross-referencing, and publishes structured evidence for enforcement, blocklist, and SIEM use.

**Pipeline:**

```
[NICENIC Zone File — 343,107 domains]
         │
         ▼
┌─────────────────┐   aiohttp, 600 concurrent, Googlebot UA
│ Phase 1 — HTTP  │   Output: lambda_results.jsonl
│ Fingerprint     │
└─────────────────┘
         │
         ▼
┌─────────────────┐   Playwright + stealth v2, isolated context/domain
│ Phase 2 — Render│   SOCKS5 pool + 2captcha (hCaptcha/Turnstile/reCAPTCHA)
│ + Screenshots   │   Output: deep_results.jsonl, screenshots/*.jpg
└─────────────────┘
         │
         ▼
┌─────────────────┐   Llama 3.1 (Groq) for content classification
│ Phase 3 — AI    │   Rule-based pre-filter + Groq for ambiguous cases
│ Classification  │   Output: enriched.csv categories + descriptions
└─────────────────┘
         │
         ▼
┌─────────────────┐   ipinfo.io (country + ASN per IP)
│ Phase 4 — GeoIP │   Output: ip_country, ip_asn fields
└─────────────────┘
         │
         ▼
┌─────────────────┐   Redaction: scan-server IP, API keys, local paths
│ Phase 5 — PII   │   Output: clean enriched.csv, data.json, IOC feeds
│ Redaction       │
└─────────────────┘
```

---

## Subject

| Field | Value |
|---|---|
| **Registrar name** | NICENIC INTERNATIONAL GROUP CO., LIMITED |
| **IANA ID** | #3765 |
| **Jurisdiction** | China |
| **WHOIS server** | `whois.nicenic.net` |
| **Abuse contact** | abuse@nicenic.net |
| **Zone size** | 343,107 domains (scan date: June 2026) |
| **Supported TLDs** | Generic TLDs (gTLD) — `.com`, `.net`, `.org`, `.xyz`, `.top`, `.shop`, `.app`, `.academy`, and 100+ more |
| **ICANN accreditation** | Active |

---

## Scope

This investigation covers the **complete zone** of all domains registered under NICENIC (IANA #3765) as enumerated from public zone data in June 2026. Every domain — alive or dead — is included.

> **Note:** Screenshots and deep-render data were collected only for HIGH and MEDIUM severity domains (estimated 10–25% of zone) to constrain storage and runtime. Dead domains are enumerated and classified but not rendered.

---

## Methodology

<details>
<summary><strong>Phase 1 — HTTP Fingerprinting</strong></summary>

- **Tool:** Python 3.14 + `aiohttp`, 600 concurrent connections
- **User-Agent:** Googlebot 2.1 (bypass naive bot-blocks)
- **Timeout:** 5s connect, 8s read
- **Extracted:** HTTP status, final URL, server headers, title, H1, meta description, form fields, body snippet (first 64 KB)
- **Cloudflare detection:** `cf-ray` / `__cf_bm` presence in headers + body
- **Captcha detection:** hCaptcha / reCAPTCHA / Turnstile keyword matching
- **Output:** `data/lambda_results.jsonl` — one JSON object per domain

</details>

<details>
<summary><strong>Phase 2 — Browser Render & Screenshots</strong></summary>

- **Engine:** Playwright 1.40 + headless Chromium
- **Stealth:** `playwright-stealth` v2
- **Viewport:** 1280 × 800
- **Settle delay:** 2.5 s post-`domcontentloaded`; +5 s on Cloudflare JS challenge
- **Captcha solving:** 2captcha — hCaptcha, reCAPTCHA v2/v3, Cloudflare Turnstile
- **Proxy pool:** 2,600+ SOCKS5 exits, round-robin per domain
- **Output:** `docs/screenshots/<domain>.jpg` (JPEG 80%, max 1280 px wide)

</details>

<details>
<summary><strong>Phase 3 — AI Classification</strong></summary>

- **Model:** Llama 3.1 8B Instant (Groq API)
- **Batch size:** 20 domains per Groq call
- **Categories:** `PHISHING_FINANCE`, `PHISHING_BRAND`, `CARDING`, `CRYPTO_DRAINER`, `CRYPTO_EXCHANGE`, `GAMBLING`, `ADULT`, `MALWARE`, `SPAM_PHARMA`, `SPAM_SEO`, `PARKING`, `DEAD`, `LEGITIMATE`, `UNKNOWN`
- **Severity map:** CRITICAL (4) — phishing/carding/malware; HIGH (3) — crypto/gambling; MEDIUM (2) — adult/spam-seo; LOW (1) — unknown; INFO (0) — parking/dead/legitimate
- **Pre-filter:** Rule-based keyword matching assigns naive category before Groq; Groq refines uncertain cases

</details>

<details>
<summary><strong>Phase 4 — GeoIP Enrichment</strong></summary>

- **Provider:** ipinfo.io API
- **Fields added:** `ip_country`, `ip_asn`
- **Coverage:** All live domains with resolved IPs

</details>

---

## Headline Findings

| Metric | Value |
|---|---|
| Total domains in zone | 343,107 |
| Alive (HTTP 200/3xx) | **37,844** (11%) |
| Dead / Parked / Error | 305,263 (89%) |
| CRITICAL severity | 10,377 |
| HIGH severity | 7,928 |
| MEDIUM severity | 622 |
| Malicious (CRITICAL+HIGH+MEDIUM) | **18,927** (50.0% of alive) |
| Behind Cloudflare | 63,190 (83% of alive) |
| Screenshots captured | 37,844 alive domains — not published in repo (size) |
| Operator clusters identified | **2,939** |

---

## Operator Clusters

**2,939 operator clusters** identified via favicon MurmurHash3 + server fingerprint combination. Clusters of 3+ domains sharing identical infrastructure are surfaced as likely operator groups.

Notable clusters:

| Cluster | Domains | Description |
|---|---|---|
| Favicon `1921725183` | 1,043 | Single phishing operator — uniform credential-harvesting kit |
| IP `188.114.96.3` | 13,293 | Cloudflare anycast — bulk domain parking on shared exit |
| Carding infra | 544 CC shops | 83% behind Cloudflare DDoS protection |

Full cluster data: [`data/clusters.json`](data/clusters.json) — includes favicon hash, server fingerprint, domain list, and category distribution per cluster.

---

## Evidence Archive

| File | Rows | Description |
|---|---|---|
| `data/enriched.csv` | 86,114 | Full enriched dataset — all classified domains with category, severity, IPs, country, AI descriptions |
| `data/high_severity.csv` | 20,480 | CRITICAL+HIGH filtered subset |
| `data/dead_domains.csv` | — | Dead / parked / error domain enumeration |
| `data/clusters.json` | 2,939 | Operator cluster map — favicon hash + server fingerprint groupings |
| `ioc/domains_high.txt` | 18,305 | Production blocklist — CRITICAL+HIGH domains |
| `ioc/domains_all_malicious.txt` | 18,927 | Production blocklist — CRITICAL+HIGH+MEDIUM |
| `ioc/indicators.csv` | 18,927 | SIEM-ready: domain, ip, server_fp, favicon_mmh3, category, severity |
| `docs/data.json` | — | Slim per-domain dataset for the live report |
| `pkg/raw_data/lambda_results.jsonl.gz` | — | Phase 1 raw HTTP fingerprint output (compressed) |
| `pkg/raw_data/enriched.csv.gz` | — | Compressed enriched dataset |
| `pkg/raw_data/high_severity.csv.gz` | — | Compressed CRITICAL+HIGH subset |
| `SHA256SUMS.txt` | — | SHA-256 checksums of all published data files |

---

## IOC Feed

```bash
# HIGH severity domains (blocklist)
https://raw.githubusercontent.com/phishdestroy/nicenic-evidence/main/ioc/domains_high.txt

# HIGH + MEDIUM domains
https://raw.githubusercontent.com/phishdestroy/nicenic-evidence/main/ioc/domains_all_malicious.txt

# SIEM indicators (CSV)
https://raw.githubusercontent.com/phishdestroy/nicenic-evidence/main/ioc/indicators.csv
```

---

## Enforcement Posture

NICENIC operates under Chinese jurisdiction. Effective enforcement requires multi-channel pressure:

| Channel | Action |
|---|---|
| **ICANN Contractual Compliance** | Registrar Compliance report — failure to respond to abuse reports per §3.18 RAA |
| **FBI IC3** | ic3.gov — US-victim phishing and fraud |
| **Europol EC3** | Cross-border cybercrime referral |
| **CISA / NCSC** | National-level threat-intel sharing |
| **Spamhaus DBL** | Bulk submission of HIGH domains |
| **URLhaus / ThreatFox** | Automated daily IOC feed |
| **Downstream hosters** | Cloudflare, Fastly, AWS — abuse reports to hosting providers (not just registrar) |
| **Brand owners** | Microsoft, PayPal, Amazon, Metamask — direct UDRP and legal action |

ICANN's Registrar Accreditation Agreement §3.18 requires registrars to maintain and respond to abuse contacts within 24 hours. Documented non-response is grounds for accreditation suspension.

---

## Repository Structure

```
nicenic-evidence/
├── scan/
│   ├── phase1_http.py          # aiohttp mass scanner
│   ├── phase2_screenshots.py   # Playwright browser scan
│   ├── classify.py             # Groq AI classification
│   ├── fast_classify.py        # Rule-based pre-filter pass
│   ├── geoip_enrich.py         # ipinfo.io enrichment
│   ├── build_clusters.py       # Favicon+fingerprint cluster analysis
│   ├── build_ioc.py            # IOC feed generation
│   ├── build_domains_html.py   # Regenerate domains.html
│   ├── threat_intel.py         # TI cross-reference
│   ├── redact_creds.py         # PII/credential redaction
│   ├── finalize.py             # Final pipeline step
│   ├── compress_screenshots.py # PNG→JPEG compression
│   ├── merge_zone.py           # Zone data merge
│   ├── lambda_handler.py       # AWS Lambda variant
│   └── invoke_all.py           # Lambda orchestrator
├── docs/
│   ├── index.html              # Investigation landing page (GitHub Pages)
│   ├── domains.html            # Searchable domain table (76,117 domains)
│   ├── data.json               # Slim per-domain dataset
│   ├── build_datajson.py       # Regenerate data.json from enriched.csv
│   └── assets/                 # Hero image, OG card, favicons
├── data/
│   ├── enriched.csv            # Canonical enriched dataset (86,114 rows)
│   ├── high_severity.csv       # CRITICAL+HIGH subset (20,480 rows)
│   ├── dead_domains.csv        # Dead / parked enumeration
│   └── clusters.json           # Operator cluster map (2,939 clusters)
├── ioc/
│   ├── domains_high.txt        # CRITICAL+HIGH blocklist (18,305 domains)
│   ├── domains_all_malicious.txt # CRITICAL+HIGH+MEDIUM (18,927 domains)
│   └── indicators.csv          # SIEM-ready IOC feed (18,927 indicators)
├── pkg/
│   └── raw_data/               # Compressed raw scan output (.gz)
├── SHA256SUMS.txt              # Checksums of all published data files
├── PROVENANCE.md               # Chain-of-custody documentation
└── README.md                   # This file
```

---

## Related Investigations

| Investigation | Registrar | Zone Size | Report |
|---|---|---|---|
| **Trustname / Fewmoretaps OÜ** | IANA #4318 | 7,641 domains | [phishdestroy.github.io/trustname-evidence](https://phishdestroy.github.io/trustname-evidence/) |
| **NameSilo** | IANA #1479 | 5.2M domains | *(in preparation)* |

---

<div align="center">

## PhishDestroy

Automated detection, classification, and public disclosure of domain abuse infrastructure.

[phishdestroy.io](https://phishdestroy.io) · [GitHub](https://github.com/phishdestroy) · TLP:CLEAR

*"NICENIC's abuse response SLA is effectively infinite — we've made it finite."*

**MIT License · TLP:CLEAR · June 2026**

</div>
