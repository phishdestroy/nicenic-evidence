# Abuse Category Taxonomy — PhishDestroy / NICENIC Investigation

Classification system used across all datasets, IOC feeds, and the live report.
Each domain is assigned exactly one category by the AI classification pipeline
(Groq Llama 3.1, rule-based pre-filter) and one severity level.

---

## Severity Levels

| Level | Value | Criteria |
|---|---|---|
| **CRITICAL** | 4 | Confirmed active abuse: phishing with form submission, carding shop with active inventory, malware C2, or domain with 2+ independent threat-intel hits |
| **HIGH** | 3 | Strong abuse signal: crypto drainer, fraudulent exchange, unlicensed gambling, brand squatting with redirect |
| **MEDIUM** | 2 | Moderate concern: adult content without verifiable age-gating, pharmaceutical spam, SEO link farms |
| **LOW** | 1 | Weak signal or ambiguous: suspicious but unconfirmed, parked with abuse-adjacent ads |
| **INFO** | 0 | No abuse: dead/timeout, legitimate content, neutral parking |

---

## Category Definitions

### CRITICAL / HIGH categories

| Category | Count | Description |
|---|---|---|
| `PHISHING_BRAND` | 7,036 | Brand-impersonation pages targeting users of Microsoft, PayPal, MetaMask, Coinbase, DHL, and similar. Designed to harvest credentials via fake login forms. |
| `GAMBLING` | 6,177 | Online gambling operations without visible licensing from recognised jurisdictions (MGA, UKGC, Curaçao eGaming). Includes sports betting, casinos, and slot aggregators. |
| `PHISHING_FINANCE` | 2,183 | Financial-institution phishing: fake bank portals, investment fraud, fake wire-transfer confirmation pages. Often carries account-takeover (ATO) risk. |
| `CRYPTO_EXCHANGE` | 1,547 | Fraudulent cryptocurrency exchanges and swap services. Domains imitate legitimate platforms (Binance, Kraken, OKX) or create fictitious high-yield "exchanges". |
| `CARDING` | 544 | Credit-card fraud infrastructure: dumps markets, CC shops, CVV stores, and fullz databases. Directly facilitates financial fraud against cardholders. |
| `MALWARE` | 387 | Malware distribution: drive-by download pages, fake software updates, cracked-software installers containing RATs, stealers, or ransomware loaders. |
| `CRYPTO_DRAINER` | 227 | Cryptocurrency wallet drain kits. Pages simulate NFT mints, airdrop claims, or wallet "verifications" to steal on-chain assets via malicious transaction approval. |
| `SPAM_PHARMA` | 204 | Unlicensed online pharmacies selling controlled substances (Tramadol, Xanax, erectile-dysfunction drugs) without prescription verification. |

### MEDIUM categories

| Category | Count | Description |
|---|---|---|
| `ADULT` | 420 | Adult content sites without verifiable age verification or parental advisory mechanisms as required in most EU/US jurisdictions. |
| `SPAM_SEO` | 202 | Thin-content SEO farms, link-exchange networks, and programmatic spam sites. Low direct harm but contribute to web quality degradation and may host affiliate fraud. |

### Informational categories (not included in IOC feeds)

| Category | Description |
|---|---|
| `PARKING` | Domain parked with registrar or third-party parking service. No active content. |
| `LEGITIMATE` | Verified legitimate business, personal, or institutional content. |
| `DEAD` | Domain did not resolve or returned persistent connection errors during scan window. |
| `UNKNOWN` | AI classification returned low confidence; domain not assigned to a specific abuse type. |

---

## Threat Intelligence Cross-Reference

Domains in `indicators.csv` include a `threat_sources` field listing which external
threat-intel feeds confirmed the domain:

| Source ID | Feed |
|---|---|
| `uribl` | URIBL — domain blacklist for spam and phishing |
| `spamhaus_zrd` | Spamhaus Zero Reputation Domains |
| `urlhaus` | abuse.ch URLhaus — malware URL database |
| `threatfox` | abuse.ch ThreatFox — malware IOC feed |
| `phishing_database` | mitchellkrogza/Phishing.Database |
| `hagezi_pro` | Hagezi DNS blocklist Pro |
| `phishtank` | PhishTank community phishing feed |

Domains with 2+ threat-intel sources are automatically escalated to **CRITICAL**
regardless of AI classification output.

---

## Category → MITRE ATT&CK Mapping (Informational)

| PhishDestroy Category | Nearest MITRE Technique |
|---|---|
| `PHISHING_BRAND` / `PHISHING_FINANCE` | T1566.002 Spearphishing Link, T1598 Phishing for Information |
| `CARDING` | T1657 Financial Theft |
| `CRYPTO_DRAINER` | T1657 Financial Theft, T1553 Subvert Trust Controls |
| `MALWARE` | T1189 Drive-by Compromise, T1204.002 Malicious File |
| `CRYPTO_EXCHANGE` | T1657 Financial Theft (fraud) |

---

*PhishDestroy Research · TLP:CLEAR · June 2026*
