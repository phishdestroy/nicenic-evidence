# ICANN Compliance Complaint — NiceNIC International Group Co., Limited
## Submission Date: 2026-08-05

**Registrar:** NiceNIC International Group Co., Limited  
**IANA ID:** 3765  
**Submitted to:** ICANN Contractual Compliance — compliance@icann.org  
**Basis:** RAA §3.18 + ICANN DNS Abuse Advisory (5 February 2024)

---

## What This Is

Formal bulk abuse complaint documenting **13,104 phishing domains** reported to NiceNIC in 2026 with zero registrar response. As of submission date, **4,430 domains remain DNS-active** and **1,655 confirmed HTTP 200** (serving content).

Key metrics:
- Median days without registrar action: **158**
- Maximum: **215 days**
- Average VT detections per domain: **7.1 / 91**
- Total VT detections: **31,627**
- Registrar responses received: **0**

---

## Files

| File | Description |
|---|---|
| `NiceNIC_ICANN_Report_2026-08-05.pdf` | Full report — complaint letter, statistics, timeline analysis, Netcraft selective compliance documentation, complete domain list (4,430) |
| `case_blockchaindappnode.pdf` | Case study — `blockchaindappnode.org/connect2`, wallet connect seed phrase phishing, 172 days unremediated with live screenshot |
| `nicenic_http200_alive.csv` | **1,655 domains** — HTTP 200 confirmed today, serving content right now |
| `nicenic_http200_domains.txt` | Same — plain domain list |
| `nicenic_evidence.csv` | **4,430 DNS-active domains** — full per-domain evidence: VT vendors, Spamhaus, URLQuery, OTX, urlscan, screenshots, IP/geo, brand, scam type |
| `nicenic_2026_all_reports.csv` | **All 13,096 domains** reported to NiceNIC in 2026 with current status |
| `nicenic_2026_all_domains.txt` | All 13,096 — domain + status + VT + report date |
| `SHA256SUMS.txt` | SHA256 integrity checksums |

---

## Key Documented Findings

**1. Selective Compliance — Netcraft Pattern**  
NiceNIC applies `clientHold` to domains flagged by Netcraft — proving technical capability exists. Our 13,104 reports with equivalent evidence received zero response. This is documented deliberate non-compliance.

**2. Manufactured Compliance Record**  
NiceNIC temporarily suspends domains for Netcraft verification scans, then restores them. Domains gain "Resolved" status in Netcraft while remaining fully operational. Verified on multiple domains from this dataset.

**3. Early Warning Systematically Ignored**  
We reported domains an average of **114 days before VT vendors first detected them**. 99.7% of reports preceded any major AV detection. Had NiceNIC acted, harm would have been prevented.

**4. Domain Lifetime After Report**  
- 88% still active 7 days after our report  
- 69% still active 30 days after report  
- 44% still active 90+ days after report  

**5. Portfolio Composition**  
No legitimate business domains identified. Documented: crypto phishing, wallet drainers, 376+ mirrors of a Russian-language darknet narcotics marketplace, illegal gambling, fake pharmaceuticals, brand impersonation across 166 identified brands.

**6. 89% on Cloudflare Free Tier**  
11,581 of 13,104 domains used Cloudflare free tier — zero identity verification, zero accountability. Cloudflare is not a registrar and should not be the de facto abuse processor.

---

## Verification

```bash
sha256sum -c SHA256SUMS.txt
```

---

## License

All materials freely available for any lawful purpose.  
**Exception:** Citizens of the Russian Federation, Belarus, and OFAC-sanctioned jurisdictions are strictly prohibited from accessing or using these materials.

---

*Part of the [PhishDestroy NiceNIC Evidence Repository](https://github.com/phishdestroy/nicenic-evidence)*  
*PhishDestroy.io — abuse@phishdestroy.io*
