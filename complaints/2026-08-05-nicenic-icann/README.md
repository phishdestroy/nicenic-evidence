<div align="center">
<img src="https://raw.githubusercontent.com/phishdestroy/nicenic-evidence/master/docs/assets/banner.gif" width="100%"/>
</div>

<div align="center">

[![Registrar](https://img.shields.io/badge/IANA-%233765-6ea8d7?style=for-the-badge&labelColor=0c1018&logo=internetcomputer&logoColor=white)](https://www.iana.org/assignments/registrar-ids/registrar-ids.xhtml)
[![Submitted](https://img.shields.io/badge/ICANN_COMPLAINT-2026--08--05-ef4444?style=for-the-badge&labelColor=0c1018)](mailto:compliance@icann.org)
[![TLP](https://img.shields.io/badge/TLP-CLEAR-3fb950?style=for-the-badge&labelColor=0c1018)](https://www.cisa.gov/tlp)
[![Domains](https://img.shields.io/badge/Reported-13%2C104_domains-f97316?style=for-the-badge&labelColor=0c1018)](nicenic_2026_all_reports.csv)

<br/>

# NiceNIC — ICANN Compliance Complaint
## RAA §3.18 Non-Compliance · 2026-08-05

*13,104 phishing domains reported. 4,430 DNS-active. Zero registrar response.*

</div>

---

## 📋 What This Is

Formal bulk abuse complaint submitted to **ICANN Contractual Compliance** (`compliance@icann.org`) against **NiceNIC International Group Co., Limited (IANA ID 3765)** for systematic failure to comply with RAA §3.18 and the 2024 DNS Abuse Framework Amendments.

<table><tr>
<td align="center"><b>📨 Domains Reported</b><br/><sub><code>13,104</code></sub></td>
<td align="center"><b>🔴 DNS-Active Today</b><br/><sub><code>4,430</code></sub></td>
<td align="center"><b>✅ HTTP 200 Live</b><br/><sub><code>1,655</code></sub></td>
<td align="center"><b>⏱ Median Ignored</b><br/><sub><code>158 days</code></sub></td>
<td align="center"><b>📵 Registrar Responses</b><br/><sub><code>0</code></sub></td>
</tr></table>

---

## 📁 Files

| File | Description |
|---|---|
| [`NiceNIC_ICANN_Report_2026-08-05.pdf`](NiceNIC_ICANN_Report_2026-08-05.pdf) | **Full report** — complaint letter, statistics, timeline, Netcraft analysis, complete domain list |
| [`case_blockchaindappnode.pdf`](case_blockchaindappnode.pdf) | **Case study** — live wallet-connect phishing page, 172 days unremediated |
| [`nicenic_http200_alive.csv`](nicenic_http200_alive.csv) | **1,655 domains** confirmed HTTP 200 today — serving content right now |
| [`nicenic_evidence.csv`](nicenic_evidence.csv) | **4,430 DNS-active** — full per-domain evidence: VT, Spamhaus, urlscan, screenshots |
| [`nicenic_2026_all_reports.csv`](nicenic_2026_all_reports.csv) | **All 13,096** reported to NiceNIC in 2026 with current status |
| [`nicenic_2026_all_domains.txt`](nicenic_2026_all_domains.txt) | Plain domain list — domain + status + VT + report date |
| [`SHA256SUMS.txt`](SHA256SUMS.txt) | SHA256 integrity checksums |

---

## 🔍 Key Findings

**Selective Compliance — Netcraft Pattern**
> NiceNIC applies `clientHold` to domains flagged by Netcraft — proving technical capability. Our 13,104 documented reports received zero response. Not incapable. Choosing not to act.

**Manufactured Compliance Record**
> NiceNIC temporarily suspends domains during Netcraft verification, then restores them. Domains gain "Resolved" status while remaining fully operational for victims.

**Early Warning Systematically Ignored**
> We reported domains an average of **114 days before** VirusTotal vendors first detected them. In 99.7% of cases our report preceded any major AV detection.

**No Legitimate Business Identified**
> Independent review of NiceNIC's portfolio found no lawful commercial activity. Documented: crypto phishing, wallet drainers, 376+ mirrors of a Russian-language darknet narcotics marketplace, illegal gambling, fake pharmaceuticals.

---

## ⚖️ Legal Basis

- **RAA §3.18** — DNS Abuse mitigation obligations
- **ICANN Advisory** — *Compliance With DNS Abuse Obligations* (5 February 2024, effective 5 April 2024)
- Illustrative response timeline per Advisory: **2 business days** for clear phishing
- Our documented median non-response: **158 days**

---

## 🔐 Verification

```bash
sha256sum -c SHA256SUMS.txt
```

---

<div align="center">

**This correspondence is not confidential. All materials will be published.**

Materials may be used freely for any lawful purpose.
Citizens of the Russian Federation, Belarus, and OFAC-sanctioned jurisdictions are **strictly prohibited** from accessing or using these materials.

<br/>

[PhishDestroy.io](https://phishdestroy.io) · [abuse@phishdestroy.io](mailto:abuse@phishdestroy.io)

</div>
