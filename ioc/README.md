# IOC Feeds

Ready-to-use blocklists derived from the NICENIC investigation.

| File | Count | Use |
|---|---|---|
| `domains_high.txt` | 18,305 | CRITICAL+HIGH — Pi-hole, AdGuard, DNS RPZ |
| `domains_all_malicious.txt` | 18,927 | CRITICAL+HIGH+MEDIUM |
| `indicators.csv` | 18,927 | SIEM-ready — domain, IP, severity, category, favicon_mmh3 |

**Subscribe in Pi-hole:**
```
https://raw.githubusercontent.com/phishdestroy/nicenic-evidence/master/ioc/domains_high.txt
```

**Subscribe in AdGuard Home:**
```
https://raw.githubusercontent.com/phishdestroy/nicenic-evidence/master/ioc/domains_high.txt
```

Updated when new HIGH/CRITICAL domains are identified.
