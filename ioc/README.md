<img src="https://capsule-render.vercel.app/api?type=waving&color=0:030810,100:da3633&height=120&fontColor=ffffff&animation=fadeIn&text=IOC%20Feeds&fontSize=32&desc=18%2C927%20malicious%20domains%20%C2%B7%20NICENIC&descAlignY=62&descSize=14" width="100%"/>

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

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:da3633,100:030810&height=60&section=footer" width="100%"/>
