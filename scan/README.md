# Scan Pipeline

Scripts used in the Phase I investigation of NICENIC (IANA #3765).

| Script | Purpose |
|---|---|
| `fetch_new.py` | Daily: fetch new registrations from NetAPI → `data/new/` |
| `phase1_http.py` | Mass HTTP fingerprinting (aiohttp, 600 concurrent) |
| `phase2_screenshots.py` | Headless Playwright browser render + screenshots |
| `classify.py` | Groq AI classification (Llama 3.1) |
| `build_clusters.py` | Favicon MurmurHash3 cluster analysis |
| `build_ioc.py` | IOC feed generation |

Run order for a full zone rescan: `phase1_http.py` → `phase2_screenshots.py` → `classify.py` → `build_clusters.py` → `build_ioc.py` → `finalize.py`
