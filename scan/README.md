<img src="https://capsule-render.vercel.app/api?type=waving&color=0:030810,100:da3633&height=120&fontColor=ffffff&animation=fadeIn&text=Scan%20Pipeline&fontSize=32&desc=NICENIC%20Investigation%20Tools&descAlignY=62&descSize=14" width="100%"/>

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

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:da3633,100:030810&height=60&section=footer" width="100%"/>
