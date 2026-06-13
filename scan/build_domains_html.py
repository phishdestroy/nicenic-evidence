"""
Rebuilds docs/domains.html with window._INLINE_DATA (inline, works on file://).
Inlines HIGH+CRITICAL+MEDIUM domains only (~19K) for manageable file size.
"""
import json
from pathlib import Path


def safe_json_string(obj):
    s = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    result = []
    in_str = False
    esc_next = False
    for ch in s:
        if esc_next:
            result.append(ch)
            esc_next = False
        elif ch == '\\':
            result.append(ch)
            esc_next = True
        elif ch == '"':
            in_str = not in_str
            result.append(ch)
        elif in_str and ch == '\n':
            result.append('\\n')
        elif in_str and ch == '\r':
            result.append('\\r')
        elif in_str and ch == '\t':
            result.append('\\t')
        else:
            result.append(ch)
    return ''.join(result)


def main():
    data_json = Path(__file__).parent.parent / "docs" / "data.json"
    domains_html = Path(__file__).parent.parent / "docs" / "domains.html"

    print("[*] Loading data.json...")
    d = json.loads(data_json.read_text(encoding="utf-8"))
    all_domains = d.get("domains", [])

    inline = [r for r in all_domains
              if r.get("severity_label") in ("HIGH", "CRITICAL", "MEDIUM")]
    print(f"    Inline: {len(inline)} domains (HIGH+CRITICAL+MEDIUM)")

    inline_obj = {
        "domains":  inline,
        "stats":    d.get("stats", {}),
        "clusters": d.get("clusters", []),
    }
    inline_json = safe_json_string(inline_obj)
    size_mb = len(inline_json.encode()) / 1_048_576
    print(f"    JSON size: {size_mb:.1f}MB")

    dh = domains_html.read_text(encoding="utf-8")

    old = (
        "(function(){\n"
        "  fetch('data.json')\n"
        "    .then(r=>r.json())\n"
        "    .then(function(j){\n"
        "      DATA = j.domains||[];\n"
        "      CATS = [...new Set(DATA.map(r=>r.category).filter(Boolean))].sort();\n"
        "      renderCatBtns();\n"
        "      if(urlCat!=='ALL'){\n"
        "        fCat=urlCat;\n"
        "        document.querySelectorAll('.cb').forEach(function(b){b.classList.remove('on');if(b.dataset.cat===urlCat)b.classList.add('on');});\n"
        "      }\n"
        "      go();\n"
        "    })\n"
        "    .catch(function(e){\n"
        "      document.getElementById('scan-pending').style.display='block';\n"
        "      document.getElementById('scan-pending').textContent='Failed to load data: '+e;\n"
        "    });\n"
        "})();"
    )

    new = (
        f"window._INLINE_DATA={inline_json};\n"
        "(function(){\n"
        "  var j=window._INLINE_DATA||{};\n"
        "  DATA=j.domains||[];\n"
        "  CATS=[...new Set(DATA.map(function(r){return r.category;}).filter(Boolean))].sort();\n"
        "  renderCatBtns();\n"
        "  if(urlCat!=='ALL'){\n"
        "    fCat=urlCat;\n"
        "    document.querySelectorAll('.cb').forEach(function(b){b.classList.remove('on');if(b.dataset.cat===urlCat)b.classList.add('on');});\n"
        "  }\n"
        "  go();\n"
        "})();"
    )

    if old in dh:
        dh = dh.replace(old, new)
        print("    Replaced fetch with _INLINE_DATA IIFE")
    else:
        print("    WARNING: pattern not found, trying partial match...")
        idx = dh.find("fetch('data.json')")
        if idx >= 0:
            # find enclosing IIFE start
            start = dh.rfind("(function(){", 0, idx)
            # find closing })();
            end = dh.find("})();", idx) + len("})();")
            print(f"    Replacing lines {start}..{end}")
            dh = dh[:start] + new + dh[end:]
        else:
            print("    ERROR: fetch not found at all")
            return

    domains_html.write_text(dh, encoding="utf-8")
    size = domains_html.stat().st_size
    print(f"[+] domains.html: {size // 1024 // 1024}MB ({size // 1024}KB)")


if __name__ == "__main__":
    main()
