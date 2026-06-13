"""Generate animated SVG banner for README."""
from pathlib import Path

svg = (
    '<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="360" viewBox="0 0 1280 360">\n'
    '<defs><style>\n'
    '.bg{fill:#030810}.grid{stroke:#0d1f35;stroke-width:.8;fill:none}\n'
    '.title{font-family:"Segoe UI",system-ui,sans-serif;font-weight:700;fill:#f0f6fc;letter-spacing:-.5px}\n'
    '.sub{font-family:"Segoe UI",system-ui,sans-serif;fill:#8b949e}\n'
    '.num{font-family:"Segoe UI",system-ui,sans-serif;font-weight:700;fill:#f0f6fc}\n'
    '.lbl{font-family:"Segoe UI",system-ui,sans-serif;fill:#8b949e;font-size:11px}\n'
    '.tag{font-family:"Consolas","Courier New",monospace;fill:#8b949e;font-size:10px}\n'
    '.mono{font-family:"Consolas","Courier New",monospace;fill:#6ea8d7}\n'
    '.dot-r{fill:#da3633}.dot-c{fill:#6ea8d7}\n'
    '@keyframes sweep{0%{transform:translateY(-40px);opacity:0}15%{opacity:.7}85%{opacity:.7}100%{transform:translateY(300px);opacity:0}}\n'
    '.scanline{animation:sweep 3.5s ease-in-out infinite}\n'
    '@keyframes pulse{0%,100%{r:3;opacity:.9}50%{r:5.5;opacity:.4}}\n'
    '@keyframes pulse2{0%,100%{r:2.5;opacity:.8}50%{r:4.5;opacity:.35}}\n'
    '.p1{animation:pulse 2s ease-in-out infinite}\n'
    '.p2{animation:pulse2 2.4s ease-in-out infinite .4s}\n'
    '.p3{animation:pulse 2.8s ease-in-out infinite .8s}\n'
    '.p4{animation:pulse2 2.2s ease-in-out infinite 1.2s}\n'
    '.p5{animation:pulse 3s ease-in-out infinite .6s}\n'
    '@keyframes fadein{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}\n'
    '.s1{animation:fadein .6s ease both .1s}.s2{animation:fadein .6s ease both .4s}\n'
    '.s3{animation:fadein .6s ease both .7s}.s4{animation:fadein .6s ease both 1s}\n'
    '.s5{animation:fadein .6s ease both 1.3s}.s6{animation:fadein .6s ease both 1.6s}\n'
    '@keyframes titlein{from{opacity:0;transform:translateX(-14px)}to{opacity:1;transform:translateX(0)}}\n'
    '.ta{animation:titlein .7s ease both .05s}.tb{animation:titlein .7s ease both .25s}\n'
    '.tc{animation:fadein .6s ease both .5s}\n'
    '@keyframes blink{0%,100%{opacity:1}50%{opacity:0}}\n'
    '.cursor{animation:blink 1s step-end infinite}\n'
    '@keyframes arc{from{stroke-dashoffset:400}to{stroke-dashoffset:0}}\n'
    '.a1{stroke-dasharray:400;animation:arc 2.2s ease both .3s}\n'
    '.a2{stroke-dasharray:350;animation:arc 2.2s ease both .6s}\n'
    '.a3{stroke-dasharray:300;animation:arc 2.2s ease both .9s}\n'
    '.a4{stroke-dasharray:280;animation:arc 2.2s ease both .5s}\n'
    '.a5{stroke-dasharray:260;animation:arc 2.2s ease both .8s}\n'
    '.a6{stroke-dasharray:320;animation:arc 2.2s ease both 1.1s}\n'
    '.a7{stroke-dasharray:290;animation:arc 2.2s ease both .4s}\n'
    '@keyframes glw{0%,100%{filter:drop-shadow(0 0 6px #da3633)}50%{filter:drop-shadow(0 0 18px #da3633)}}\n'
    '.origin{animation:glw 2.5s ease-in-out infinite}\n'
    '</style>\n'
    '<filter id="blur3"><feGaussianBlur stdDeviation="3"/></filter>\n'
    '<filter id="blur6"><feGaussianBlur stdDeviation="6"/></filter>\n'
    '<linearGradient id="sg" x1="0" x2="0" y1="0" y2="1">'
    '<stop offset="0" stop-color="#1a6aaa" stop-opacity="0"/>'
    '<stop offset=".5" stop-color="#1a6aaa" stop-opacity=".55"/>'
    '<stop offset="1" stop-color="#1a6aaa" stop-opacity="0"/>'
    '</linearGradient>\n'
    '<clipPath id="mc"><rect x="650" y="30" width="620" height="310"/></clipPath>\n'
    '</defs>\n'

    # Background
    '<rect width="1280" height="360" class="bg"/>\n'

    # Grid
    '<g class="grid">'
    + ''.join(f'<line x1="0" y1="{y}" x2="1280" y2="{y}"/>' for y in range(40, 360, 40))
    + ''.join(f'<line x1="{x}" y1="0" x2="{x}" y2="360"/>' for x in range(80, 1280, 80))
    + '</g>\n'

    # Left accent bar
    '<rect x="0" y="0" width="4" height="360" fill="#da3633"/>\n'

    # Scan sweep
    '<rect class="scanline" x="40" y="0" width="570" height="10" fill="url(#sg)" rx="3"/>\n'

    # Divider
    '<line x1="645" y1="0" x2="645" y2="360" stroke="#162030" stroke-width="1.5"/>\n'

    # Right panel – China glow + arcs
    '<g clip-path="url(#mc)">\n'
    '<ellipse cx="1050" cy="185" rx="45" ry="32" fill="#da3633" opacity=".2" filter="url(#blur6)"/>\n'
    '<ellipse cx="1050" cy="185" rx="22" ry="16" fill="#da3633" opacity=".4" filter="url(#blur3)"/>\n'
    # Threat arcs
    '<path class="a1" fill="none" stroke="#da3633" stroke-width="1.5" d="M1050 185 Q940 90 820 140"/>\n'
    '<path class="a2" fill="none" stroke="#da3633" stroke-width="1.3" d="M1050 185 Q890 60 760 130"/>\n'
    '<path class="a3" fill="none" stroke="#ff5533" stroke-width="1" d="M1050 185 Q970 105 880 148"/>\n'
    '<path class="a4" fill="none" stroke="#da3633" stroke-width="1.4" d="M1050 185 Q960 255 830 230"/>\n'
    '<path class="a5" fill="none" stroke="#ff5533" stroke-width="1.1" d="M1050 185 Q990 270 920 258"/>\n'
    '<path class="a6" fill="none" stroke="#da3633" stroke-width="1.2" d="M1050 185 Q870 120 740 160"/>\n'
    '<path class="a7" fill="none" stroke="#ff7755" stroke-width="1" d="M1050 185 Q850 210 720 200"/>\n'
    # Origin
    '<circle cx="1050" cy="185" r="5.5" fill="#da3633" class="p1 origin"/>\n'
    '<circle cx="1050" cy="185" r="12" fill="none" stroke="#da3633" stroke-width="1" opacity=".35"/>\n'
    '<circle cx="1050" cy="185" r="22" fill="none" stroke="#da3633" stroke-width=".6" opacity=".18"/>\n'
    # Target dots
    '<circle cx="820" cy="140" r="3.5" class="dot-r p2"/>\n'
    '<circle cx="760" cy="130" r="3" class="dot-r p3"/>\n'
    '<circle cx="880" cy="148" r="3" class="dot-r p4"/>\n'
    '<circle cx="830" cy="230" r="3.5" class="dot-r p5"/>\n'
    '<circle cx="920" cy="258" r="3" class="dot-r p2"/>\n'
    '<circle cx="740" cy="160" r="2.5" class="dot-c p3"/>\n'
    '<circle cx="720" cy="200" r="2.5" class="dot-c p4"/>\n'
    '</g>\n'

    # Right panel labels
    '<text class="tag s1" x="665" y="34" font-size="10">THREAT VECTOR MAP · ORIGIN: CHINA (IANA #3765)</text>\n'
    '<text class="sub s6" x="665" y="348" font-size="10">63,190 domains shielded by Cloudflare (83% of alive zone)</text>\n'

    # === LEFT PANEL ===
    '<text class="tag ta" x="48" y="34" font-size="10">PHISHDESTROY RESEARCH · TLP:CLEAR · JUNE 2026</text>\n'

    # Title
    '<text class="title ta" x="48" y="92" font-size="36">NICENIC INTERNATIONAL</text>\n'
    '<text class="title tb" x="48" y="132" font-size="36">GROUP CO., LIMITED</text>\n'
    '<text class="sub tc" x="48" y="158" font-size="13">IANA Registrar ·3765 · China · Complete Zone Scan</text>\n'

    # Divider line
    '<rect x="48" y="168" width="530" height="1" fill="#162030" class="s1"/>\n'

    # Big stats
    '<g class="s2">'
    '<text class="num" x="48" y="205" font-size="30">343,107</text>'
    '<text class="lbl" x="48" y="221">DOMAINS SCANNED</text>'
    '</g>\n'
    '<g class="s3">'
    '<text class="num" x="240" y="205" font-size="30">18,927</text>'
    '<text class="lbl" x="240" y="221">MALICIOUS</text>'
    '</g>\n'
    '<g class="s4">'
    '<text class="num" x="400" y="205" font-size="30">48.4%</text>'
    '<text class="lbl" x="400" y="221">OF ALIVE</text>'
    '</g>\n'
    '<g class="s4">'
    '<text class="num" x="510" y="205" font-size="30">2,939</text>'
    '<text class="lbl" x="510" y="221">CLUSTERS</text>'
    '</g>\n'

    # Category bars
    '<g class="s3">'
    '<text class="tag" x="48" y="246">PHISHING_BRAND</text>'
    '<rect x="48" y="249" width="150" height="5" rx="2" fill="#da3633"/>'
    '<text class="tag" x="210" y="254">7,036</text>'
    '</g>\n'
    '<g class="s4">'
    '<text class="tag" x="48" y="266">GAMBLING</text>'
    '<rect x="48" y="269" width="128" height="5" rx="2" fill="#c0a060"/>'
    '<text class="tag" x="210" y="274">6,177</text>'
    '</g>\n'
    '<g class="s5">'
    '<text class="tag" x="48" y="286">PHISHING_FINANCE</text>'
    '<rect x="48" y="289" width="90" height="5" rx="2" fill="#ff4433"/>'
    '<text class="tag" x="210" y="294">2,183</text>'
    '</g>\n'
    '<g class="s5">'
    '<text class="tag" x="48" y="306">CARDING</text>'
    '<rect x="48" y="309" width="55" height="5" rx="2" fill="#ff3333"/>'
    '<text class="tag" x="210" y="314">544</text>'
    '</g>\n'
    '<g class="s6">'
    '<text class="tag" x="48" y="326">MALWARE</text>'
    '<rect x="48" y="329" width="40" height="5" rx="2" fill="#8b5cf6"/>'
    '<text class="tag" x="210" y="334">387</text>'
    '<text class="mono cursor" x="230" y="334" font-size="11">_</text>'
    '</g>\n'

    # Bottom strip
    '<rect x="0" y="348" width="1280" height="12" fill="#060d18"/>\n'
    '<text class="tag" x="48" y="358" font-size="9">domains_high.txt · indicators.csv · SHA256SUMS.txt.sig · ED25519 signed</text>\n'
    '<text class="tag" x="1240" y="358" font-size="9" text-anchor="end">phishdestroy.github.io/nicenic-evidence</text>\n'

    '</svg>'
)

Path("E:/nicenic-evidence/docs/assets/banner.svg").write_text(svg, encoding="utf-8")
print(f"banner.svg written ({len(svg)} chars)")
