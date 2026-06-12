"""
Compress PNG screenshots → JPEG 80% quality, max 1280px wide.
Reduces storage ~80% for GitHub commit.

Usage:
    python scan/compress_screenshots.py
    python scan/compress_screenshots.py --ss-dir docs/screenshots --quality 80
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

try:
    from PIL import Image
except ImportError:
    print("[!] pip install Pillow")
    raise

SS_DIR   = Path("docs/screenshots")
QUALITY  = 80
MAX_W    = 1280
WORKERS  = 4


def compress(png_path: Path) -> tuple[int, int]:
    out_path = png_path.with_suffix(".jpg")
    try:
        with Image.open(png_path) as img:
            if img.width > MAX_W:
                ratio = MAX_W / img.width
                img   = img.resize((MAX_W, int(img.height * ratio)), Image.LANCZOS)
            rgb = img.convert("RGB")
            rgb.save(out_path, "JPEG", quality=QUALITY, optimize=True)
        orig = png_path.stat().st_size
        new  = out_path.stat().st_size
        png_path.unlink()
        return orig, new
    except Exception as e:
        print(f"  [!] {png_path.name}: {e}")
        return 0, 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ss-dir",  default=str(SS_DIR))
    ap.add_argument("--quality", type=int, default=QUALITY)
    ap.add_argument("--workers", type=int, default=WORKERS)
    args = ap.parse_args()

    pngs = list(Path(args.ss_dir).glob("*.png"))
    print(f"[*] {len(pngs)} PNGs to compress")
    if not pngs:
        return

    total_orig = 0
    total_new  = 0
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for orig, new in pool.map(compress, pngs):
            total_orig += orig
            total_new  += new

    saved = total_orig - total_new
    pct   = 100 * saved / total_orig if total_orig else 0
    print(f"[+] {total_orig//1_048_576} MB → {total_new//1_048_576} MB  "
          f"(saved {saved//1_048_576} MB, {pct:.0f}%)")


if __name__ == "__main__":
    main()
