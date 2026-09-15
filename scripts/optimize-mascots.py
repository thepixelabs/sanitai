#!/usr/bin/env python3
"""scripts/optimize-mascots.py — build web-sized mascot images for docs/.

The landing page never renders a mascot wider than ~380 CSS px, so shipping the
full-resolution renders (1856x2304, ~5 MB each) is pure download cost. This
script resizes each source render to 2x its largest displayed width and writes
AVIF + WebP + PNG (fallback) variants next to index.html.

Usage:
    python3 scripts/optimize-mascots.py path/to/nix-hero.png [more sources...]

Source files are matched by basename to the entries in TARGETS. Full-res
originals are not kept in the repo (they live in git history before the
optimisation commit, or in the design source folder).

Requires Pillow >= 10 with AVIF support (pip install pillow).
"""
import sys
from pathlib import Path

from PIL import Image

DOCS = Path(__file__).resolve().parent.parent / "docs"

# basename -> output width in px (2x the widest CSS rendering of that image)
TARGETS = {
    "nix-hero.png": 800,      # rendered at max 380px wide
    "nix-stories.png": 560,   # rendered at 260px wide
    "nix-cta.png": 560,       # rendered at 260px wide
}


def build(src: Path) -> None:
    width = TARGETS.get(src.name)
    if width is None:
        sys.exit(f"unknown mascot {src.name!r}; expected one of {sorted(TARGETS)}")

    im = Image.open(src).convert("RGBA")
    height = round(im.height * width / im.width)
    im = im.resize((width, height), Image.LANCZOS)

    stem = DOCS / src.stem
    im.save(stem.with_suffix(".avif"), quality=60, speed=4)
    im.save(stem.with_suffix(".webp"), quality=82, method=6)
    im.save(stem.with_suffix(".png"), optimize=True)

    for ext in (".avif", ".webp", ".png"):
        out = stem.with_suffix(ext)
        print(f"{out.relative_to(DOCS.parent)}: {width}x{height} {out.stat().st_size // 1024} KB")


def main(argv: list[str]) -> None:
    if not argv:
        sys.exit(__doc__)
    for arg in argv:
        build(Path(arg))


if __name__ == "__main__":
    main(sys.argv[1:])
