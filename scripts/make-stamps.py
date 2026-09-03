#!/usr/bin/env python3
"""Generate the coloured stamp variants in verifier/stamps/ from
verifier/inklinestamp.png. Keeps the white mark, recolours the disc.

Requires Pillow:  pip install pillow && python3 scripts/make-stamps.py
The palette here must match STAMP_THEMES in extension/options.js.
"""
import os, sys
from PIL import Image

THEMES = {
    'ink':      (26, 26, 26),
    'graphite': (138, 138, 138),
    'ocean':    (29, 95, 214),
    'forest':   (31, 122, 77),
    'coral':    (242, 85, 62),
    'plum':     (124, 58, 237),
    'gold':     (201, 138, 27),
    'rose':     (214, 51, 108),
}

root = os.path.join(os.path.dirname(__file__), '..', 'verifier')
src = Image.open(os.path.join(root, 'inklinestamp.png')).convert('RGBA')
out = os.path.join(root, 'stamps')
os.makedirs(out, exist_ok=True)

# The original gradient disc stays available as "inkline".
src.save(os.path.join(out, 'inkline.png'))

px = src.load()
w, h = src.size
for name, rgb in THEMES.items():
    img = Image.new('RGBA', (w, h))
    dst = img.load()
    for y in range(h):
        for x in range(w):
            r, g, b, a = px[x, y]
            if a == 0:
                dst[x, y] = (0, 0, 0, 0)
                continue
            # whiteness: the mark is pure white, the disc is saturated/dark
            wh = max(0.0, min(1.0, (min(r, g, b) - 120) / 135.0))
            dst[x, y] = tuple(int(255 * wh + c * (1 - wh)) for c in rgb) + (a,)
    img.save(os.path.join(out, name + '.png'))
    print('wrote', name)
