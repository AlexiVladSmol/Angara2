#!/usr/bin/env python3
"""Convert an `examples/m11_screenshot.rs` cell dump to PNG."""

import json
import sys

from PIL import Image, ImageDraw, ImageFont

CELL_W = 9
CELL_H = 18
FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: m11_screenshot.py <input.json> <output.png>", file=sys.stderr)
        return 2
    document = json.load(open(sys.argv[1], encoding="utf-8"))
    width = document["width"]
    height = document["height"]
    image = Image.new("RGB", (width * CELL_W, height * CELL_H), (18, 20, 24))
    draw = ImageDraw.Draw(image)
    font = ImageFont.truetype(FONT, 14)
    bold = ImageFont.truetype(FONT_BOLD, 14)
    for y, row in enumerate(document["rows"]):
        for x, cell in enumerate(row):
            bg = tuple(cell["bg"])
            fg = tuple(cell["fg"])
            left = x * CELL_W
            top = y * CELL_H
            draw.rectangle(
                [left, top, left + CELL_W - 1, top + CELL_H - 1],
                fill=bg,
            )
            symbol = cell["s"]
            if symbol and not symbol.isspace():
                draw.text(
                    (left, top + 1),
                    symbol,
                    fill=fg,
                    font=bold if cell["b"] else font,
                )
    image.save(sys.argv[2])
    return 0


if __name__ == "__main__":
    sys.exit(main())
