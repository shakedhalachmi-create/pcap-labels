"""Color names and conversions to Wireshark's coloring-rule format."""
import re

NAMED_COLORS = {
    "pink": (255, 105, 180),
    "red": (220, 40, 40),
    "orange": (255, 150, 30),
    "yellow": (255, 230, 60),
    "green": (80, 200, 100),
    "cyan": (70, 210, 220),
    "blue": (70, 120, 240),
    "purple": (160, 90, 220),
    "gray": (150, 150, 150),
}

_HEX_RE = re.compile(r"^#?([0-9a-fA-F]{6})$")
_WS_RGB_RE = re.compile(r"\[(\d+),(\d+),(\d+)\]")


def parse_color(text):
    """'pink' or '#ff69b4' -> (r, g, b) with 8-bit channels."""
    key = text.strip().lower()
    if key in NAMED_COLORS:
        return NAMED_COLORS[key]
    m = _HEX_RE.match(key)
    if not m:
        raise ValueError(
            f"Unknown color '{text}'. Use #RRGGBB or one of: {', '.join(NAMED_COLORS)}")
    h = m.group(1)
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def to_hex(rgb):
    return "#%02x%02x%02x" % rgb


def text_color_for(rgb):
    """Black or white text, whichever reads better on the given background."""
    r, g, b = rgb
    luminance = 0.299 * r + 0.587 * g + 0.114 * b
    return (0, 0, 0) if luminance > 140 else (255, 255, 255)


def to_wireshark(rgb):
    """(255, 105, 180) -> '[65535,26985,46260]' (16-bit channels)."""
    return "[%d,%d,%d]" % tuple(c * 257 for c in rgb)


def from_wireshark(text):
    """'[65535,26985,46260][0,0,0]' -> [(255, 105, 180), (0, 0, 0)] (8-bit channels)."""
    return [tuple(int(c) >> 8 for c in m.groups()) for m in _WS_RGB_RE.finditer(text)]
