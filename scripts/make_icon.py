"""Draws otinv's icon: three linked devices on a slate tile, one flagged in
orange. Writes assets/otinv.ico (for the installers and shortcuts) and
assets/icon-64.rgba (the GUI's window icon, raw RGBA). Standard library only.

    python scripts/make_icon.py
"""

import math
import pathlib
import struct
import zlib

OUT = pathlib.Path(__file__).resolve().parent.parent / "assets"
N = 256
SS = 4  # samples per pixel per axis

TILE = (31, 58, 68)
LINK = (226, 233, 236)
NODE = (226, 233, 236)
FLAG = (242, 140, 40)

NODES = [(78, 172), (178, 172), (128, 80)]
NODE_R = 30
LINK_W = 13


def in_tile(x, y):
    r, lo, hi = 52, 8, N - 8
    cx = min(max(x, lo + r), hi - r)
    cy = min(max(y, lo + r), hi - r)
    return lo <= x <= hi and lo <= y <= hi and math.hypot(x - cx, y - cy) <= r


def near_segment(x, y, a, b, w):
    (ax, ay), (bx, by) = a, b
    dx, dy = bx - ax, by - ay
    t = max(0.0, min(1.0, ((x - ax) * dx + (y - ay) * dy) / (dx * dx + dy * dy)))
    return math.hypot(x - (ax + t * dx), y - (ay + t * dy)) <= w / 2


def color_at(x, y):
    for i, (nx, ny) in enumerate(NODES):
        d = math.hypot(x - nx, y - ny)
        if d <= NODE_R:
            return FLAG if i == 2 else NODE
    for i in range(3):
        if near_segment(x, y, NODES[i], NODES[(i + 1) % 3], LINK_W):
            return LINK
    if in_tile(x, y):
        return TILE
    return None


def render():
    px = []
    for y in range(N):
        for x in range(N):
            r = g = b = a = 0
            for sy in range(SS):
                for sx in range(SS):
                    c = color_at(x + (sx + 0.5) / SS, y + (sy + 0.5) / SS)
                    if c:
                        r, g, b, a = r + c[0], g + c[1], b + c[2], a + 1
            px.append((r // a, g // a, b // a, 255 * a // (SS * SS)) if a else (0, 0, 0, 0))
    return px


def shrink(px, n):
    k = N // n
    out = []
    for y in range(n):
        for x in range(n):
            block = [px[(y * k + j) * N + x * k + i] for j in range(k) for i in range(k)]
            a = sum(p[3] for p in block)
            if a == 0:
                out.append((0, 0, 0, 0))
                continue
            out.append(
                tuple(sum(p[c] * p[3] for p in block) // a for c in range(3))
                + (a // len(block),)
            )
    return out


def png(px, n):
    raw = b"".join(b"\0" + bytes(c for p in px[y * n:(y + 1) * n] for c in p) for y in range(n))

    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(
            ">I", zlib.crc32(kind + data) & 0xFFFFFFFF
        )

    ihdr = struct.pack(">IIBBBBB", n, n, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )


def main():
    big = render()
    sizes = [256, 64, 48, 32, 24, 16]
    images = [(n, png(big if n == N else shrink(big, n), n)) for n in sizes]
    head = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries, blobs = b"", b""
    for n, data in images:
        entries += struct.pack("<BBBBHHII", n % 256, n % 256, 0, 0, 1, 32, len(data), offset)
        blobs += data
        offset += len(data)
    OUT.mkdir(exist_ok=True)
    (OUT / "otinv.ico").write_bytes(head + entries + blobs)
    (OUT / "icon-64.rgba").write_bytes(bytes(c for p in shrink(big, 64) for c in p))
    print(f"wrote {OUT / 'otinv.ico'} and {OUT / 'icon-64.rgba'}")


if __name__ == "__main__":
    main()
