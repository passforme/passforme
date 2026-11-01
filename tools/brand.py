"""Builds the brand kit in brand/ and the site's icons, from one place.

Two colourways of the mark (a keyhole on a rounded square): gold, the
brand's main one, and brass, the darker brown. Everything is generated:
SVGs here, PNGs and favicon.ico by headless Chromium, so a change to the
palette or the mark is one edit and one run.

The wordmark is "passforme" in Bricolage Grotesque (weight 750, optical
size 96, as the site's titles), turned into outlines so the SVGs need no
font. Needs fontTools and brotli (to read the site's woff2) and chromium:

    uv venv /tmp/brand && uv pip install --python /tmp/brand/bin/python fonttools brotli
    /tmp/brand/bin/python tools/brand.py
"""

import shutil
import struct
import subprocess
import tempfile
import zipfile
from pathlib import Path

from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont

ROOT = Path(__file__).resolve().parent.parent
FONTS = ROOT / "site/assets/fonts"
SITE = ROOT / "site"
BRAND = SITE / "brand"

# The palette; site/assets/site.css holds the same values as CSS tokens.
GOLD = "#e0ac5c"
BRASS = "#8a5a12"
INK = "#1d2427"
NIGHT = "#13181b"
PAPER = "#f3f4f1"
SHEET = "#fbfbf9"
INK_DARK = "#e4e7e3"
MUTED = "#5b6669"
MUTED_DARK = "#9aa5a6"

README = f"""passforme brand kit (https://passforme.com/brand.html)

Colours
  Gold    {GOLD}   the mark; accents on dark backgrounds
  Brass   {BRASS}   the darker mark; links and accents on light backgrounds
  Ink     {INK}   text on light
  Night   {NIGHT}   dark background
  Paper   {PAPER}   light background
  Sheet   {SHEET}   cards on light; the brass mark's keyhole
  Fog     {INK_DARK}   text on dark

Fonts (SIL Open Font License)
  Bricolage Grotesque  titles and the wordmark (weight 750, optical size 96)
  Source Sans 3        text
  JetBrains Mono       code

logo/      the logo, the mark and the wordmark, for light and dark backgrounds
favicon/   favicon.ico, apple-touch-icon, 192 and 512 px icons, per colourway
fonts/     the three fonts as the site serves them (variable woff2) and their licences
social/    avatar and banners (Open Graph, GitHub, X, LinkedIn, YouTube)
"""

# Colourway: the square's colour, the keyhole's colour.
WAYS = {"gold": (GOLD, INK), "brass": (BRASS, SHEET)}

KEYHOLE = '<circle cx="32" cy="26" r="9" fill="{k}"/><path d="M27.5 30h9l3 18h-15z" fill="{k}"/>'


def icon(way: str, rounded: bool = True) -> str:
    """The mark, 64×64. Unrounded for avatars and touch icons, which the
    platform crops itself."""
    bg, key = WAYS[way]
    rx = ' rx="14"' if rounded else ""
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
        f'<rect width="64" height="64"{rx} fill="{bg}"/>{KEYHOLE.format(k=key)}</svg>\n'
    )


def wordmark_path(text: str) -> tuple[str, float, float, float]:
    """Outlines of `text`, in font units with y down: path data, width,
    ascender and descender."""
    font = TTFont(FONTS / "bricolage-grotesque-latin-standard-normal.woff2")
    font = instantiateVariableFont(font, {"wght": 750, "opsz": 96, "wdth": 100})
    glyphs = font.getGlyphSet()
    cmap = font.getBestCmap()
    tracking = -0.01 * font["head"].unitsPerEm  # letter-spacing: -0.01em
    pen = SVGPathPen(glyphs)
    x = 0.0
    for ch in text:
        name = cmap[ord(ch)]
        glyphs[name].draw(TransformPen(pen, (1, 0, 0, -1, x, 0)))
        x += glyphs[name].width + tracking
    os2 = font["OS/2"]
    return pen.getCommands(), x - tracking, os2.sTypoAscender, -os2.sTypoDescender


def svg(width: float, height: float, body: str) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width:.0f} {height:.0f}">\n'
        f"{body}</svg>\n"
    )


def logo(way: str, ink: str, d: str, width: float, ascent: float, descent: float) -> str:
    """The mark beside the wordmark, centred on the text box."""
    box = ascent + descent
    size = box * 0.86
    gap = box * 0.2
    pad = 40
    bg, key = WAYS[way]
    mark = (
        f'  <g transform="translate({pad} {pad + (box - size) / 2:.0f}) scale({size / 64:.4f})">'
        f'<rect width="64" height="64" rx="14" fill="{bg}"/>{KEYHOLE.format(k=key)}</g>\n'
    )
    text = (
        f'  <path transform="translate({pad + size + gap:.0f} {pad + ascent:.0f})" '
        f'fill="{ink}" d="{d}"/>\n'
    )
    return svg(size + gap + width + 2 * pad, box + 2 * pad, mark + text)


def font_faces() -> str:
    return "".join(
        f'@font-face{{font-family:"{fam}";src:url("{(FONTS / file).as_uri()}");font-weight:100 900}}'
        for fam, file in (
            ("Bricolage Grotesque", "bricolage-grotesque-latin-standard-normal.woff2"),
            ("Source Sans 3", "source-sans-3-latin-wght-normal.woff2"),
            ("JetBrains Mono", "jetbrains-mono-latin-wght-normal.woff2"),
        )
    )


def banner(way: str, w: int, h: int, logo_svg: Path) -> str:
    """A social banner: gold on night, brass on paper. Content is centred
    and kept in the middle 60 % of the height, clear of the avatar that X
    and LinkedIn lay over the bottom left."""
    dark = way == "gold"
    bg, ink, muted, accent = (
        (NIGHT, INK_DARK, MUTED_DARK, GOLD) if dark else (PAPER, INK, MUTED, BRASS)
    )
    logo_h = round(h * 0.2)
    return f"""<!doctype html><meta charset="utf-8"><style>{font_faces()}
html,body{{margin:0;width:{w}px;height:{h}px;overflow:hidden}}
body{{background:{bg};display:flex;flex-direction:column;align-items:center;justify-content:center;
  gap:{round(h * 0.05)}px;font-family:"Source Sans 3"}}
img{{height:{logo_h}px}}
p{{margin:0;color:{ink};font:600 {round(h * 0.075)}px/1.2 "Bricolage Grotesque";
  font-variation-settings:"opsz" 72;letter-spacing:-0.01em;text-align:center}}
small{{color:{muted};font:500 {round(h * 0.042)}px "JetBrains Mono"}}
small b{{color:{accent};font-weight:600}}
</style><img src="{logo_svg.as_uri()}" alt="">
<p>A password vault only you can open.</p>
<small><b>$</b> pfm · zero-knowledge · open source</small>
"""


def shoot(html: Path, png: Path, w: int, h: int) -> None:
    subprocess.run(
        [
            "chromium", "--headless", "--disable-gpu", "--hide-scrollbars",
            "--default-background-color=00000000", f"--window-size={w},{h}",
            f"--screenshot={png}", html.as_uri(),
        ],
        check=True, capture_output=True,
    )


def png_of_svg(src: Path, png: Path, w: int, h: int, tmp: Path) -> None:
    page = tmp / f"{png.stem}-{w}x{h}.html"
    page.write_text(
        f'<!doctype html><style>html,body{{margin:0}}img{{display:block;width:{w}px;'
        f'height:{h}px}}</style><img src="{src.as_uri()}">'
    )
    shoot(page, png, w, h)


def ico(pngs: list[Path], out: Path) -> None:
    """A .ico holding PNG images (every browser since IE Vista reads them)."""
    data = [p.read_bytes() for p in pngs]
    head = struct.pack("<HHH", 0, 1, len(data))
    offset = 6 + 16 * len(data)
    entries = b""
    for p, blob in zip(pngs, data):
        size = int(p.stem.rsplit("-", 1)[1])
        entries += struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32, len(blob), offset)
        offset += len(blob)
    out.write_bytes(head + entries + b"".join(data))


def main() -> None:
    shutil.rmtree(BRAND, ignore_errors=True)
    for sub in ("logo", "favicon", "social", "fonts"):
        (BRAND / sub).mkdir(parents=True, exist_ok=True)

    d, width, ascent, descent = wordmark_path("passforme")
    pad = 40
    for name, ink in (("wordmark-on-light", INK), ("wordmark-on-dark", INK_DARK)):
        body = f'  <path transform="translate({pad} {pad + ascent:.0f})" fill="{ink}" d="{d}"/>\n'
        (BRAND / "logo" / f"{name}.svg").write_text(svg(width + 2 * pad, ascent + descent + 2 * pad, body))

    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        for way in WAYS:
            (BRAND / "logo" / f"icon-{way}.svg").write_text(icon(way))
            square = tmp / f"square-{way}.svg"
            square.write_text(icon(way, rounded=False))
            for side, ink in (("light", INK), ("dark", INK_DARK)):
                path = BRAND / "logo" / f"logo-{way}-on-{side}.svg"
                path.write_text(logo(way, ink, d, width, ascent, descent))
                vw, vh = (float(v) for v in path.read_text().split('viewBox="0 0 ')[1].split('"')[0].split())
                png_of_svg(path, BRAND / "logo" / f"logo-{way}-on-{side}.png", 1600, round(1600 * vh / vw), tmp)

            fav = BRAND / "favicon" / way
            fav.mkdir(exist_ok=True)
            (fav / "icon.svg").write_text(icon(way))
            rounded = fav / "icon.svg"
            sizes = []
            for s in (16, 32, 48):
                p = tmp / f"fav-{s}.png"
                png_of_svg(rounded, p, s, s, tmp)
                sizes.append(p)
            ico(sizes, fav / "favicon.ico")
            png_of_svg(square, fav / "apple-touch-icon.png", 180, 180, tmp)
            for s in (192, 512):
                png_of_svg(rounded, fav / f"icon-{s}.png", s, s, tmp)

            soc = BRAND / "social" / way
            soc.mkdir(exist_ok=True)
            png_of_svg(square, soc / "avatar-1024.png", 1024, 1024, tmp)
            on = "dark" if way == "gold" else "light"
            logo_svg = BRAND / "logo" / f"logo-{way}-on-{on}.svg"
            for name, w, h in (
                ("og-1200x630", 1200, 630),
                ("github-1280x640", 1280, 640),
                ("x-header-1500x500", 1500, 500),
                ("linkedin-1584x396", 1584, 396),
                ("youtube-2560x1440", 2560, 1440),
            ):
                page = tmp / f"{way}-{name}.html"
                page.write_text(banner(way, w, h, logo_svg))
                shoot(page, soc / f"{name}.png", w, h)

    # The fonts exactly as the site serves them (variable woff2, latin, from
    # @fontsource-variable), each with its licence; the full families for
    # desktop apps are linked from the brand page.
    for font in FONTS.glob("*.woff2"):
        shutil.copy(font, BRAND / "fonts" / font.name)
    for lic in FONTS.glob("OFL-*.txt"):
        shutil.copy(lic, BRAND / "fonts" / lic.name)

    # The site uses the gold mark.
    gold = BRAND / "favicon" / "gold"
    shutil.copy(gold / "icon.svg", SITE / "assets/icon.svg")
    shutil.copy(gold / "favicon.ico", SITE / "favicon.ico")
    shutil.copy(gold / "apple-touch-icon.png", SITE / "assets/apple-touch-icon.png")
    shutil.copy(BRAND / "social/gold/og-1200x630.png", SITE / "assets/og.png")

    # Everything in one download, for the brand page.
    with zipfile.ZipFile(BRAND / "passforme-brand-kit.zip", "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("passforme-brand-kit/README.txt", README)
        for f in sorted(BRAND.rglob("*")):
            if f.is_file() and f.suffix != ".zip":
                z.write(f, "passforme-brand-kit/" + f.relative_to(BRAND).as_posix())


if __name__ == "__main__":
    main()
