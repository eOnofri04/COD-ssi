#!/usr/bin/env python3
"""Re-render the figures of ``PerformanceAnalysis.ipynb`` for a dark canvas.

The paper figures are light-themed: black text and axes on an opaque white
background.  On a dark deck they can only be shown behind a white plate.
This script produces the same figures with the palette reversed --- light
foreground, Monokai accents, no background at all --- to use on dark canvas.

Usage
-----
    python3 PerformanceAnalysis_dark.py                 # -> imgs/dark/*.pdf
    python3 PerformanceAnalysis_dark.py --format png --dpi 300
    python3 PerformanceAnalysis_dark.py --background mkBg    # opaque Monokai

Requires the same stack as the notebook (see ``requirements.txt``).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # no display needed, and no Qt/Tk dependency

import matplotlib.colors as mcolors  # noqa: E402
import matplotlib.pyplot as plt  # noqa: E402
from cycler import cycler  # noqa: E402
from matplotlib.figure import Figure  # noqa: E402

# ── Monokai palette ──────────────────────────────────────────────────────────
# Hex values copied from slides/slideStyle_dark.sty, so the figures and the
# deck share one palette.
MK_BG = "#272822"  # canvas       (only used by --background mkBg)
MK_TEXT = "#F8F8F2"  # near-white body text
MK_COMMENT = "#75715E"  # muted grey: grid, spines, secondary lines
MK_GREEN = "#A6E22E"
MK_CYAN = "#66D9E8"
MK_PINK = "#F92672"
MK_YELLOW = "#E6DB74"
MK_ORANGE = "#FD971F"
MK_PURPLE = "#AE81FF"

# The notebook addresses cycle entries positionally (C2, C3, C4, C5), so the
# order below mirrors matplotlib's default tab10 semantics --- blue, orange,
# green, red, purple, brown --- to keep every figure's colour coding intact.
MK_CYCLE = [
    MK_CYAN,  # C0  (was tab:blue)   left-axis boxplot, first metric
    MK_ORANGE,  # C1  (was tab:orange) left-axis boxplot, second metric
    MK_GREEN,  # C2  (was tab:green)  metadata / D_VC / D_VP sizes
    MK_PINK,  # C3  (was tab:red)    VC / VP sizes
    MK_PURPLE,  # C4  (was tab:purple) OPRF request size
    MK_YELLOW,  # C5  (was tab:brown)  OPRF response size
    "#F92672",
    "#75715E",
    "#A6E22E",
    "#66D9E8",
]


def dark_rc(background: str) -> dict:
    """Return the rcParams that turn a light figure into a dark-canvas one."""
    face = "none" if background == "transparent" else MK_BG
    return {
        # ── surfaces: nothing is painted, the slide shows through ──
        "figure.facecolor": face,
        "figure.edgecolor": face,
        "axes.facecolor": face,
        "savefig.facecolor": face,
        "savefig.edgecolor": face,
        "savefig.transparent": background == "transparent",
        # ── foreground ──
        "text.color": MK_TEXT,
        "axes.labelcolor": MK_TEXT,
        "axes.titlecolor": MK_TEXT,
        "axes.edgecolor": MK_TEXT,
        "xtick.color": MK_TEXT,
        "ytick.color": MK_TEXT,
        "xtick.labelcolor": MK_TEXT,
        "ytick.labelcolor": MK_TEXT,
        "patch.edgecolor": MK_TEXT,
        "hatch.color": MK_TEXT,
        # ── secondary ink ──
        "grid.color": MK_COMMENT,
        "legend.edgecolor": MK_COMMENT,
        "legend.facecolor": "none",
        "legend.framealpha": 0.0,
        "boxplot.flierprops.markeredgecolor": MK_TEXT,
        "boxplot.flierprops.color": MK_TEXT,
        # ── series colours ──
        "axes.prop_cycle": cycler(color=MK_CYCLE),
    }


def override_named_colours() -> None:
    """Repoint the ``k``/``black`` shorthands at the light foreground.

    The notebook hard-codes ``color='k'`` for the claim-count separators and
    ``edgecolor='k'`` for the size bars.  Those literals bypass rcParams, so
    without this they would stay black --- invisible on the dark canvas.
    """
    mcolors.get_named_colors_mapping().update(
        {
            "k": MK_TEXT,
            "black": MK_TEXT,
            "0": MK_TEXT,  # the '0' greyscale string, same intent
        }
    )


def brighten_seaborn_boxes() -> None:
    """Draw seaborn's box outlines, whiskers and fliers in the foreground ink.

    ``sns.boxplot`` defaults to ``linecolor="auto"``, which darkens the fill
    colour --- the right choice on white, illegible on ``#272822``.  Wrap the
    function so the notebook's calls inherit a light outline unless they ask
    for something else.  Silently skipped on seaborn < 0.13, which has no
    ``linecolor`` parameter.
    """
    import inspect

    import seaborn as sns

    if "linecolor" not in inspect.signature(sns.boxplot).parameters:
        return

    original = sns.boxplot

    def boxplot(*args, **kwargs):
        kwargs.setdefault("linecolor", MK_TEXT)
        return original(*args, **kwargs)

    sns.boxplot = boxplot


def install_savefig_hook(outdir: Path, fmt: str, dpi: int | None, transparent: bool):
    """Redirect every ``savefig`` into *outdir*, and record what was written."""
    written: list[Path] = []
    original = Figure.savefig

    def savefig(self, fname, *args, **kwargs):
        target = outdir / Path(str(fname)).with_suffix(f".{fmt}").name
        kwargs["transparent"] = transparent
        if dpi is not None:
            kwargs.setdefault("dpi", dpi)
        target.parent.mkdir(parents=True, exist_ok=True)
        result = original(self, target, *args, **kwargs)
        written.append(target)
        return result

    Figure.savefig = savefig
    return written


def code_cells(notebook: Path):
    """Yield ``(index, source)`` for every non-empty code cell of *notebook*."""
    cells = json.loads(notebook.read_text(encoding="utf-8"))["cells"]
    for index, cell in enumerate(cells):
        if cell.get("cell_type") != "code":
            continue
        source = "".join(cell.get("source", []))
        if not source.strip():
            continue
        # IPython magics and shell escapes are not valid Python; the notebook
        # currently has none, but drop them rather than crash if one appears.
        magics = [ln for ln in source.splitlines() if re.match(r"\s*[%!]", ln)]
        if magics:
            print(f"  cell {index}: skipping {len(magics)} magic line(s)", file=sys.stderr)
            source = "\n".join(
                ln for ln in source.splitlines() if not re.match(r"\s*[%!]", ln)
            )
        yield index, source


def main() -> int:
    here = Path(__file__).resolve().parent

    parser = argparse.ArgumentParser(
        description="Re-render the notebook figures with the Monokai palette."
    )
    parser.add_argument(
        "--notebook",
        type=Path,
        default=here / "PerformanceAnalysis.ipynb",
        help="notebook to execute (default: PerformanceAnalysis.ipynb)",
    )
    parser.add_argument(
        "--outdir",
        type=Path,
        default=here / "imgs" / "dark",
        help="where the re-rendered figures go (default: imgs/dark)",
    )
    parser.add_argument(
        "--format",
        default="pdf",
        help="output format: pdf (vector, for the deck), png, svg (default: pdf)",
    )
    parser.add_argument(
        "--dpi",
        type=int,
        default=None,
        help="raster resolution, for --format png (default: matplotlib's)",
    )
    parser.add_argument(
        "--background",
        choices=("transparent", "mkBg"),
        default="transparent",
        help="transparent (default) or an opaque Monokai #272822 plate",
    )
    args = parser.parse_args()

    notebook = args.notebook.resolve()
    if not notebook.is_file():
        parser.error(f"notebook not found: {notebook}")

    outdir = args.outdir.resolve()
    outdir.mkdir(parents=True, exist_ok=True)

    # The notebook reads ../performancesData/ and writes imgs/ with relative
    # paths, so run from its own directory.
    os.chdir(notebook.parent)

    override_named_colours()
    brighten_seaborn_boxes()
    written = install_savefig_hook(
        outdir, args.format, args.dpi, args.background == "transparent"
    )

    print(f"notebook : {notebook}")
    print(f"outdir   : {outdir}")
    print(f"palette  : Monokai on {args.background}")

    namespace: dict = {"__name__": "__notebook__"}
    with plt.rc_context(dark_rc(args.background)):
        for index, source in code_cells(notebook):
            try:
                exec(compile(source, f"<{notebook.name}:cell {index}>", "exec"), namespace)
            except Exception:  # noqa: BLE001 - report which cell, then re-raise
                print(f"\nfailed in cell {index} of {notebook.name}", file=sys.stderr)
                raise
            plt.close("all")

    print(f"\n{len(written)} figure(s) written:")
    for path in written:
        print(f"  {path.relative_to(outdir.parent.parent)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
