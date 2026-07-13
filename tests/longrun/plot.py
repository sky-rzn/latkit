#!/usr/bin/env python3
"""Render the long-run witness (samples.tsv) to a PNG for docs/perf.md.

Three stacked panels sharing a time axis (hours since start): agent RSS,
open fd count, and the metric_series count — the three things Р53 says must
plateau. Induced-loss / restart samples are shaded so the "loss only in
disturbance windows" property is visible, not just asserted.

    tests/longrun/plot.py tests/longrun/out/<ts>/samples.tsv [out.png]

matplotlib only; it is not a runtime or CI dependency, just the docs step.
"""
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    src = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else src.rsplit("/", 1)[0] + "/rss.png"

    t, rss, fds, series, phase = [], [], [], [], []
    t0 = None
    with open(src) as f:
        for line in f:
            if line.startswith("#"):
                continue
            c = line.rstrip("\n").split("\t")
            if len(c) < 12:
                continue
            epoch = int(c[1])
            t0 = epoch if t0 is None else t0
            t.append((epoch - t0) / 3600.0)
            phase.append(c[2])
            rss.append(int(c[3]) / 1048576.0)  # MiB
            series.append(int(c[4]))
            fds.append(int(c[6]))

    if len(t) < 2:
        print(f"not enough samples in {src}", file=sys.stderr)
        return 1

    fig, axes = plt.subplots(3, 1, figsize=(10, 8), sharex=True)
    panels = [
        (axes[0], rss, "RSS (MiB)", "#2563eb"),
        (axes[1], fds, "open fds", "#059669"),
        (axes[2], series, "metric_series", "#d97706"),
    ]
    for ax, y, label, color in panels:
        ax.plot(t, y, color=color, lw=1.2)
        ax.set_ylabel(label)
        ax.grid(True, alpha=0.3)
        # Shade every disturbance sample so windows stand out.
        for i, ph in enumerate(phase):
            if ph.startswith(("recovery", "restart")) or ph.endswith("-noscrape"):
                lo = t[i - 1] if i else t[i]
                ax.axvspan(lo, t[i], color="#ef4444", alpha=0.12, lw=0)
    axes[-1].set_xlabel("hours since start")
    axes[0].set_title(
        f"latkit long-run soak — {t[-1]:.1f} h, {len(t)} samples "
        "(shaded = induced-loss / restart windows)"
    )
    fig.tight_layout()
    fig.savefig(out, dpi=110)
    print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
