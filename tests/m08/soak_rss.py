#!/usr/bin/env python3
"""RSS plateau checks for the hour-long soak.

The process reaches its steady-state RSS at different times on different
runners: the first batch can finish below or at the plateau. Therefore a
single warmed baseline is not stable. The leak check compares the last and
third quartiles (a leak keeps growing while a plateau does not) and requires
the last-quarter median to be close to the peak (a still-rising process has a
large peak-to-median gap). The absolute peak remains a separate hard limit.
"""

from __future__ import annotations

from statistics import median

DEFAULT_GROWTH_KIB = 32 * 1024
DEFAULT_PEAK_GAP_KIB = 2 * 1024
DEFAULT_PEAK_KIB = 512 * 1024


def evaluate_rss(
    samples: list[dict[str, object]],
    growth_kib: int = DEFAULT_GROWTH_KIB,
    peak_gap_kib: int = DEFAULT_PEAK_GAP_KIB,
    peak_kib: int = DEFAULT_PEAK_KIB,
) -> dict[str, object]:
    values: list[int] = []
    for sample in samples:
        value = sample.get("rss_kib")
        if isinstance(value, int) and value > 0:
            values.append(value)
    if len(values) < 8:
        return {
            "ok": False,
            "reason": "not enough RSS samples",
            "samples": len(values),
            "threshold_growth_kib": growth_kib,
            "threshold_peak_gap_kib": peak_gap_kib,
            "threshold_peak_kib": peak_kib,
        }
    quarter = len(values) // 4
    third = median(values[2 * quarter : 3 * quarter])
    last = median(values[3 * quarter :])
    peak = max(values)
    growth = last - third
    peak_gap = peak - last
    return {
        "ok": growth <= growth_kib and peak_gap <= peak_gap_kib and peak <= peak_kib,
        "samples": len(values),
        "third_quarter_kib": third,
        "last_quarter_kib": last,
        "growth_kib": growth,
        "peak_gap_kib": peak_gap,
        "peak_kib": peak,
        "threshold_growth_kib": growth_kib,
        "threshold_peak_gap_kib": peak_gap_kib,
        "threshold_peak_kib": peak_kib,
    }
