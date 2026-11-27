#!/usr/bin/env python3
"""RSS plateau checks for the hour-long soak.

The process reaches its steady-state RSS at different times on different
runners.  A single warmed baseline is therefore not stable, and comparing only
the third and last quarters fails when an allocator step lands late in the
run.  This checker works on one-minute medians and separates two effects:

* a small number of large allocator steps (``step_kib`` or more in a minute)
  are removed before the trend is estimated;
* the remaining trend must stay below ``slope_kib_per_min``.

A staircase of allocator-sized steps in the second half is limited explicitly,
so a process that keeps jumping up still fails.  The absolute peak remains a
separate hard limit.
"""

from __future__ import annotations

from itertools import combinations
from statistics import median

DEFAULT_WINDOWS = 60
DEFAULT_STEP_KIB = 8 * 1024
DEFAULT_MAX_STEP_KIB = 64 * 1024
DEFAULT_MAX_LATE_STEPS = 2
DEFAULT_SLOPE_KIB_PER_MIN = 128
DEFAULT_PEAK_KIB = 512 * 1024


def _minute_medians(values: list[int], windows: int) -> list[float]:
    values_count = len(values)
    result: list[float] = []
    for index in range(windows):
        start = index * values_count // windows
        end = (index + 1) * values_count // windows
        if end > start:
            result.append(median(values[start:end]))
    return result


def _theil_sen_slope(points: list[tuple[int, float]]) -> float:
    slopes = [
        (y2 - y1) / (x2 - x1)
        for (x1, y1), (x2, y2) in combinations(points, 2)
        if x2 != x1
    ]
    return median(slopes) if slopes else 0.0


def evaluate_rss(
    samples: list[dict[str, object]],
    windows: int = DEFAULT_WINDOWS,
    step_kib: int = DEFAULT_STEP_KIB,
    max_step_kib: int = DEFAULT_MAX_STEP_KIB,
    max_late_steps: int = DEFAULT_MAX_LATE_STEPS,
    slope_kib_per_min: int = DEFAULT_SLOPE_KIB_PER_MIN,
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
            "threshold_step_kib": step_kib,
            "threshold_max_step_kib": max_step_kib,
            "threshold_max_late_steps": max_late_steps,
            "threshold_slope_kib_per_min": slope_kib_per_min,
            "threshold_peak_kib": peak_kib,
        }

    medians = _minute_medians(values, windows)
    if len(medians) < 8:
        return {
            "ok": False,
            "reason": "not enough one-minute RSS windows",
            "samples": len(values),
            "windows": len(medians),
            "threshold_step_kib": step_kib,
            "threshold_max_step_kib": max_step_kib,
            "threshold_max_late_steps": max_late_steps,
            "threshold_slope_kib_per_min": slope_kib_per_min,
            "threshold_peak_kib": peak_kib,
        }

    # A step is a one-minute increase of at least step_kib.  Adjacent
    # increases are grouped because a single allocator step can straddle a
    # minute boundary.
    step_diffs: list[tuple[int, float]] = []
    for index in range(1, len(medians)):
        delta = medians[index] - medians[index - 1]
        if delta >= step_kib:
            step_diffs.append((index, delta))
    step_events: list[list[tuple[int, float]]] = []
    for index, delta in step_diffs:
        if step_events and index - step_events[-1][-1][0] <= 1:
            step_events[-1].append((index, delta))
        else:
            step_events.append([(index, delta)])

    # Remove each detected jump from the following values.  The remaining
    # series shows a leak as a slope, while allocator steps disappear.
    step_at: dict[int, float] = {}
    for index, delta in step_diffs:
        step_at[index] = step_at.get(index, 0.0) + delta
    detrended: list[float] = []
    removed = 0.0
    for index, value in enumerate(medians):
        removed += step_at.get(index, 0.0)
        detrended.append(value - removed)

    quarter = len(detrended) // 4
    points = list(enumerate(detrended[quarter:], start=quarter))
    slope = _theil_sen_slope(points)
    peak = max(values)
    second_half = len(detrended) // 2
    late_steps = [
        event for event in step_events if event[0][0] >= second_half
    ]
    oversized_steps = [
        event
        for event in step_events
        if sum(delta for _, delta in event) > max_step_kib
    ]
    reasons: list[str] = []
    if slope > slope_kib_per_min:
        reasons.append(
            f"RSS slope {slope:.0f} KiB/min exceeds {slope_kib_per_min} KiB/min"
        )
    if len(late_steps) > max_late_steps:
        reasons.append(
            f"{len(late_steps)} late RSS steps exceed {max_late_steps}"
        )
    if oversized_steps:
        reasons.append(
            f"{len(oversized_steps)} RSS step(s) exceed {max_step_kib} KiB"
        )
    if peak > peak_kib:
        reasons.append(f"RSS peak {peak} KiB exceeds {peak_kib} KiB")

    events = [
        {
            "minute": event[0][0],
            "delta_kib": round(sum(delta for _, delta in event)),
            "late": event[0][0] >= second_half,
        }
        for event in step_events
    ]
    return {
        "ok": not reasons,
        "reason": "; ".join(reasons) if reasons else "plateau",
        "samples": len(values),
        "windows": len(medians),
        "quarter_start_window": quarter,
        "second_half_window": second_half,
        "slope_kib_per_min": round(slope, 1),
        "threshold_slope_kib_per_min": slope_kib_per_min,
        "steps": events,
        "late_steps": len(late_steps),
        "threshold_max_late_steps": max_late_steps,
        "threshold_step_kib": step_kib,
        "threshold_max_step_kib": max_step_kib,
        "peak_kib": peak,
        "threshold_peak_kib": peak_kib,
        "minute_medians_kib": [round(value) for value in medians],
    }
