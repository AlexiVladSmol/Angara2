#!/usr/bin/env python3
"""Synthetic regressions for the RSS plateau checker."""

from __future__ import annotations

import unittest

from soak_rss import evaluate_rss


def samples(values: list[int]) -> list[dict[str, object]]:
    return [{"t": float(index), "rss_kib": value} for index, value in enumerate(values)]


class RssPlateauTest(unittest.TestCase):
    def test_allocator_plateau_passes(self) -> None:
        values = [200_000 + min(index, 40) * 100 for index in range(400)]
        result = evaluate_rss(samples(values))
        self.assertTrue(result["ok"], result)

    def test_initial_ramp_then_plateau_passes(self) -> None:
        values = [160_000 + min(index * 300, 60_000) for index in range(400)]
        result = evaluate_rss(samples(values))
        self.assertTrue(result["ok"], result)

    def test_synthetic_ongoing_leak_fails(self) -> None:
        values = [200_000 + index * 2_048 for index in range(400)]
        result = evaluate_rss(samples(values))
        self.assertFalse(result["ok"], result)
        self.assertTrue(
            result["growth_kib"] > result["threshold_growth_kib"]
            or result["peak_gap_kib"] > result["threshold_peak_gap_kib"],
            result,
        )

    def test_absolute_peak_fails(self) -> None:
        values = [600_000 for _ in range(400)]
        result = evaluate_rss(samples(values))
        self.assertFalse(result["ok"], result)


if __name__ == "__main__":
    unittest.main()
