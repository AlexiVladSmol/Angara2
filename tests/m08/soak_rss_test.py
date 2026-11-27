#!/usr/bin/env python3
"""Synthetic regressions for the RSS plateau checker."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from soak_rss import evaluate_rss

FIXTURES = json.loads(
    Path(__file__).with_name("soak_rss_fixtures.json").read_text(encoding="utf-8")
)
MIB = 1024


def samples(values: list[int]) -> list[dict[str, object]]:
    return [{"t": float(index), "rss_kib": value} for index, value in enumerate(values)]


def with_step(values: list[int], percent: int, delta_kib: int) -> list[int]:
    start = max(0, min(len(values) - 1, len(values) * percent // 100))
    return [
        value + (delta_kib if index >= start else 0)
        for index, value in enumerate(values)
    ]


def with_leak(values: list[int], mib_per_hour: int) -> list[int]:
    return [
        value + index * mib_per_hour * MIB // 60
        for index, value in enumerate(values)
    ]


class RssPlateauTest(unittest.TestCase):
    def test_real_soak_series_pass(self) -> None:
        for run, values in FIXTURES.items():
            with self.subTest(run=run):
                result = evaluate_rss(samples(values))
                self.assertTrue(result["ok"], result)

    def test_single_late_allocator_step_passes(self) -> None:
        for run, values in FIXTURES.items():
            for percent in (60, 80, 90, 95):
                with self.subTest(run=run, percent=percent):
                    result = evaluate_rss(samples(with_step(values, percent, 20 * MIB)))
                    self.assertTrue(result["ok"], result)

    def test_step_split_across_two_minutes_is_one_event(self) -> None:
        values = [200_000 + index for index in range(60)]
        values = [
            value + (10 * MIB if 48 <= index < 49 else 20 * MIB if index >= 49 else 0)
            for index, value in enumerate(values)
        ]
        result = evaluate_rss(samples(values))
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["late_steps"], 1, result)

    def test_linear_leak_below_absolute_limit_fails(self) -> None:
        for run, values in FIXTURES.items():
            for rate in (16, 24, 32):
                with self.subTest(run=run, mib_per_hour=rate):
                    result = evaluate_rss(samples(with_leak(values, rate)))
                    self.assertFalse(result["ok"], result)
                    self.assertIn("slope", result["reason"], result)

    def test_allocator_sized_staircase_fails(self) -> None:
        for run, values in FIXTURES.items():
            with self.subTest(run=run):
                staircase = values[:]
                for minute in (30, 40, 50):
                    staircase = [
                        value + (20 * MIB if index >= minute else 0)
                        for index, value in enumerate(staircase)
                    ]
                result = evaluate_rss(samples(staircase))
                self.assertFalse(result["ok"], result)
                self.assertIn("late RSS steps", result["reason"], result)

    def test_oversized_allocator_step_fails(self) -> None:
        values = FIXTURES["45827741649"]
        result = evaluate_rss(samples(with_step(values, 80, 80 * MIB)))
        self.assertFalse(result["ok"], result)
        self.assertIn("exceed", result["reason"], result)

    def test_absolute_peak_fails(self) -> None:
        result = evaluate_rss(samples([600_000 for _ in range(400)]))
        self.assertFalse(result["ok"], result)
        self.assertIn("peak", result["reason"], result)

    def test_too_few_samples_fails(self) -> None:
        result = evaluate_rss(samples([200_000]))
        self.assertFalse(result["ok"], result)
        self.assertIn("not enough", result["reason"], result)


if __name__ == "__main__":
    unittest.main()
