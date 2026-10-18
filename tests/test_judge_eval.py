"""The judge evaluation harness: statistics, cache keys and the dev selection rule."""

import importlib.util
import math
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location(
    "judge_eval", Path(__file__).resolve().parents[1] / "eval" / "judge_eval.py"
)
judge_eval = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(judge_eval)


def test_wilson_interval_matches_known_values():
    lo, hi = judge_eval.wilson(5, 100)
    assert (round(lo, 4), round(hi, 4)) == (0.0215, 0.1118)
    assert judge_eval.wilson(0, 10)[0] == 0.0
    assert all(math.isnan(x) for x in judge_eval.wilson(0, 0))


def test_cache_key_ignores_titles_unless_they_are_sent():
    key = judge_eval.request_key
    assert key("m", "v", "low", "text", "hi", ["A"]) == key("m", "v", "low", "text", "hi", ["B"])
    assert key("m", "v", "low", "titles", "hi", ["A"]) != key("m", "v", "low", "titles", "hi", ["B"])
    assert key("m", "v", "low", "text", "hi") != key("m", "v", "medium", "text", "hi")
    assert key("m", "v1", "low", "text", "hi") != key("m", "v2", "low", "text", "hi")


def test_cost_uses_cached_token_prices():
    rec = {"input_tokens": 1_000_000, "cache_read_input_tokens": 1_000_000, "cache_creation_input_tokens": 0,
           "output_tokens": 1_000_000}
    assert judge_eval.cost_usd(rec) == pytest.approx(0.10 + 0.01 + 0.50)


def _rows_and_grid(false_close, benign_close):
    """One config per entry: 100 attacks and 100 benign rows with the given rates."""
    rows = [{"label": 1, "subset": "s"}] * 100 + [{"label": 0, "subset": "s"}] * 100
    grid = {}
    for cfg, fc, bc in zip([("low", "text"), ("low", "titles"), ("medium", "text"), ("medium", "titles")],
                           false_close, benign_close):
        attacks = [{"status": "ok", "verdict": "benign"}] * fc + [{"status": "ok", "verdict": "injection"}] * (100 - fc)
        benign = [{"status": "ok", "verdict": "benign"}] * bc + [{"status": "ok", "verdict": "uncertain"}] * (100 - bc)
        grid[cfg] = attacks + benign
    return rows, grid


def test_selection_takes_best_close_rate_within_the_miss_budget():
    rows, grid = _rows_and_grid(false_close=[2, 5, 3, 1], benign_close=[60, 90, 70, 65])
    choice, eligible = judge_eval.select(rows, grid)
    assert ("low", "titles") not in eligible  # 5% false-close is over the 3% budget
    assert choice == ("medium", "text")


def test_selection_falls_back_to_lowest_false_close():
    rows, grid = _rows_and_grid(false_close=[9, 5, 7, 6], benign_close=[90, 10, 90, 90])
    assert judge_eval.select(rows, grid) == (("low", "titles"), [])


def test_failures_never_count_as_closed():
    s = judge_eval.band_stats([(1, {"status": "timeout", "verdict": None}), (1, {"status": "ok", "verdict": "benign"})])
    assert (s["attack"], s["attack:benign"], s["failed"]) == (2, 1, 1)
