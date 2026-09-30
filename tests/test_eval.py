"""Label handling in the evaluation harness. A bad mapping here would silently skew every metric."""

import importlib.util
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location(
    "run_eval", Path(__file__).resolve().parents[1] / "eval" / "run_eval.py"
)
run_eval = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(run_eval)


def test_numeric_labels_pass_through():
    assert run_eval.to_label(1, None) == 1
    assert run_eval.to_label("0", None) == 0


def test_non_binary_numeric_label_is_rejected():
    with pytest.raises(SystemExit):
        run_eval.to_label(2, None)


def test_string_labels_map_against_positive():
    assert run_eval.to_label("jailbreak", "jailbreak") == 1
    assert run_eval.to_label("benign", "jailbreak") == 0


def test_string_label_without_positive_is_rejected():
    with pytest.raises(SystemExit):
        run_eval.to_label("jailbreak", None)


def test_bundled_sample_set_is_binary_and_balanced():
    rows = run_eval.load_local(run_eval.DEFAULT_DATASET)
    labels = [label for _, label in rows]
    assert set(labels) == {0, 1}
    assert labels.count(1) == labels.count(0)
