from decimal import Decimal

import pytest

from src.metrics.metrics import Metrics

test_sample_a: Metrics = Metrics(tp=10, fp=90, fn=3)

print(f"Recall: {format(test_sample_a.recall, '.4f')}")
print(f"Precision: {format(test_sample_a.precision, '.4f')}")
print(f"F1 Score: {format(test_sample_a.f1_score, '.4f')}")
print(f"FNR: {format(test_sample_a.false_negative_rate, '.4f')}")


def test_str_input_data():
    with pytest.raises(TypeError) as e:
        metric = Metrics(tp="1", fp=90, fn=3)


def test_negative_int_input():
    with pytest.raises(ValueError) as e:
        metric = Metrics(tp=-1, fp=90, fn=3)


def test_expected_metrics_results():
    tp: int = 1
    fp: int = 9
    fn: int = 3
    metric = Metrics(tp=1, fp=9, fn=3)
    assert metric.precision == Decimal(tp) / Decimal(tp + fp)
    assert metric.recall == Decimal(tp) / Decimal(tp + fn)
    assert metric.f1_score == Decimal(2 * tp) / Decimal(2 * tp + fp + fn)
    assert metric.false_negative_rate == Decimal(fn) / Decimal(fn + tp)


def test_correct_handling_of_zero():
    tp: int = 0
    fp: int = 10
    fn: int = 3
    metric = Metrics(tp=0, fp=10, fn=3)
    assert metric.precision == Decimal(0)
    assert metric.recall == Decimal(0)
    assert metric.f1_score == Decimal(0)
    assert metric.false_negative_rate == Decimal(fn) / Decimal(fn + tp)
