"""Run-level evaluation metrics. Pure functions; no I/O and no process actions.

The experimental unit is a workload run, never an individual notification.
Primary positive criterion: at least one scored assessment reached High
(score >= the frozen high threshold) inside the run's observation window.
Uncertain runs are tabulated separately and are not silently converted.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import statistics

LEVELS = ("High", "Uncertain", "Low", "No scored evidence")
PRIMARY_CRITERION = "high"          # positive = max level High
SENSITIVITY_CRITERION = "uncertain"  # positive = max level Uncertain or High (sensitivity analysis only)


def outcome_level(max_level: str | None) -> str:
    return max_level if max_level in {"High", "Uncertain", "Low"} else "No scored evidence"


def predicted_positive(max_level: str | None, criterion: str = PRIMARY_CRITERION) -> bool:
    level = outcome_level(max_level)
    if criterion == PRIMARY_CRITERION:
        return level == "High"
    if criterion == SENSITIVITY_CRITERION:
        return level in {"High", "Uncertain"}
    raise ValueError(f"Unknown criterion: {criterion}")


def ratio(numerator: int, denominator: int) -> dict:
    """A rate with its counts; 'undefined' rather than 0 when the denominator is 0."""
    return {"value": (numerator / denominator) if denominator else None,
            "numerator": numerator, "denominator": denominator,
            "display": f"{numerator}/{denominator} = {numerator / denominator:.3f}" if denominator else
                       f"{numerator}/{denominator} = undefined"}


def confusion(runs: list[dict], criterion: str = PRIMARY_CRITERION) -> dict:
    counts = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    for run in runs:
        positive = predicted_positive(run.get("max_level"), criterion)
        if run["label"] == "suspicious":
            counts["TP" if positive else "FN"] += 1
        elif run["label"] == "benign":
            counts["FP" if positive else "TN"] += 1
        else:
            raise ValueError(f"Unknown label: {run['label']}")
    return counts


def detection_metrics(counts: dict) -> dict:
    tp, fp, tn, fn = counts["TP"], counts["FP"], counts["TN"], counts["FN"]
    return {
        "precision": ratio(tp, tp + fp),
        "recall": ratio(tp, tp + fn),
        "f1": ratio(2 * tp, 2 * tp + fp + fn),
        "benign_alert_rate": ratio(fp, fp + tn),
        "specificity": ratio(tn, fp + tn),
    }


def level_table(runs: list[dict]) -> dict:
    table = {label: {level: 0 for level in LEVELS} for label in ("benign", "suspicious")}
    for run in runs:
        table[run["label"]][outcome_level(run.get("max_level"))] += 1
    return table


def distribution(values: list[float]) -> dict:
    values = sorted(v for v in values if v is not None)
    if not values:
        return {"n": 0, "median": None, "min": None, "max": None, "p25": None, "p75": None}
    quartiles = statistics.quantiles(values, n=4, method="inclusive") if len(values) >= 2 else [values[0]] * 3
    return {"n": len(values), "median": statistics.median(values), "min": values[0], "max": values[-1],
            "p25": quartiles[0], "p75": quartiles[2]}


def match_coverage(expected: list[dict], observed: list[dict]) -> dict:
    """Compare expected path notifications with observed ones (relative paths).

    Each expected (path, operation) counts once however many notifications
    arrive. Paths are compared case-insensitively, as on Windows.
    """
    def key(path: str) -> str:
        return path.replace("\\", "/").casefold()

    observed_pairs = Counter((key(o["path"]), o["operation"]) for o in observed)
    observed_paths = {key(o["path"]) for o in observed}
    wanted = {(key(e["path"]), e["operation"]) for e in expected}
    exact = {pair for pair in wanted if observed_pairs[pair]}
    any_op = {pair for pair in wanted if pair[0] in observed_paths}
    expected_paths = {pair[0] for pair in wanted}
    return {
        # Repeated edits of one file collapse to one expected (path, operation);
        # these two counts expose repeats that a collector may coalesce.
        "planned_notifying_actions": len(expected),
        "matching_notifications": sum(observed_pairs[pair] for pair in wanted),
        "expected_notifications": len(wanted),
        "observed_exact": len(exact),
        "observed_path_any_operation": len(any_op),
        "exact_coverage": ratio(len(exact), len(wanted)),
        "path_coverage": ratio(len(any_op), len(wanted)),
        "missing": sorted(f"{op}:{path}" for path, op in wanted - any_op),
        "operation_mismatch": sorted(f"{op}:{path}" for path, op in any_op - exact),
        "duplicate_notifications": sum(max(0, observed_pairs[pair] - 1) for pair in exact),
        "unexpected_paths": sorted(observed_paths - expected_paths),
    }


def indicator_summary(runs: list[dict]) -> dict:
    """Median points per indicator at each run's peak assessment, by label."""
    result = {}
    for label in ("benign", "suspicious"):
        points = defaultdict(list)
        for run in runs:
            if run["label"] != label:
                continue
            for signal in run.get("peak_signals") or []:
                points[signal["name"]].append(signal["points"])
        result[label] = {name: distribution(values) for name, values in points.items()}
    return result


def summarize(runs: list[dict]) -> dict:
    """Aggregate completed runs; failed runs are reported, never scored."""
    completed = [r for r in runs if r.get("status") == "completed"]
    failed = [{"run_id": r.get("run_id"), "workload_id": r.get("workload_id"), "error": r.get("error")}
              for r in runs if r.get("status") != "completed"]

    def block(selected: list[dict]) -> dict:
        primary = confusion(selected, PRIMARY_CRITERION)
        sensitivity = confusion(selected, SENSITIVITY_CRITERION)
        tp_latency = [r["timings"].get("detection_latency_s") for r in selected
                      if r["label"] == "suspicious" and predicted_positive(r.get("max_level"))]
        delivery = [r["timings"].get("delivery_delay_s") for r in selected]
        return {
            "runs": len(selected),
            "primary_criterion": "max level High (score >= high threshold)",
            "confusion": primary,
            "metrics": detection_metrics(primary),
            "outcome_levels_by_label": level_table(selected),
            "sensitivity_uncertain_or_high": {"confusion": sensitivity, "metrics": detection_metrics(sensitivity),
                                              "note": "Sensitivity analysis only; not the predeclared criterion."},
            "detection_latency_s_true_positives": distribution(tp_latency),
            "delivery_delay_s_all_runs": distribution(delivery),
            "peak_score_by_label": {label: distribution([r.get("peak_score") for r in selected if r["label"] == label])
                                    for label in ("benign", "suspicious")},
            "exact_coverage_by_label": {label: distribution([r["coverage"]["exact_coverage"]["value"]
                                                             for r in selected if r["label"] == label])
                                        for label in ("benign", "suspicious")},
            "late_unscored_observations": sum(r["evidence"]["late_observations"] for r in selected),
            "dropped_notifications": sum(r["evidence"]["dropped_notifications"] for r in selected),
            "indicator_points_at_peak": indicator_summary(selected),
        }

    return {
        "completed_runs": len(completed),
        "failed_runs": failed,
        "overall": block(completed),
        "by_split": {split: block([r for r in completed if r["split"] == split])
                     for split in sorted({r["split"] for r in completed})},
        "per_workload": [{"workload_id": r["workload_id"], "label": r["label"], "split": r["split"],
                          "repeat": r.get("repeat"), "max_level": outcome_level(r.get("max_level")),
                          "peak_score": r.get("peak_score"),
                          "detection_latency_s": r["timings"].get("detection_latency_s"),
                          "exact_coverage": r["coverage"]["exact_coverage"]["display"]}
                         for r in completed],
    }
