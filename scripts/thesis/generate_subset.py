#!/usr/bin/env python3
"""
Generate a balanced subset of OWASP Benchmark tests for thesis experiment.

This script creates a reproducible subset of ~500 tests with proportional
representation of true vulnerabilities and false positives from each category.
"""

import csv
import random
from pathlib import Path
from collections import defaultdict

SEED = 42
TESTS_PER_CATEGORY = 50

EXPECTED_RESULTS_FILE = Path(__file__).parent.parent.parent / "expectedresults-1.2.csv"
OUTPUT_FILE = Path(__file__).parent / "subset_tests.csv"


def load_expected_results(filepath: Path) -> list[dict]:
    """Load and parse the expected results CSV file."""
    tests = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            if len(parts) >= 4:
                tests.append({
                    "test_name": parts[0],
                    "category": parts[1],
                    "is_vulnerable": parts[2].lower() == "true",
                    "cwe": parts[3]
                })
    return tests


def group_by_category(tests: list[dict]) -> dict[str, dict[str, list[dict]]]:
    """Group tests by category and vulnerability status."""
    grouped = defaultdict(lambda: {"true": [], "false": []})
    for test in tests:
        key = "true" if test["is_vulnerable"] else "false"
        grouped[test["category"]][key].append(test)
    return grouped


def select_subset(grouped: dict, tests_per_category: int, seed: int) -> list[dict]:
    """Select a balanced subset from each category."""
    random.seed(seed)
    subset = []
    
    for category, vuln_groups in sorted(grouped.items()):
        true_vulns = vuln_groups["true"]
        false_positives = vuln_groups["false"]
        
        total_available = len(true_vulns) + len(false_positives)
        target = min(tests_per_category, total_available)
        
        true_ratio = len(true_vulns) / total_available if total_available > 0 else 0.5
        true_count = round(target * true_ratio)
        false_count = target - true_count
        
        true_count = min(true_count, len(true_vulns))
        false_count = min(false_count, len(false_positives))
        
        if true_count < round(target * true_ratio):
            false_count = min(target - true_count, len(false_positives))
        elif false_count < target - round(target * true_ratio):
            true_count = min(target - false_count, len(true_vulns))
        
        selected_true = random.sample(true_vulns, true_count)
        selected_false = random.sample(false_positives, false_count)
        
        subset.extend(selected_true)
        subset.extend(selected_false)
        
        print(f"{category}: {true_count} true + {false_count} false = {true_count + false_count} tests")
    
    return subset


def save_subset(subset: list[dict], filepath: Path) -> None:
    """Save the subset to a CSV file."""
    subset_sorted = sorted(subset, key=lambda x: x["test_name"])
    
    with open(filepath, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["test_name", "category", "is_vulnerable", "cwe"])
        for test in subset_sorted:
            writer.writerow([
                test["test_name"],
                test["category"],
                str(test["is_vulnerable"]).lower(),
                test["cwe"]
            ])
    
    print(f"\nSaved {len(subset)} tests to {filepath}")


def main():
    print(f"Loading expected results from {EXPECTED_RESULTS_FILE}")
    tests = load_expected_results(EXPECTED_RESULTS_FILE)
    print(f"Loaded {len(tests)} total tests\n")
    
    grouped = group_by_category(tests)
    
    print(f"Selecting ~{TESTS_PER_CATEGORY} tests per category (seed={SEED}):\n")
    subset = select_subset(grouped, TESTS_PER_CATEGORY, SEED)
    
    true_count = sum(1 for t in subset if t["is_vulnerable"])
    false_count = len(subset) - true_count
    print(f"\nTotal: {len(subset)} tests ({true_count} true vulnerabilities, {false_count} false positives)")
    
    save_subset(subset, OUTPUT_FILE)


if __name__ == "__main__":
    main()
