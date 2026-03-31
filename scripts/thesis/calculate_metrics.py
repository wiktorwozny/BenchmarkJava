#!/usr/bin/env python3
"""
Calculate security metrics by comparing tool output with ground truth.

This script parses output from SAST tools (SARIF format) or LLM analyzers (JSON format),
maps findings to OWASP Benchmark test cases, and calculates Precision,
Recall, and F1 scores both globally and per vulnerability category.
"""

from __future__ import annotations

import json
import csv
import re
import argparse
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Tuple

SUBSET_FILE = Path(__file__).parent / "subset_tests.csv"

CWE_TO_CATEGORY = {
    "22": "pathtraver",
    "78": "cmdi",
    "79": "xss",
    "89": "sqli",
    "90": "ldapi",
    "327": "crypto",
    "328": "hash",
    "330": "weakrand",
    "501": "trustbound",
    "614": "securecookie",
    "643": "xpathi",
}


@dataclass
class GroundTruth:
    """Ground truth data for a test case."""
    test_name: str
    category: str
    is_vulnerable: bool
    cwe: str


@dataclass
class Finding:
    """A finding from the SAST tool."""
    test_name: str
    rule_id: str
    cwe: str | None
    message: str
    severity: str
    file_path: str


@dataclass
class CategoryMetrics:
    """Metrics for a single category."""
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    
    @property
    def precision(self) -> float:
        if self.tp + self.fp == 0:
            return 0.0
        return self.tp / (self.tp + self.fp)
    
    @property
    def recall(self) -> float:
        if self.tp + self.fn == 0:
            return 0.0
        return self.tp / (self.tp + self.fn)
    
    @property
    def f1(self) -> float:
        if self.precision + self.recall == 0:
            return 0.0
        return 2 * (self.precision * self.recall) / (self.precision + self.recall)
    
    def to_dict(self) -> dict:
        return {
            "TP": self.tp,
            "FP": self.fp,
            "FN": self.fn,
            "TN": self.tn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
        }


def load_ground_truth(filepath: Path) -> dict[str, GroundTruth]:
    """Load ground truth from subset CSV."""
    ground_truth = {}
    with open(filepath, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            gt = GroundTruth(
                test_name=row["test_name"],
                category=row["category"],
                is_vulnerable=row["is_vulnerable"].lower() == "true",
                cwe=row["cwe"]
            )
            ground_truth[gt.test_name] = gt
    return ground_truth


def extract_test_name(file_path: str) -> str | None:
    """Extract BenchmarkTest##### from file path."""
    match = re.search(r"(BenchmarkTest\d+)", file_path)
    return match.group(1) if match else None


def extract_cwe(tags: list[str] | None) -> str | None:
    """Extract CWE number from SARIF tags."""
    if not tags:
        return None
    for tag in tags:
        if tag.startswith("CWE-"):
            return tag[4:]
        match = re.search(r"cwe[:\-]?(\d+)", tag, re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def parse_sarif(sarif_path: Path) -> tuple[list[Finding], dict]:
    """Parse SARIF file and extract findings."""
    with open(sarif_path, "r") as f:
        sarif = json.load(f)
    
    findings = []
    tool_info = {}
    
    for run in sarif.get("runs", []):
        tool = run.get("tool", {}).get("driver", {})
        tool_info = {
            "name": tool.get("name", "unknown"),
            "version": tool.get("semanticVersion", tool.get("version", "unknown")),
        }
        
        rules = {r["id"]: r for r in tool.get("rules", [])}
        
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            rule = rules.get(rule_id, {})
            
            tags = rule.get("properties", {}).get("tags", [])
            cwe = extract_cwe(tags)
            
            for location in result.get("locations", []):
                physical = location.get("physicalLocation", {})
                artifact = physical.get("artifactLocation", {})
                file_path = artifact.get("uri", "")
                
                test_name = extract_test_name(file_path)
                if test_name:
                    findings.append(Finding(
                        test_name=test_name,
                        rule_id=rule_id,
                        cwe=cwe,
                        message=result.get("message", {}).get("text", ""),
                        severity=rule.get("defaultConfiguration", {}).get("level", "warning"),
                        file_path=file_path
                    ))
    
    return findings, tool_info


def parse_llm_results(llm_path: Path) -> tuple[list[Finding], dict]:
    """Parse LLM analyzer JSON output and extract findings."""
    with open(llm_path, "r") as f:
        data = json.load(f)
    
    tool_info = {
        "name": f"LLM ({data.get('model', 'unknown')})",
        "version": data.get('model', 'unknown'),
    }
    
    findings = []
    for result in data.get("results", []):
        if result.get("is_vulnerable", False):
            category = result.get("category", "")
            cwe = None
            for cwe_num, cat in CWE_TO_CATEGORY.items():
                if cat == category:
                    cwe = cwe_num
                    break
            
            findings.append(Finding(
                test_name=result["test_name"],
                rule_id=f"llm-{category}",
                cwe=cwe,
                message=result.get("reasoning", ""),
                severity="warning",
                file_path=f"{result['test_name']}.java"
            ))
    
    return findings, tool_info


def parse_filtered_results(filtered_path: Path) -> tuple[list[Finding], dict]:
    """Parse SAST+LLM filtered results JSON (Stage 3 output)."""
    with open(filtered_path, "r") as f:
        data = json.load(f)
    
    tool_info = {
        "name": f"SAST+LLM ({data.get('model', 'unknown')})",
        "version": data.get('model', 'unknown'),
        "original_findings": data.get("original_findings", 0),
        "filtered_out": data.get("filtered_out", 0),
    }
    
    findings = []
    for result in data.get("results", []):
        if result.get("is_true_positive", False):
            findings.append(Finding(
                test_name=result["test_name"],
                rule_id=result.get("original_rule_id", "unknown"),
                cwe=None,
                message=result.get("reasoning", ""),
                severity="warning",
                file_path=f"{result['test_name']}.java"
            ))
    
    return findings, tool_info


def calculate_metrics(
    ground_truth: dict[str, GroundTruth],
    findings: list[Finding]
) -> tuple[CategoryMetrics, dict[str, CategoryMetrics], dict]:
    """Calculate metrics comparing findings to ground truth."""
    
    detected_tests = set(f.test_name for f in findings)
    
    global_metrics = CategoryMetrics()
    category_metrics = defaultdict(CategoryMetrics)
    
    details = {
        "true_positives": [],
        "false_positives": [],
        "false_negatives": [],
        "true_negatives": [],
    }
    
    for test_name, gt in ground_truth.items():
        detected = test_name in detected_tests
        
        if gt.is_vulnerable and detected:
            global_metrics.tp += 1
            category_metrics[gt.category].tp += 1
            details["true_positives"].append(test_name)
        elif not gt.is_vulnerable and detected:
            global_metrics.fp += 1
            category_metrics[gt.category].fp += 1
            details["false_positives"].append(test_name)
        elif gt.is_vulnerable and not detected:
            global_metrics.fn += 1
            category_metrics[gt.category].fn += 1
            details["false_negatives"].append(test_name)
        else:
            global_metrics.tn += 1
            category_metrics[gt.category].tn += 1
            details["true_negatives"].append(test_name)
    
    return global_metrics, dict(category_metrics), details


def generate_report(
    tool_info: dict,
    global_metrics: CategoryMetrics,
    category_metrics: dict[str, CategoryMetrics],
    subset_size: int,
    details: dict
) -> str:
    """Generate a markdown report."""
    lines = [
        "# SAST Analysis Report",
        "",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Tool:** {tool_info.get('name', 'unknown')} v{tool_info.get('version', 'unknown')}",
        f"**Test subset size:** {subset_size}",
        "",
        "## Global Metrics",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| True Positives (TP) | {global_metrics.tp} |",
        f"| False Positives (FP) | {global_metrics.fp} |",
        f"| False Negatives (FN) | {global_metrics.fn} |",
        f"| True Negatives (TN) | {global_metrics.tn} |",
        f"| **Precision** | {global_metrics.precision:.2%} |",
        f"| **Recall** | {global_metrics.recall:.2%} |",
        f"| **F1 Score** | {global_metrics.f1:.2%} |",
        "",
        "## Metrics by Category",
        "",
        "| Category | TP | FP | FN | TN | Precision | Recall | F1 |",
        "|----------|----|----|----|----|-----------|--------|-----|",
    ]
    
    for category in sorted(category_metrics.keys()):
        m = category_metrics[category]
        lines.append(
            f"| {category} | {m.tp} | {m.fp} | {m.fn} | {m.tn} | "
            f"{m.precision:.2%} | {m.recall:.2%} | {m.f1:.2%} |"
        )
    
    lines.extend([
        "",
        "## Interpretation",
        "",
        f"- **Precision ({global_metrics.precision:.2%})**: Of all vulnerabilities reported by the tool, "
        f"{global_metrics.precision:.2%} were actual vulnerabilities.",
        f"- **Recall ({global_metrics.recall:.2%})**: Of all actual vulnerabilities in the code, "
        f"{global_metrics.recall:.2%} were detected by the tool.",
        "",
        "## Details",
        "",
        f"### False Positives ({len(details['false_positives'])} tests)",
        "",
        "These are tests that were flagged as vulnerable but are actually safe:",
        "",
    ])
    
    for test in sorted(details["false_positives"])[:20]:
        lines.append(f"- {test}")
    if len(details["false_positives"]) > 20:
        lines.append(f"- ... and {len(details['false_positives']) - 20} more")
    
    lines.extend([
        "",
        f"### False Negatives ({len(details['false_negatives'])} tests)",
        "",
        "These are actual vulnerabilities that were not detected:",
        "",
    ])
    
    for test in sorted(details["false_negatives"])[:20]:
        lines.append(f"- {test}")
    if len(details["false_negatives"]) > 20:
        lines.append(f"- ... and {len(details['false_negatives']) - 20} more")
    
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Calculate security metrics against OWASP Benchmark")
    parser.add_argument("results_file", type=Path, help="Path to results file (SARIF or LLM JSON)")
    parser.add_argument("--output-dir", type=Path, default=Path("."), help="Output directory for results")
    parser.add_argument("--subset-file", type=Path, default=SUBSET_FILE, help="Path to subset CSV")
    parser.add_argument(
        "--input-format",
        type=str,
        choices=["sarif", "llm", "filtered"],
        default="sarif",
        help="Input format: 'sarif' for SAST tools, 'llm' for LLM analyzer, 'filtered' for SAST+LLM (default: sarif)"
    )
    args = parser.parse_args()
    
    print(f"Loading ground truth from {args.subset_file}")
    ground_truth = load_ground_truth(args.subset_file)
    print(f"Loaded {len(ground_truth)} test cases")
    
    print(f"Parsing {args.input_format.upper()} file {args.results_file}")
    if args.input_format == "sarif":
        findings, tool_info = parse_sarif(args.results_file)
    elif args.input_format == "llm":
        findings, tool_info = parse_llm_results(args.results_file)
    else:
        findings, tool_info = parse_filtered_results(args.results_file)
    print(f"Found {len(findings)} findings from {tool_info.get('name', 'unknown')}")
    
    relevant_findings = [f for f in findings if f.test_name in ground_truth]
    print(f"Relevant findings (in subset): {len(relevant_findings)}")
    
    global_metrics, category_metrics, details = calculate_metrics(ground_truth, relevant_findings)
    
    print(f"\nResults:")
    print(f"  Precision: {global_metrics.precision:.2%}")
    print(f"  Recall:    {global_metrics.recall:.2%}")
    print(f"  F1 Score:  {global_metrics.f1:.2%}")
    
    args.output_dir.mkdir(parents=True, exist_ok=True)
    
    metrics_output = {
        "tool": tool_info,
        "subset_size": len(ground_truth),
        "total_findings": len(findings),
        "relevant_findings": len(relevant_findings),
        "metrics": global_metrics.to_dict(),
        "by_category": {cat: m.to_dict() for cat, m in category_metrics.items()},
        "generated_at": datetime.now().isoformat(),
    }
    
    metrics_file = args.output_dir / "metrics.json"
    with open(metrics_file, "w") as f:
        json.dump(metrics_output, f, indent=2)
    print(f"\nSaved metrics to {metrics_file}")
    
    report = generate_report(tool_info, global_metrics, category_metrics, len(ground_truth), details)
    report_file = args.output_dir / "report.md"
    with open(report_file, "w") as f:
        f.write(report)
    print(f"Saved report to {report_file}")
    
    details_output = {
        "true_positives": sorted(details["true_positives"]),
        "false_positives": sorted(details["false_positives"]),
        "false_negatives": sorted(details["false_negatives"]),
        "true_negatives": sorted(details["true_negatives"]),
    }
    details_file = args.output_dir / "details.json"
    with open(details_file, "w") as f:
        json.dump(details_output, f, indent=2)
    print(f"Saved details to {details_file}")


if __name__ == "__main__":
    main()
