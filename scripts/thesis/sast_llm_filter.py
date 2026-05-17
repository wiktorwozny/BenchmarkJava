#!/usr/bin/env python3
"""
SAST + LLM Filter for OWASP Benchmark (Stage 3).

This script takes SAST (Semgrep) findings and uses an LLM to verify each finding,
filtering out false positives while preserving true positives.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional

import instructor
import openai

from llm_models import (
    VerificationResult,
    BatchVerification,
)


DEFAULT_MODEL = "openai/gpt-4o-mini"
DEFAULT_BATCH_SIZE = 10
DEFAULT_TEMPERATURE = 0.1
DEFAULT_MAX_RETRIES = 3
DEFAULT_MAX_WORKERS = 5

TESTCODE_DIR = Path(__file__).parent.parent.parent / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode"
SUBSET_FILE = Path(__file__).parent / "subset_tests.csv"


@dataclass
class SastFinding:
    """A finding from SAST tool (Semgrep)."""
    test_name: str
    rule_id: str
    message: str
    severity: str
    line: int
    cwe: Optional[str] = None


def get_verification_system_prompt() -> str:
    """Generate the system prompt for SAST finding verification."""
    return """You are an expert security analyst verifying findings from a Static Application Security Testing (SAST) tool.

## Your Task
For each SAST finding, determine whether it is:
- **TRUE POSITIVE**: A real, exploitable security vulnerability
- **FALSE POSITIVE**: A false alarm that should be filtered out

## How to Identify FALSE POSITIVES:
1. **Dead code paths**: The tainted data never actually reaches the sink due to conditional logic
2. **Constant values**: A variable is assigned a constant value, not user input
3. **Sanitization**: User input is properly validated, escaped, or encoded before use
4. **Safe APIs**: The code uses parameterized queries, prepared statements, or other safe APIs
5. **Unreachable conditions**: An if/switch condition always evaluates to a safe branch

## Analysis Process:
1. Read the SAST finding (rule ID, message, line number)
2. Examine the code to trace data flow from SOURCE to SINK
3. Check if user-controlled data actually reaches the dangerous operation
4. Look for any sanitization or validation along the path
5. Determine if the vulnerability is actually exploitable

## Response Format
For each finding, provide:
- test_name: The test file name
- original_rule_id: The SAST rule that triggered
- is_true_positive: true if real vulnerability, false if should be filtered
- confidence: Your confidence level (0.0-1.0)
- reasoning: Brief explanation (1-2 sentences)"""


def extract_test_name(file_path: str) -> Optional[str]:
    """Extract BenchmarkTest##### from file path."""
    match = re.search(r"(BenchmarkTest\d+)", file_path)
    return match.group(1) if match else None


def extract_cwe(tags: List[str]) -> Optional[str]:
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


def load_sast_findings(sarif_path: Path, subset_tests: Optional[set] = None) -> List[SastFinding]:
    """Parse SARIF file and extract findings."""
    with open(sarif_path, "r") as f:
        sarif = json.load(f)
    
    findings = []
    seen = set()
    
    for run in sarif.get("runs", []):
        tool = run.get("tool", {}).get("driver", {})
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
                region = physical.get("region", {})
                line = region.get("startLine", 0)
                
                test_name = extract_test_name(file_path)
                if not test_name:
                    continue
                
                if subset_tests and test_name not in subset_tests:
                    continue
                
                if test_name in seen:
                    continue
                seen.add(test_name)
                
                findings.append(SastFinding(
                    test_name=test_name,
                    rule_id=rule_id,
                    message=result.get("message", {}).get("text", ""),
                    severity=rule.get("defaultConfiguration", {}).get("level", "warning"),
                    line=line,
                    cwe=cwe,
                ))
    
    return findings


def load_subset_tests(subset_file: Path) -> set:
    """Load subset test names."""
    import csv
    tests = set()
    with open(subset_file, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            tests.add(row["test_name"])
    return tests


def load_test_file(test_name: str, testcode_dir: Path) -> Optional[str]:
    """Load the Java source code for a test."""
    filepath = testcode_dir / f"{test_name}.java"
    if not filepath.exists():
        print(f"Warning: File not found: {filepath}")
        return None
    with open(filepath, "r") as f:
        return f.read()


def create_batch_prompt(findings_with_code: List[Dict]) -> str:
    """Create the user prompt for a batch of findings to verify."""
    entries = []
    for item in findings_with_code:
        finding = item["finding"]
        code = item["code"]
        entries.append(f"""### {finding.test_name}.java

**SAST Finding:**
- Rule: {finding.rule_id}
- Message: {finding.message}
- Line: {finding.line}
- CWE: {finding.cwe or "N/A"}

**Code:**
```java
{code}
```""")
    
    return f"""Verify the following {len(findings_with_code)} SAST findings. For each one, determine if it's a TRUE POSITIVE (real vulnerability) or FALSE POSITIVE (should be filtered out).

{chr(10).join(entries)}

Analyze each finding and return your verification for all {len(findings_with_code)} cases."""


def verify_batch(
    client: instructor.Instructor,
    findings_with_code: List[Dict],
    model: str,
    temperature: float,
    max_retries: int,
    batch_id: int = 0,
) -> tuple[int, List[VerificationResult]]:
    """Verify a batch of SAST findings using LLM. Returns (batch_id, results)."""
    
    system_prompt = get_verification_system_prompt()
    user_prompt = create_batch_prompt(findings_with_code)
    
    try:
        result = client.chat.completions.create(
            model=model,
            response_model=BatchVerification,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=temperature,
            max_retries=max_retries,
        )
        return batch_id, result.verifications
    except Exception as e:
        print(f"Error verifying batch {batch_id}: {e}")
        return batch_id, [
            VerificationResult(
                test_name=item["finding"].test_name,
                original_rule_id=item["finding"].rule_id,
                is_true_positive=True,
                confidence=0.0,
                reasoning=f"Error during verification: {str(e)}"
            )
            for item in findings_with_code
        ]


def run_filter(
    sarif_path: Path,
    output_path: Path,
    model: str,
    batch_size: int,
    temperature: float,
    max_retries: int,
    max_workers: int,
    testcode_dir: Path,
    subset_file: Optional[Path],
) -> Dict:
    """Run the SAST + LLM filtering pipeline."""
    
    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        raise ValueError("OPENROUTER_API_KEY environment variable not set")
    
    client = instructor.from_openai(
        openai.OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=api_key,
        ),
        mode=instructor.Mode.JSON,
    )
    
    subset_tests = None
    if subset_file and subset_file.exists():
        subset_tests = load_subset_tests(subset_file)
        print(f"Loaded {len(subset_tests)} tests from subset")
    
    print(f"Loading SAST findings from {sarif_path}")
    findings = load_sast_findings(sarif_path, subset_tests)
    print(f"Found {len(findings)} unique findings to verify")
    
    if not findings:
        print("No findings to verify")
        return {"results": [], "original_findings": 0, "filtered_findings": 0}
    
    print(f"Model: {model}")
    print(f"Batch size: {batch_size}")
    print(f"Max workers: {max_workers}")
    
    findings_with_code = []
    for finding in findings:
        code = load_test_file(finding.test_name, testcode_dir)
        if code:
            findings_with_code.append({"finding": finding, "code": code})
    
    print(f"Loaded code for {len(findings_with_code)} findings")
    
    batches = []
    for i in range(0, len(findings_with_code), batch_size):
        batches.append((i // batch_size, findings_with_code[i:i + batch_size]))
    
    total_batches = len(batches)
    print(f"Processing {total_batches} batches concurrently...")
    
    batch_results = {}
    completed = 0
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                verify_batch, client, batch, model, temperature, max_retries, batch_id
            ): batch_id
            for batch_id, batch in batches
        }
        
        for future in as_completed(futures):
            batch_id, results = future.result()
            batch_results[batch_id] = results
            completed += 1
            
            tp_count = len([r for r in results if r.is_true_positive])
            fp_count = len([r for r in results if not r.is_true_positive])
            elapsed = time.time() - start_time
            
            print(f"  Batch {batch_id + 1}/{total_batches} done: "
                  f"{tp_count} true positives, {fp_count} filtered "
                  f"[{completed}/{total_batches}, {elapsed:.1f}s elapsed]")
    
    all_results = []
    for batch_id in sorted(batch_results.keys()):
        all_results.extend(batch_results[batch_id])
    
    total_time = time.time() - start_time
    
    true_positives = [r for r in all_results if r.is_true_positive]
    filtered_out = [r for r in all_results if not r.is_true_positive]
    
    output = {
        "model": model,
        "batch_size": batch_size,
        "max_workers": max_workers,
        "temperature": temperature,
        "original_findings": len(findings),
        "filtered_findings": len(true_positives),
        "filtered_out": len(filtered_out),
        "processing_time_seconds": round(total_time, 2),
        "generated_at": datetime.now().isoformat(),
        "results": [
            {
                "test_name": r.test_name,
                "original_rule_id": r.original_rule_id,
                "is_true_positive": r.is_true_positive,
                "confidence": r.confidence,
                "reasoning": r.reasoning,
            }
            for r in all_results
        ],
    }
    
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    
    print(f"\nResults saved to {output_path}")
    print(f"\nSummary:")
    print(f"  Original SAST findings: {len(findings)}")
    print(f"  True positives (kept): {len(true_positives)}")
    print(f"  False positives (filtered): {len(filtered_out)}")
    print(f"  Processing time: {total_time:.1f}s")
    
    return output


def main():
    parser = argparse.ArgumentParser(
        description="Filter SAST findings using LLM verification (Stage 3)"
    )
    parser.add_argument(
        "sarif_file",
        type=Path,
        help="Path to SARIF file with SAST findings"
    )
    parser.add_argument(
        "--model",
        type=str,
        default=DEFAULT_MODEL,
        help=f"OpenRouter model to use (default: {DEFAULT_MODEL})"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help=f"Number of findings per API request (default: {DEFAULT_BATCH_SIZE})"
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=DEFAULT_TEMPERATURE,
        help=f"Model temperature (default: {DEFAULT_TEMPERATURE})"
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=DEFAULT_MAX_RETRIES,
        help=f"Max retries per request (default: {DEFAULT_MAX_RETRIES})"
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=DEFAULT_MAX_WORKERS,
        help=f"Max concurrent API requests (default: {DEFAULT_MAX_WORKERS})"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("filtered_results.json"),
        help="Output file path (default: filtered_results.json)"
    )
    parser.add_argument(
        "--testcode-dir",
        type=Path,
        default=TESTCODE_DIR,
        help="Path to testcode directory"
    )
    parser.add_argument(
        "--subset-file",
        type=Path,
        default=SUBSET_FILE,
        help="Path to subset CSV file (optional, filters to subset only)"
    )
    
    args = parser.parse_args()
    
    run_filter(
        sarif_path=args.sarif_file,
        output_path=args.output,
        model=args.model,
        batch_size=args.batch_size,
        temperature=args.temperature,
        max_retries=args.max_retries,
        max_workers=args.max_workers,
        testcode_dir=args.testcode_dir,
        subset_file=args.subset_file,
    )


if __name__ == "__main__":
    main()
