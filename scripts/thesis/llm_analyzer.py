#!/usr/bin/env python3
"""
LLM-based security vulnerability analyzer for OWASP Benchmark.

This script analyzes Java code files using GPT models via OpenRouter API
to detect security vulnerabilities. Uses instructor library for structured
output with Pydantic models.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional

import instructor
import openai

from llm_models import (
    BatchAnalysis,
    FileAnalysis,
    VulnerabilityCategory,
    CWE_DESCRIPTIONS,
)


DEFAULT_MODEL = "openai/gpt-4o-mini"
DEFAULT_BATCH_SIZE = 10
DEFAULT_TEMPERATURE = 0.1
DEFAULT_MAX_RETRIES = 3
DEFAULT_MAX_WORKERS = 5
RATE_LIMIT_DELAY = 0.5

SUBSET_FILE = Path(__file__).parent / "subset_tests.csv"
TESTCODE_DIR = Path(__file__).parent.parent.parent / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode"


def get_system_prompt() -> str:
    """Generate the system prompt for security analysis."""
    
    cwe_definitions = "\n".join([
        f"- {cat.value}: {desc}"
        for cat, desc in CWE_DESCRIPTIONS.items()
    ])
    
    return f"""You are an expert in web application security specializing in Java code analysis.

## Your Task
Analyze each Java code file and determine:
1. Whether it contains a REAL exploitable security vulnerability (not a false positive)
2. The vulnerability category according to CWE

## Category Definitions (CWE):
{cwe_definitions}

## IMPORTANT - Recognizing FALSE POSITIVES:
- If user data is validated/escaped before use -> NOT a vulnerability
- If a conditional expression ALWAYS leads to a constant value -> NOT a vulnerability
- If a variable comes from a constant string, not from user input -> NOT a vulnerability
- Analyze data flow (taint analysis) from source to sink
- Check if the tainted data actually reaches the dangerous sink
- Look for dead code paths where user input is never actually used

## Analysis Guidelines:
1. Identify the SOURCE: Where does user input enter? (request parameters, headers, cookies, etc.)
2. Identify the SINK: Where is the dangerous operation? (SQL query, command execution, file access, etc.)
3. Trace the FLOW: Does the tainted data actually flow from source to sink?
4. Check for SANITIZATION: Is there any validation, encoding, or escaping?
5. Evaluate EXPLOITABILITY: Can an attacker actually exploit this?

## Response Format
For each file, provide:
- test_name: The test name (e.g., BenchmarkTest00018)
- is_vulnerable: true if real vulnerability exists, false otherwise
- category: The vulnerability category (or "none" if not vulnerable)
- confidence: Your confidence level (0.0-1.0)
- reasoning: Brief explanation (1-2 sentences) of why it is/isn't vulnerable"""


def load_subset_tests(filepath: Path) -> List[str]:
    """Load the list of test names from subset CSV."""
    test_names = []
    with open(filepath, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            test_names.append(row["test_name"])
    return test_names


def load_test_file(test_name: str, testcode_dir: Path) -> Optional[str]:
    """Load the Java source code for a test."""
    filepath = testcode_dir / f"{test_name}.java"
    if not filepath.exists():
        print(f"Warning: File not found: {filepath}")
        return None
    with open(filepath, "r") as f:
        return f.read()


def create_batch_prompt(files: List[Dict[str, str]]) -> str:
    """Create the user prompt for a batch of files."""
    file_contents = []
    for f in files:
        file_contents.append(f"### {f['test_name']}.java\n```java\n{f['code']}\n```")
    
    return f"""Analyze the following {len(files)} Java files for security vulnerabilities:

{chr(10).join(file_contents)}

For each file, determine if it contains a real exploitable vulnerability or if it's a false positive.
Return your analysis for all {len(files)} files."""


def analyze_batch(
    client: instructor.Instructor,
    files: List[Dict[str, str]],
    model: str,
    temperature: float,
    max_retries: int,
    batch_id: int = 0,
) -> tuple[int, List[FileAnalysis]]:
    """Analyze a batch of files using the LLM. Returns (batch_id, results)."""
    
    system_prompt = get_system_prompt()
    user_prompt = create_batch_prompt(files)
    
    try:
        result = client.chat.completions.create(
            model=model,
            response_model=BatchAnalysis,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=temperature,
            max_retries=max_retries,
        )
        return batch_id, result.analyses
    except Exception as e:
        print(f"Error analyzing batch {batch_id}: {e}")
        return batch_id, [
            FileAnalysis(
                test_name=f["test_name"],
                is_vulnerable=False,
                category=VulnerabilityCategory.NONE,
                confidence=0.0,
                reasoning=f"Error during analysis: {str(e)}"
            )
            for f in files
        ]


def run_analysis(
    model: str,
    batch_size: int,
    temperature: float,
    max_retries: int,
    max_workers: int,
    limit: Optional[int],
    output_file: Path,
    subset_file: Path,
    testcode_dir: Path,
) -> Dict:
    """Run the full LLM analysis pipeline with concurrent batch processing."""
    
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
    
    print(f"Loading subset tests from {subset_file}")
    test_names = load_subset_tests(subset_file)
    
    if limit:
        test_names = test_names[:limit]
        print(f"Limited to {limit} tests")
    
    print(f"Total tests to analyze: {len(test_names)}")
    print(f"Model: {model}")
    print(f"Batch size: {batch_size}")
    print(f"Max workers: {max_workers}")
    
    files_to_analyze = []
    for test_name in test_names:
        code = load_test_file(test_name, testcode_dir)
        if code:
            files_to_analyze.append({"test_name": test_name, "code": code})
    
    print(f"Loaded {len(files_to_analyze)} files")
    
    batches = []
    for i in range(0, len(files_to_analyze), batch_size):
        batches.append((i // batch_size, files_to_analyze[i:i + batch_size]))
    
    total_batches = len(batches)
    print(f"Processing {total_batches} batches concurrently...")
    
    batch_results = {}
    completed = 0
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                analyze_batch, client, batch, model, temperature, max_retries, batch_id
            ): batch_id
            for batch_id, batch in batches
        }
        
        for future in as_completed(futures):
            batch_id, results = future.result()
            batch_results[batch_id] = results
            completed += 1
            
            vuln_count = len([r for r in results if r.is_vulnerable])
            safe_count = len([r for r in results if not r.is_vulnerable])
            elapsed = time.time() - start_time
            
            print(f"  Batch {batch_id + 1}/{total_batches} done: "
                  f"{vuln_count} vulnerable, {safe_count} safe "
                  f"[{completed}/{total_batches}, {elapsed:.1f}s elapsed]")
    
    all_results = []
    for batch_id in sorted(batch_results.keys()):
        all_results.extend(batch_results[batch_id])
    
    total_time = time.time() - start_time
    
    output = {
        "model": model,
        "batch_size": batch_size,
        "max_workers": max_workers,
        "temperature": temperature,
        "total_files": len(files_to_analyze),
        "processing_time_seconds": round(total_time, 2),
        "generated_at": datetime.now().isoformat(),
        "results": [
            {
                "test_name": r.test_name,
                "is_vulnerable": r.is_vulnerable,
                "category": r.category.value if r.category else None,
                "confidence": r.confidence,
                "reasoning": r.reasoning,
            }
            for r in all_results
        ],
    }
    
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(output, f, indent=2)
    
    print(f"\nResults saved to {output_file}")
    
    vulnerable_count = len([r for r in all_results if r.is_vulnerable])
    safe_count = len([r for r in all_results if not r.is_vulnerable])
    print(f"\nSummary:")
    print(f"  Total analyzed: {len(all_results)}")
    print(f"  Vulnerable: {vulnerable_count}")
    print(f"  Safe: {safe_count}")
    print(f"  Processing time: {total_time:.1f}s")
    
    return output


def main():
    parser = argparse.ArgumentParser(
        description="Analyze Java code for security vulnerabilities using LLM"
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
        help=f"Number of files per API request (default: {DEFAULT_BATCH_SIZE})"
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
        "--limit",
        type=int,
        default=None,
        help="Limit number of tests to analyze (for testing)"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("llm_results.json"),
        help="Output file path (default: llm_results.json)"
    )
    parser.add_argument(
        "--subset-file",
        type=Path,
        default=SUBSET_FILE,
        help="Path to subset CSV file"
    )
    parser.add_argument(
        "--testcode-dir",
        type=Path,
        default=TESTCODE_DIR,
        help="Path to testcode directory"
    )
    
    args = parser.parse_args()
    
    run_analysis(
        model=args.model,
        batch_size=args.batch_size,
        temperature=args.temperature,
        max_retries=args.max_retries,
        max_workers=args.max_workers,
        limit=args.limit,
        output_file=args.output,
        subset_file=args.subset_file,
        testcode_dir=args.testcode_dir,
    )


if __name__ == "__main__":
    main()
