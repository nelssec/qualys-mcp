#!/usr/bin/env python3
"""
Qualys MCP Nightly Regression Test Runner
Phases 1-5 with regression detection and data accuracy checks.
"""
import json
import os
import random
import subprocess
import sys
import time
import traceback
from datetime import datetime, date
from pathlib import Path

# ── env ──────────────────────────────────────────────────────────────────────
# Credentials MUST come from environment or .env file — never hardcode here.
for _var in ("QUALYS_USERNAME", "QUALYS_PASSWORD"):
    if _var not in os.environ:
        sys.exit(f"ERROR: {_var} not set. Export it or add to .env")

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from qualys.workflows.overview import security_overview
from qualys.workflows.assess_risk import assess_risk
from qualys.workflows.investigate import investigate
from qualys.workflows.compliance import check_compliance
from qualys.workflows.remediation import plan_remediation
from qualys.api import get_api_error_counts, reset_api_error_counts

# ── helpers ───────────────────────────────────────────────────────────────────

def load_questions():
    p = ROOT / "eval" / "v3_routing_questions.json"
    return json.loads(p.read_text())

def latest_previous(results_dir: Path):
    files = sorted(results_dir.glob("nightly_*.json"))
    # exclude today
    today_str = date.today().isoformat()
    candidates = [f for f in files if today_str not in f.name]
    return json.loads(candidates[-1].read_text()) if candidates else None

def has_real_data(text: str) -> bool:
    """Heuristic: response has meaningful Qualys data."""
    if not text or len(text) < 100:
        return False
    bad = ["error", "exception", "traceback", "No data", "timed out"]
    for b in bad:
        if b.lower() in text.lower():
            return False
    return True

def run_claude_headless(question: str, timeout: int = 120) -> dict:
    """Run one question through claude CLI with qualys MCP tools."""
    tools = ",".join([
        "mcp__qualys__assess_risk",
        "mcp__qualys__security_overview",
        "mcp__qualys__plan_remediation",
        "mcp__qualys__investigate",
        "mcp__qualys__check_compliance",
    ])
    cmd = [
        "claude", "-p", "--allowedTools", tools,
        "--max-turns", "4",
        question,
    ]
    t0 = time.time()
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            env={**os.environ}
        )
        elapsed = time.time() - t0
        output = result.stdout + result.stderr
        passed = has_real_data(output)
        return {"passed": passed, "elapsed": elapsed, "output": output[:2000]}
    except subprocess.TimeoutExpired:
        return {"passed": False, "elapsed": timeout, "output": "TIMEOUT"}
    except Exception as e:
        return {"passed": False, "elapsed": time.time()-t0, "output": str(e)}

def call_workflow(name: str, kwargs: dict, timeout: int = 180) -> dict:
    """Call a workflow function directly and measure result."""
    fn_map = {
        "security_overview": security_overview,
        "assess_risk": assess_risk,
        "investigate": investigate,
        "check_compliance": check_compliance,
        "plan_remediation": plan_remediation,
    }
    fn = fn_map.get(name)
    if not fn:
        return {"passed": False, "elapsed": 0, "error": f"Unknown workflow: {name}"}

    t0 = time.time()
    try:
        result = fn(**kwargs)
        elapsed = time.time() - t0

        # Validate result structure
        if result is None:
            return {"passed": False, "elapsed": elapsed, "error": "None result"}

        text = str(result)
        if len(text) < 50:
            return {"passed": False, "elapsed": elapsed, "error": "Result too short"}

        # Check for headline / risk_level
        has_headline = any(k in result if isinstance(result, dict) else False
                          for k in ["headline", "summary", "title", "status"])
        if isinstance(result, dict):
            has_headline = bool(result.get("headline") or result.get("summary") or
                               result.get("title") or result.get("overview") or
                               result.get("risk_level") or result.get("status"))
        else:
            has_headline = len(text) > 100

        return {
            "passed": has_headline or len(text) > 200,
            "elapsed": elapsed,
            "risk_level": result.get("risk_level") if isinstance(result, dict) else None,
            "output_len": len(text),
        }
    except Exception as e:
        elapsed = time.time() - t0
        return {"passed": False, "elapsed": elapsed, "error": str(e), "tb": traceback.format_exc()[-500:]}

# ── Phase 1: MCP Headless ─────────────────────────────────────────────────────

def phase1(questions, n=20):
    print(f"\n{'='*60}")
    print("PHASE 1 — MCP Headless (20 questions via claude CLI)")
    print('='*60)

    random.seed(42)
    sample = random.sample(questions, n)
    results = []

    for i, q in enumerate(sample, 1):
        print(f"  [{i:02d}/{n}] Q{q['id']}: {q['question'][:60]}...")
        r = run_claude_headless(q["question"])
        r["id"] = q["id"]
        r["question"] = q["question"]
        r["expected"] = q["expected_workflow"]
        results.append(r)
        status = "PASS" if r["passed"] else "FAIL"
        print(f"         → {status} ({r['elapsed']:.1f}s)")

    passed = sum(1 for r in results if r["passed"])
    print(f"\n  Phase 1 result: {passed}/{n} passed ({100*passed/n:.0f}%)")
    return results

# ── Phase 2: Direct Function ──────────────────────────────────────────────────

def phase2(questions, n=30):
    print(f"\n{'='*60}")
    print("PHASE 2 — Direct Function (30 questions)")
    print('='*60)

    # pick 30 questions that have useful params_hint
    rng = random.Random(123)
    candidates = [q for q in questions if q.get("params_hint")]
    sample = rng.sample(candidates, min(n, len(candidates)))
    results = []

    for i, q in enumerate(sample, 1):
        workflow = q["expected_workflow"]
        params = q.get("params_hint", {})

        # Map params_hint to actual kwargs
        kwargs = {}
        if workflow == "investigate":
            kwargs["target"] = params.get("target", q["question"][:50])
            kwargs["depth"] = params.get("depth", "quick")
        elif workflow == "assess_risk":
            kwargs["scope"] = params.get("scope", "all")
            if "tag" in params:
                kwargs["tag"] = params["tag"]
            if "limit" in params:
                kwargs["limit"] = params["limit"]
        elif workflow == "check_compliance":
            if "framework" in params:
                kwargs["framework"] = params["framework"]
            if "include_exceptions" in params:
                kwargs["include_exceptions"] = params["include_exceptions"]
        elif workflow == "plan_remediation":
            kwargs["scope"] = params.get("scope", "all")
            if "severity" in params:
                kwargs["severity"] = params["severity"]
        elif workflow == "security_overview":
            if "quick" in params:
                kwargs["quick"] = params["quick"]
            if "period" in params:
                kwargs["period"] = params["period"]

        print(f"  [{i:02d}/{n}] Q{q['id']} {workflow}({kwargs})")
        r = call_workflow(workflow, kwargs)
        r["id"] = q["id"]
        r["question"] = q["question"]
        r["workflow"] = workflow
        r["kwargs"] = kwargs
        results.append(r)
        status = "PASS" if r["passed"] else "FAIL"
        err = r.get("error", "")[:60] if not r["passed"] else ""
        print(f"         → {status} ({r.get('elapsed', 0):.1f}s) {err}")

    passed = sum(1 for r in results if r["passed"])
    print(f"\n  Phase 2 result: {passed}/{n} passed ({100*passed/n:.0f}%)")
    return results

# ── Phase 3: Customer Simulation ─────────────────────────────────────────────

PHASE3_CASES = [
    ("security_overview", {"quick": True}),
    ("security_overview", {"period": "week"}),
    ("assess_risk",       {"scope": "all", "limit": 5}),
    ("assess_risk",       {"scope": "cloud", "limit": 10}),
    ("assess_risk",       {"scope": "containers", "limit": 10}),
    ("assess_risk",       {"scope": "web", "limit": 10}),
    ("assess_risk",       {"scope": "assets", "tag": "Cloud Agent"}),
    ("assess_risk",       {"scope": "certs"}),
    ("investigate",       {"target": "CVE-2024-3400", "depth": "quick"}),
    ("investigate",       {"target": "ransomware", "depth": "quick"}),
    ("investigate",       {"target": "AI security", "depth": "quick"}),
    ("check_compliance",  {}),
    ("check_compliance",  {"framework": "PCI"}),
    ("check_compliance",  {"include_exceptions": True}),
    ("plan_remediation",  {"scope": "patches", "severity": "critical"}),
    ("plan_remediation",  {"scope": "all"}),
    ("plan_remediation",  {"scope": "program"}),
]

def phase3():
    print(f"\n{'='*60}")
    print("PHASE 3 — Customer Simulation (17 fixed questions)")
    print('='*60)

    reset_api_error_counts()
    results = []
    for i, (workflow, kwargs) in enumerate(PHASE3_CASES, 1):
        label = f"{workflow}({', '.join(f'{k}={repr(v)}' for k,v in kwargs.items())})"
        print(f"  [{i:02d}/17] {label}")
        r = call_workflow(workflow, kwargs)
        r["workflow"] = workflow
        r["kwargs"] = kwargs
        r["label"] = label
        results.append(r)
        status = "PASS" if r["passed"] else "FAIL"
        err = r.get("error", "")[:80] if not r["passed"] else ""
        print(f"         → {status} ({r.get('elapsed', 0):.1f}s) {err}")

    passed = sum(1 for r in results if r["passed"])
    # Capture API error counts so regression check can apply latency tolerance
    error_counts = get_api_error_counts()
    print(f"\n  Phase 3 result: {passed}/17 passed ({100*passed/17:.0f}%)")
    if any(error_counts.get(k, 0) > 0 for k in ("503", "502", "429")):
        print(f"  API errors detected during run: {error_counts} — latency threshold widened")
    return results, error_counts

# ── Phase 4: Regression Check ─────────────────────────────────────────────────

def phase4(today_results: dict, previous: dict | None, api_error_counts: dict | None = None):
    print(f"\n{'='*60}")
    print("PHASE 4 — Regression Check")
    print('='*60)

    regressions = []

    if previous is None:
        print("  No previous results found — baseline run, skipping regression check.")
        return regressions

    prev_pass = previous.get("pass_rate", 0)
    curr_pass = today_results["pass_rate"]

    print(f"  Previous pass rate: {prev_pass:.1f}%")
    print(f"  Current  pass rate: {curr_pass:.1f}%")

    if curr_pass < prev_pass:
        msg = f"Pass rate dropped from {prev_pass:.1f}% to {curr_pass:.1f}%"
        regressions.append({"type": "pass_rate", "detail": msg})
        print(f"  *** REGRESSION: {msg}")

    # Widen latency threshold when the Qualys API was degraded during the run
    # (503/502/429 errors cause retry backoff that inflates wall-clock time).
    err = api_error_counts or {}
    api_degraded = any(err.get(k, 0) > 0 for k in ("503", "502", "429"))
    latency_multiplier = 3.0 if api_degraded else 1.5
    if api_degraded:
        print(f"  API errors detected {err} — latency threshold widened to {latency_multiplier}×")

    # Check Phase 3 individually (fixed questions, comparable run-to-run)
    prev_p3 = {r["label"]: r for r in previous.get("phase3", [])}
    curr_p3 = {r["label"]: r for r in today_results.get("phase3", [])}

    for label, curr_r in curr_p3.items():
        prev_r = prev_p3.get(label)
        if prev_r and prev_r["passed"] and not curr_r["passed"]:
            msg = f"Phase3 question previously PASSED now FAILS: {label}"
            regressions.append({"type": "question_regression", "label": label, "detail": msg})
            print(f"  *** REGRESSION: {msg}")

        if prev_r and prev_r.get("elapsed", 0) > 0:
            prev_t = prev_r["elapsed"]
            curr_t = curr_r.get("elapsed", 0)
            if curr_t > prev_t * latency_multiplier:
                msg = (
                    f"Response time regression on '{label}': "
                    f"{prev_t:.1f}s → {curr_t:.1f}s"
                    + (f" (threshold {latency_multiplier}× due to API errors)" if api_degraded else "")
                )
                regressions.append({"type": "latency", "label": label, "detail": msg})
                print(f"  *** REGRESSION: {msg}")

    if not regressions:
        print("  No regressions detected.")

    return regressions

# ── Phase 5: Data Accuracy ────────────────────────────────────────────────────

def phase5():
    print(f"\n{'='*60}")
    print("PHASE 5 — Data Accuracy Spot Check")
    print('='*60)

    checks = {}

    # Run security_overview to get aggregate stats
    print("  Running security_overview(quick=True) for spot check data...")
    t0 = time.time()
    try:
        ov = security_overview(quick=True)
        elapsed = time.time() - t0
        print(f"  security_overview completed in {elapsed:.1f}s")
    except Exception as e:
        print(f"  security_overview FAILED: {e}")
        ov = {}

    # Run assess_risk for asset/cloud data
    print("  Running assess_risk(scope='all', limit=5) for asset data...")
    t0 = time.time()
    try:
        ar = assess_risk(scope="all", limit=5)
        elapsed = time.time() - t0
        print(f"  assess_risk completed in {elapsed:.1f}s")
    except Exception as e:
        print(f"  assess_risk FAILED: {e}")
        ar = {}

    def extract_metric(data, *keys):
        """Try to extract a numeric metric from nested dict."""
        if not isinstance(data, dict):
            return None
        for k in keys:
            if k in data:
                v = data[k]
                if isinstance(v, (int, float)):
                    return v
                if isinstance(v, dict):
                    # try first numeric value
                    for vv in v.values():
                        if isinstance(vv, (int, float)):
                            return vv
        return None

    def search_recursive(data, key_fragment, depth=0):
        """Recursively search for a key containing key_fragment."""
        if depth > 5 or not isinstance(data, dict):
            return None
        for k, v in data.items():
            if key_fragment.lower() in k.lower():
                if isinstance(v, (int, float)):
                    return v
            if isinstance(v, dict):
                r = search_recursive(v, key_fragment, depth+1)
                if r is not None:
                    return r
            if isinstance(v, list) and v and isinstance(v[0], dict):
                r = search_recursive(v[0], key_fragment, depth+1)
                if r is not None:
                    return r
        return None

    combined = {}
    if isinstance(ov, dict):
        combined.update(ov)
    if isinstance(ar, dict):
        combined.update(ar)

    # Print raw keys to help debug
    all_keys = list(combined.keys())[:30]
    print(f"  Available top-level keys: {all_keys}")

    # Thresholds
    THRESHOLDS = {
        "Total assets": ("asset", 50000, None),
        "Container images": ("container", 100, None),
        "Cloud accounts": ("cloud_account", 29, None),
        "Compliance pass rate": ("compliance_pass", 20, 100),
        "Patch coverage": ("patch_coverage", 50, 100),
        "TotalAI detections": ("ai_detection", 100, None),
        "WAS findings": ("was_finding", 1000, None),
    }

    for metric_name, (search_key, min_val, max_val) in THRESHOLDS.items():
        val = search_recursive(combined, search_key)
        if val is None:
            # Try broader search in string representation
            text = json.dumps(combined)
            # Simple heuristic
            val = None

        ok = None
        if val is not None:
            ok = val >= min_val
            if max_val is not None:
                ok = ok and val <= max_val

        checks[metric_name] = {
            "value": val,
            "min": min_val,
            "max": max_val,
            "pass": ok,
        }
        status = "PASS" if ok else ("FAIL" if ok is False else "UNKNOWN")
        print(f"  {metric_name}: {val} → {status} (expected >={min_val}{'<= '+str(max_val) if max_val else ''})")

    return checks, combined

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("\n" + "="*60)
    print("QUALYS MCP NIGHTLY REGRESSION TEST")
    print(f"Date: {date.today().isoformat()}")
    print("="*60)

    results_dir = ROOT / "eval_results"
    results_dir.mkdir(exist_ok=True)

    questions = load_questions()
    print(f"Loaded {len(questions)} questions from v3_routing_questions.json")

    previous = latest_previous(results_dir)
    if previous:
        print(f"Previous results: pass_rate={previous.get('pass_rate', '?')}%  ({previous.get('date', 'unknown')})")
    else:
        print("No previous results found (baseline run)")

    # ── Phase 1 ──────────────────────────────────────────────────────────────
    p1_results = phase1(questions, n=20)
    p1_passed = sum(1 for r in p1_results if r["passed"])

    # ── Phase 2 ──────────────────────────────────────────────────────────────
    p2_results = phase2(questions, n=30)
    p2_passed = sum(1 for r in p2_results if r["passed"])

    # ── Phase 3 ──────────────────────────────────────────────────────────────
    p3_results, p3_error_counts = phase3()
    p3_passed = sum(1 for r in p3_results if r["passed"])

    # ── Totals ────────────────────────────────────────────────────────────────
    total = 20 + 30 + 17
    passed = p1_passed + p2_passed + p3_passed
    pass_rate = 100 * passed / total

    print(f"\n{'='*60}")
    print(f"OVERALL: {passed}/{total} passed — {pass_rate:.1f}%")
    print('='*60)

    today_results = {
        "date": date.today().isoformat(),
        "pass_rate": pass_rate,
        "total": total,
        "passed": passed,
        "failed": total - passed,
        "phase1": {"total": 20, "passed": p1_passed, "results": p1_results},
        "phase2": {"total": 30, "passed": p2_passed, "results": p2_results},
        "phase3": {"total": 17, "passed": p3_passed, "results": p3_results},
        "previous_pass_rate": previous.get("pass_rate") if previous else None,
    }

    # ── Phase 4 ──────────────────────────────────────────────────────────────
    regressions = phase4(today_results, previous, api_error_counts=p3_error_counts)
    today_results["regressions"] = regressions

    # ── Phase 5 ──────────────────────────────────────────────────────────────
    data_accuracy, raw_data = phase5()
    today_results["data_accuracy"] = data_accuracy

    # ── Save results ──────────────────────────────────────────────────────────
    out_path = results_dir / f"nightly_{date.today().isoformat()}.json"
    out_path.write_text(json.dumps(today_results, indent=2, default=str))
    print(f"\nResults saved to {out_path}")

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print("SUMMARY")
    print('='*60)
    print(f"  Phase 1 (MCP Headless):     {p1_passed}/20 ({100*p1_passed/20:.0f}%)")
    print(f"  Phase 2 (Direct Function):  {p2_passed}/30 ({100*p2_passed/30:.0f}%)")
    print(f"  Phase 3 (Customer Sim):     {p3_passed}/17 ({100*p3_passed/17:.0f}%)")
    print(f"  TOTAL:                      {passed}/{total} ({pass_rate:.1f}%)")
    if regressions:
        print(f"\n  *** {len(regressions)} REGRESSION(S) DETECTED ***")
        for r in regressions:
            print(f"      - {r['detail']}")
    else:
        print(f"\n  No regressions detected.")

    return today_results, regressions

if __name__ == "__main__":
    results, regressions = main()
    sys.exit(1 if regressions else 0)
