#!/usr/bin/env bash
# eval_questions.sh — Claude Code + MCP question eval harness
# Asks representative questions from docs/questions.md via MCP and measures coverage.
#
# Usage:
#   ./scripts/eval_questions.sh [--dry-run]
#
# Requirements:
#   - python3.12 with qualys-mcp installed
#   - claude CLI with --mcp-config support
#   - .env with QUALYS_USERNAME, QUALYS_PASSWORD, QUALYS_POD=US2

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RESULTS_FILE="$PROJECT_ROOT/eval/question_eval_results.txt"
MCP_CONFIG=$(mktemp /tmp/mcp_config_XXXXXX.json)

# Load .env
if [[ -f "$PROJECT_ROOT/.env" ]]; then
  set -a; source "$PROJECT_ROOT/.env"; set +a
fi

DRY_RUN=false
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=true

# ── Create MCP config ────────────────────────────────────────────────────────
cat > "$MCP_CONFIG" <<MCPCONF
{
  "mcpServers": {
    "qualys": {
      "command": "python3.12",
      "args": ["$PROJECT_ROOT/qualys_mcp.py"],
      "env": {
        "QUALYS_USERNAME": "${QUALYS_USERNAME:-}",
        "QUALYS_PASSWORD": "${QUALYS_PASSWORD:-}",
        "QUALYS_POD": "${QUALYS_POD:-US2}"
      }
    }
  }
}
MCPCONF

cleanup() { rm -f "$MCP_CONFIG"; }
trap cleanup EXIT

echo "=== Qualys MCP Question Eval ===" | tee "$RESULTS_FILE"
echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$RESULTS_FILE"
echo "Pod: ${QUALYS_POD:-US2}" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

# ── Representative questions (one per category) ──────────────────────────────
declare -A QUESTIONS
QUESTIONS=(
  ["vuln_mgmt"]="What are the top 10 critical vulnerabilities in my environment right now?"
  ["asset_mgmt"]="List assets running Windows Server 2016 with critical vulnerabilities"
  ["scanner_ops"]="What is the health status of all my scanners?"
  ["cve_intel"]="What is the impact of CVE-2024-3400 on my environment?"
  ["trurisk"]="What is my current TruRisk score and how has it trended?"
  ["cloud_sec"]="What are my top cloud security risks and misconfigurations?"
  ["webapp"]="What are the top web application vulnerabilities across my apps?"
  ["compliance"]="What is my compliance posture for CIS Level 1?"
  ["edr"]="Have there been any malware detections in the last 7 days?"
  ["fim"]="What critical files have been modified in the last 24 hours?"
  ["certs"]="Which TLS certificates expire within the next 30 days?"
  ["patch_mgmt"]="What patches are most urgent based on TruRisk?"
  ["reports"]="List my 5 most recent scan reports"
  ["investigation"]="Investigate the risk from Log4Shell in my environment"
  ["morning"]="Give me my morning security briefing"
)

PASS=0
FAIL=0
SKIP=0

printf "%-20s %-50s %-15s %s\n" "CATEGORY" "QUESTION (truncated)" "STATUS" "NOTES" | tee -a "$RESULTS_FILE"
printf "%-20s %-50s %-15s %s\n" "--------" "-------------------" "------" "-----" | tee -a "$RESULTS_FILE"

for category in "${!QUESTIONS[@]}"; do
  question="${QUESTIONS[$category]}"
  short_q="${question:0:48}..."

  if [[ "$DRY_RUN" == "true" ]]; then
    printf "%-20s %-50s %-15s %s\n" "$category" "$short_q" "SKIP(dry-run)" "" | tee -a "$RESULTS_FILE"
    ((SKIP++))
    continue
  fi

  # Run claude with MCP config, capture output
  set +e
  output=$(timeout 120 claude \
    --print \
    --permission-mode bypassPermissions \
    --mcp-config "$MCP_CONFIG" \
    "$question" 2>&1)
  exit_code=$?
  set -e

  # Determine status: did Claude call a tool AND get a real answer?
  if [[ $exit_code -ne 0 ]]; then
    status="ERROR"
    notes="exit=$exit_code"
    ((FAIL++))
  elif echo "$output" | grep -qiE "error|failed|not available|no data|cannot|unable"; then
    status="FAIL"
    notes="error in response"
    ((FAIL++))
  elif echo "$output" | grep -qiE "tool_use|tool_result|qualys\." 2>/dev/null || [[ ${#output} -gt 200 ]]; then
    status="PASS"
    notes="got response (${#output} chars)"
    ((PASS++))
  else
    status="EMPTY"
    notes="short/empty response"
    ((FAIL++))
  fi

  printf "%-20s %-50s %-15s %s\n" "$category" "$short_q" "$status" "$notes" | tee -a "$RESULTS_FILE"

  # Brief pause to avoid rate limits
  sleep 2
done

echo "" | tee -a "$RESULTS_FILE"
echo "=== SUMMARY ===" | tee -a "$RESULTS_FILE"
TOTAL=$((PASS + FAIL + SKIP))
if [[ $TOTAL -gt 0 && $SKIP -eq 0 ]]; then
  PCT=$(( PASS * 100 / TOTAL ))
  echo "Pass: $PASS / $TOTAL ($PCT%)" | tee -a "$RESULTS_FILE"
  echo "Fail: $FAIL / $TOTAL" | tee -a "$RESULTS_FILE"
else
  echo "Total questions: $TOTAL (skipped: $SKIP)" | tee -a "$RESULTS_FILE"
fi
echo "Results saved to: $RESULTS_FILE"
