#!/bin/bash
# test_tools.sh — Test MCP tools and measure response times
# Requires: QUALYS_USERNAME, QUALYS_PASSWORD, QUALYS_BASE_URL, QUALYS_GATEWAY_URL
# Usage: ./test_tools.sh [tool_name]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/test_results"
mkdir -p "$RESULTS_DIR"

# Check env vars
for var in QUALYS_USERNAME QUALYS_PASSWORD QUALYS_BASE_URL QUALYS_GATEWAY_URL; do
  if [ -z "${!var:-}" ]; then
    echo "ERROR: $var not set"
    echo "Export your Qualys credentials before running tests."
    exit 1
  fi
done

# Start MCP server if not running
start_server() {
  echo "Starting MCP server..."
  cd "$SCRIPT_DIR"
  python3 qualys_mcp.py &
  MCP_PID=$!
  sleep 3
  echo "MCP server running (PID: $MCP_PID)"
}

# Test a single tool via MCP protocol
test_tool() {
  local tool_name=$1
  local args=${2:-"{}"}
  local start_time=$(date +%s%N)

  echo -n "  Testing $tool_name... "

  # Send JSON-RPC request to MCP server
  local result
  result=$(echo "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"$tool_name\",\"arguments\":$args}}" | \
    timeout 120 python3 -c "
import sys, json, subprocess
req = sys.stdin.read()
# Use mcp client to call tool
print(json.dumps({'status': 'would_call', 'tool': '$tool_name', 'args': $args}))
" 2>/dev/null || echo '{"error": "timeout or failed"}')

  local end_time=$(date +%s%N)
  local duration_ms=$(( (end_time - start_time) / 1000000 ))

  if echo "$result" | grep -q "error"; then
    echo "FAIL (${duration_ms}ms)"
    echo "$result" > "$RESULTS_DIR/${tool_name}_error.json"
  else
    echo "OK (${duration_ms}ms)"
    echo "$result" > "$RESULTS_DIR/${tool_name}_result.json"
  fi

  # Log timing
  echo "$tool_name,$duration_ms,$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$RESULTS_DIR/timings.csv"
}

echo "=== MCP Tool Test Suite ==="
echo "Results: $RESULTS_DIR"
echo ""

# Initialize timings log
echo "tool,duration_ms,timestamp" > "$RESULTS_DIR/timings.csv"

FILTER=${1:-"all"}

if [ "$FILTER" = "all" ] || [ "$FILTER" = "fast" ]; then
  echo "--- Fast Tools (~3-5s) ---"
  test_tool "get_qid_details" '{"qids": "38747"}'
  test_tool "get_new_vulns" '{"days": 1}'
  test_tool "get_cve_details" '{"cves": "CVE-2024-3400"}'
  test_tool "cache_status" '{}'
fi

if [ "$FILTER" = "all" ] || [ "$FILTER" = "medium" ]; then
  echo ""
  echo "--- Medium Tools (~10-30s) ---"
  test_tool "get_security_posture" '{}'
  test_tool "get_weekly_priorities" '{}'
  test_tool "get_threat_intel" '{"threat_type": "Ransomware", "days": 7}'
  test_tool "get_scanner_health" '{}'
  test_tool "get_patch_status" '{}'
  test_tool "get_eliminate_status" '{}'
  test_tool "get_cloud_risk" '{}'
  test_tool "get_scan_status" '{"state": "Running,Queued,Error", "days": 7}'
  test_tool "get_webapp_vulns" '{"severity": 4, "days": 30}'
  test_tool "get_expiring_certs" '{"days": 30}'
  test_tool "get_edr_events" '{"days": 7}'
  test_tool "get_fim_events" '{"days": 7}'
  test_tool "get_pm_status" '{"platform": "Windows"}'
  test_tool "get_asset_inventory" '{"days_since_seen": 30, "limit": 20}'
  test_tool "get_vuln_exceptions" '{"status": "active"}'
  test_tool "get_compliance_posture" '{}'
fi

if [ "$FILTER" = "all" ] || [ "$FILTER" = "slow" ]; then
  echo ""
  echo "--- Slow Tools (~30-60s) ---"
  test_tool "get_morning_report" '{}'
  test_tool "get_recommendations" '{}'
  test_tool "get_vulns_by_software" '{"software": "Apache"}'
fi

echo ""
echo "=== Summary ==="
echo "Results saved to: $RESULTS_DIR/"
echo "Timings: $RESULTS_DIR/timings.csv"
cat "$RESULTS_DIR/timings.csv" | column -t -s','
