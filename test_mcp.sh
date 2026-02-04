#!/bin/bash

# Comprehensive MCP Testing Script
# Sends 50 realistic security queries across all modules

set -e

MCP_BIN="./qualys-mcp"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASSED=0
FAILED=0
TOTAL=0

call_tool() {
    local name="$1"
    local args="$2"
    local desc="$3"

    TOTAL=$((TOTAL + 1))
    printf "[%02d] %-60s " "$TOTAL" "$desc"

    # Build JSON-RPC request
    local request=$(cat <<EOF
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"$name","arguments":$args}}
EOF
)

    # Call MCP and capture response
    local response=$(echo "$request" | timeout 30 $MCP_BIN 2>/dev/null | tail -1)

    if echo "$response" | grep -q '"error"'; then
        local error=$(echo "$response" | grep -o '"message":"[^"]*"' | head -1)
        echo -e "${RED}FAIL${NC} $error"
        FAILED=$((FAILED + 1))
    elif echo "$response" | grep -q '"result"'; then
        echo -e "${GREEN}PASS${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "${YELLOW}UNKNOWN${NC}"
        FAILED=$((FAILED + 1))
    fi
}

echo "=============================================="
echo "  Qualys MCP Comprehensive Test Suite"
echo "  Testing 50 security queries"
echo "=============================================="
echo ""

# Check prerequisites
if [ ! -f "$MCP_BIN" ]; then
    echo "Building MCP server..."
    go build -o qualys-mcp ./cmd/qualys-mcp
fi

if [ -z "$QUALYS_POD" ]; then
    echo -e "${RED}Error: QUALYS_POD not set${NC}"
    echo "Run: export QUALYS_POD=US1 (or your pod)"
    exit 1
fi

if [ -z "$QUALYS_USERNAME" ] || [ -z "$QUALYS_PASSWORD" ]; then
    echo -e "${RED}Error: QUALYS_USERNAME or QUALYS_PASSWORD not set${NC}"
    exit 1
fi

echo "Using POD: $QUALYS_POD"
echo ""

# ============================================
# VMDR Module Tests (1-10)
# ============================================
echo -e "${YELLOW}=== VMDR Module ===${NC}"

call_tool "vmdr_list_hosts" '{"limit":10}' \
    "List hosts with vulnerabilities"

call_tool "vmdr_list_hosts" '{"filter":"1-50","limit":5}' \
    "List first 50 host IDs"

call_tool "vmdr_search_detections" '{"query":"11830","limit":5}' \
    "Search for ShellShock (QID 11830)"

call_tool "vmdr_search_detections" '{"query":"38739","limit":5}' \
    "Search for Log4Shell (QID 38739)"

call_tool "vmdr_search_detections" '{"query":"91849","limit":5}' \
    "Search for EternalBlue (QID 91849)"

call_tool "vmdr_list_scans" '{"limit":10}' \
    "List recent vulnerability scans"

call_tool "vmdr_list_scans" '{"status":"Finished","limit":5}' \
    "List completed scans"

call_tool "vmdr_list_asset_groups" '{}' \
    "List all asset groups"

call_tool "vmdr_search_detections" '{"query":"38173","limit":5}' \
    "Search for OpenSSL vulns (QID 38173)"

call_tool "vmdr_search_detections" '{"query":"197191","limit":5}' \
    "Search for Spring4Shell (QID 197191)"

# ============================================
# KnowledgeBase Module Tests (11-20)
# ============================================
echo ""
echo -e "${YELLOW}=== KnowledgeBase Module ===${NC}"

call_tool "kb_search_vulns" '{"keyword":"openssl","limit":10}' \
    "Search KB for OpenSSL vulnerabilities"

call_tool "kb_search_vulns" '{"keyword":"log4j","limit":10}' \
    "Search KB for Log4j vulnerabilities"

call_tool "kb_search_vulns" '{"keyword":"apache","limit":10}' \
    "Search KB for Apache vulnerabilities"

call_tool "kb_search_vulns" '{"keyword":"remote code execution","limit":10}' \
    "Search KB for RCE vulnerabilities"

call_tool "kb_get_cve_mapping" '{"cve":"CVE-2021-44228"}' \
    "Map CVE-2021-44228 (Log4Shell) to QIDs"

call_tool "kb_get_cve_mapping" '{"cve":"CVE-2014-0160"}' \
    "Map CVE-2014-0160 (Heartbleed) to QIDs"

call_tool "kb_get_cve_mapping" '{"cve":"CVE-2017-0144"}' \
    "Map CVE-2017-0144 (EternalBlue) to QIDs"

call_tool "kb_get_cve_mapping" '{"cve":"CVE-2022-22965"}' \
    "Map CVE-2022-22965 (Spring4Shell) to QIDs"

call_tool "kb_list_recent_vulns" '{"days":7,"limit":20}' \
    "List vulns published in last 7 days"

call_tool "kb_list_recent_vulns" '{"days":30,"limit":10}' \
    "List vulns published in last 30 days"

# ============================================
# Container Security Module Tests (21-28)
# ============================================
echo ""
echo -e "${YELLOW}=== Container Security Module ===${NC}"

call_tool "cs_list_images" '{"limit":10}' \
    "List container images"

call_tool "cs_list_images" '{"filter":"vulnerabilities.severity:5","limit":10}' \
    "List images with critical vulns"

call_tool "cs_list_containers" '{"limit":10}' \
    "List running containers"

call_tool "cs_list_containers" '{"filter":"state:RUNNING","limit":10}' \
    "List only running containers"

call_tool "cs_search_images" '{"query":"repo:nginx","limit":5}' \
    "Search for nginx images"

call_tool "cs_search_images" '{"query":"repo:alpine","limit":5}' \
    "Search for alpine images"

call_tool "cs_search_images" '{"query":"vulnerabilities.severity:5","limit":5}' \
    "Search images with critical CVEs"

call_tool "cs_list_images" '{"filter":"repo:ubuntu","limit":5}' \
    "List Ubuntu-based images"

# ============================================
# Global AssetView Module Tests (29-35)
# ============================================
echo ""
echo -e "${YELLOW}=== Global AssetView Module ===${NC}"

call_tool "gav_list_assets" '{"limit":10}' \
    "List all assets"

call_tool "gav_search_assets" '{"query":"operatingSystem:Windows","limit":10}' \
    "Search for Windows assets"

call_tool "gav_search_assets" '{"query":"operatingSystem:Linux","limit":10}' \
    "Search for Linux assets"

call_tool "gav_search_assets" '{"query":"lastVulnScan.date<now-30d","limit":10}' \
    "Assets not scanned in 30 days"

call_tool "gav_list_tags" '{}' \
    "List all asset tags"

call_tool "gav_search_assets" '{"query":"openPort:22","limit":10}' \
    "Assets with SSH port open"

call_tool "gav_search_assets" '{"query":"openPort:3389","limit":10}' \
    "Assets with RDP port open"

# ============================================
# Patch Management Module Tests (36-40)
# ============================================
echo ""
echo -e "${YELLOW}=== Patch Management Module ===${NC}"

call_tool "pm_list_patches" '{"limit":10}' \
    "List available patches"

call_tool "pm_list_patches" '{"filter":"severity:Critical","limit":10}' \
    "List critical patches"

call_tool "pm_list_assets" '{"limit":10}' \
    "List assets with patch status"

call_tool "pm_list_jobs" '{"limit":10}' \
    "List patch deployment jobs"

call_tool "pm_list_jobs" '{"status":"Completed","limit":5}' \
    "List completed patch jobs"

# ============================================
# TotalCloud Module Tests (41-45)
# ============================================
echo ""
echo -e "${YELLOW}=== TotalCloud Module ===${NC}"

call_tool "tc_list_connectors" '{"provider":"aws","limit":10}' \
    "List AWS connectors"

call_tool "tc_list_resources" '{"provider":"AWS","resource_type":"EC2_INSTANCE","limit":10}' \
    "List AWS EC2 instances"

call_tool "tc_list_controls" '{"provider":"AWS","limit":10}' \
    "List AWS security controls"

call_tool "tc_list_cdr_findings" '{"provider":"AWS","days":7,"limit":10}' \
    "List CDR findings"

call_tool "tc_list_connectors" '{"provider":"azure","limit":10}' \
    "List Azure connectors"

# ============================================
# Additional Security Queries (46-50)
# ============================================
echo ""
echo -e "${YELLOW}=== Additional Security Queries ===${NC}"

call_tool "kb_search_vulns" '{"keyword":"CVE-2023","limit":10}' \
    "Search for 2023 CVEs"

call_tool "kb_search_vulns" '{"keyword":"privilege escalation","limit":10}' \
    "Search for privilege escalation"

call_tool "cert_list_certificates" '{"limit":10}' \
    "List SSL certificates"

call_tool "cert_get_expiring" '{"days":30,"limit":10}' \
    "Certs expiring in 30 days"

call_tool "was_list_webapps" '{"limit":10}' \
    "List web applications"

# ============================================
# Summary
# ============================================
echo ""
echo "=============================================="
echo "  Test Results Summary"
echo "=============================================="
echo -e "  Total:  $TOTAL"
echo -e "  ${GREEN}Passed: $PASSED${NC}"
echo -e "  ${RED}Failed: $FAILED${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${YELLOW}Some tests failed - check output above${NC}"
    exit 1
fi
