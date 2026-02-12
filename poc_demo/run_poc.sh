#!/bin/bash

echo "======================================================================"
echo "JWKSET Race Condition POC Runner"
echo "======================================================================"
echo ""

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "❌ Error: Go is not installed"
    exit 1
fi

echo "Running POC demonstrations..."
echo ""

echo "----------------------------------------------------------------------"
echo "POC 1: Vulnerable vs Fixed Implementation Comparison"
echo "----------------------------------------------------------------------"
echo "This demonstrates the difference between vulnerable and fixed versions"
echo ""

go run -mod=mod vulnerable_version.go

echo ""
echo ""
echo "----------------------------------------------------------------------"
echo "POC 2: Current jwkset Library Test (Should be FIXED)"
echo "----------------------------------------------------------------------"
echo "This tests the actual jwkset library (should show no vulnerability)"
echo ""

go run -mod=mod main.go

echo ""
echo ""
echo "======================================================================"
echo "POC Execution Complete"
echo "======================================================================"
echo ""
echo "📖 For detailed documentation, see:"
echo "   - README.md (detailed explanation)"
echo "   - ../RACE_CONDITION_POC.md (summary)"
echo ""
echo "🔍 Key files:"
echo "   - vulnerable_version.go (comparison POC)"
echo "   - main.go (library test POC)"
echo "   - ../storage.go:265-289 (fix location)"
echo ""
