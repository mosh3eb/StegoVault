#!/bin/bash
# Test runner for StegoVault 2.0

echo "=========================================="
echo "StegoVault 2.0 - Test Suite"
echo "=========================================="

cd "$(dirname "$0")"

# Add src to Python path
export PYTHONPATH="${PWD}/src:${PYTHONPATH}"

# Test 1: Basic CLI commands
echo ""
echo "TEST 1: Basic CLI Commands"
echo "---------------------------"

# Create test files
mkdir -p test_temp
echo "Test secret content" > test_temp/test.txt
echo "File 1" > test_temp/file1.txt
echo "File 2" > test_temp/file2.txt

# Test embed
echo "Testing embed..."
python3 src/stegovault/cli_main.py embed test_temp/test.txt test_temp/output.png --password "testpass" 2>&1 | grep -q "successfully" && echo "✅ Embed test passed" || echo "❌ Embed test failed"

# Test extract
echo "Testing extract..."
python3 src/stegovault/cli_main.py extract test_temp/output.png --password "testpass" --output test_temp/extracted.txt 2>&1 | grep -q "successfully" && echo "✅ Extract test passed" || echo "❌ Extract test failed"

# Test info
echo "Testing info..."
python3 src/stegovault/cli_main.py info test_temp/output.png 2>&1 | grep -q "File Name" && echo "✅ Info test passed" || echo "❌ Info test failed"

# Test archive
echo "Testing archive embed..."
python3 src/stegovault/cli_main.py embed-archive test_temp/file1.txt test_temp/file2.txt test_temp/archive.png --password "testpass" 2>&1 | grep -q "successfully" && echo "✅ Archive embed test passed" || echo "❌ Archive embed test failed"

# Test archive extract
echo "Testing archive extract..."
mkdir -p test_temp/extracted
python3 src/stegovault/cli_main.py extract-archive test_temp/archive.png --output test_temp/extracted --password "testpass" 2>&1 | grep -q "successfully" && echo "✅ Archive extract test passed" || echo "❌ Archive extract test failed"

# Test capacity
echo "Testing capacity..."
python3 src/stegovault/cli_main.py capacity test_temp/output.png 2>&1 | grep -q "Capacity" && echo "✅ Capacity test passed" || echo "❌ Capacity test failed"

# Test detect
echo "Testing detect..."
python3 src/stegovault/cli_main.py detect test_temp/output.png 2>&1 | grep -q "Risk" && echo "✅ Detect test passed" || echo "❌ Detect test failed"

# Test privacy
echo "Testing privacy..."
python3 src/stegovault/cli_main.py privacy test_temp/output.png 2>&1 | grep -q "Privacy" && echo "✅ Privacy test passed" || echo "❌ Privacy test failed"

# Cleanup
rm -rf test_temp

echo ""
echo "=========================================="
echo "Tests Complete"
echo "=========================================="

