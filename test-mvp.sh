#!/bin/bash

# GoSniffer MVP Test Script
# Tests User Story 1 (HTTP interception) acceptance criteria

PROXY="http://localhost:8080"
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo "GoSniffer MVP Test Suite (User Story 1)"
echo "=========================================="
echo ""

# Check if proxy is running
echo -n "Checking if GoSniffer is running on port 8080... "
if ! nc -z localhost 8080 2>/dev/null; then
    echo -e "${RED}FAILED${NC}"
    echo "Please start GoSniffer first: ./bin/gosniffer -addr :8080"
    exit 1
fi
echo -e "${GREEN}OK${NC}"
echo ""

# Test 1: HTTP GET request with header injection
echo "Test 1: HTTP GET request (should inject X-Proxied-By header)"
echo "----------------------------------------------"
RESPONSE=$(curl -s -x $PROXY http://httpbin.org/headers)
if echo "$RESPONSE" | grep -q "X-Proxied-By.*GoSniffer"; then
    echo -e "${GREEN}✓ PASSED${NC} - Custom header injected"
else
    echo -e "${RED}✗ FAILED${NC} - Custom header not found"
fi
echo ""

# Test 2: HTTP request logging (check console manually)
echo "Test 2: HTTP request logging"
echo "----------------------------------------------"
echo "Making request to httpbin.org..."
curl -s -x $PROXY http://httpbin.org/status/200 > /dev/null
echo -e "${YELLOW}Check GoSniffer console for:${NC}"
echo "  [timestamp] httpbin.org - 200"
echo ""

# Test 3: HTTP 404 status code logging
echo "Test 3: HTTP 404 status code logging"
echo "----------------------------------------------"
echo "Making request that returns 404..."
curl -s -x $PROXY http://httpbin.org/status/404 > /dev/null
echo -e "${YELLOW}Check GoSniffer console for:${NC}"
echo "  [timestamp] httpbin.org - 404"
echo ""

# Test 4: CONNECT method (should return 501 Not Implemented)
echo "Test 4: CONNECT method (HTTPS not yet implemented)"
echo "----------------------------------------------"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -x $PROXY https://httpbin.org/get 2>&1 | grep -o '[0-9]*' | head -1)
if [ "$HTTP_CODE" = "501" ]; then
    echo -e "${GREEN}✓ PASSED${NC} - CONNECT returns 501 Not Implemented"
else
    echo -e "${RED}✗ FAILED${NC} - Expected 501, got $HTTP_CODE"
fi
echo ""

# Test 5: Concurrent requests (test for race conditions)
echo "Test 5: Concurrent HTTP requests (3 parallel)"
echo "----------------------------------------------"
echo "Sending 3 concurrent requests..."
curl -s -x $PROXY http://httpbin.org/delay/1 > /dev/null &
curl -s -x $PROXY http://httpbin.org/delay/1 > /dev/null &
curl -s -x $PROXY http://httpbin.org/delay/1 > /dev/null &
wait
echo -e "${YELLOW}Check GoSniffer console for 3 log entries${NC}"
echo "  All should show correct hostname and status without corruption"
echo ""

# Test 6: Upstream error handling (invalid domain)
echo "Test 6: Upstream error handling (Bad Gateway)"
echo "----------------------------------------------"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -x $PROXY http://this-domain-does-not-exist-12345.com/ 2>&1)
if echo "$HTTP_CODE" | grep -q "502"; then
    echo -e "${GREEN}✓ PASSED${NC} - Returns 502 Bad Gateway for unreachable upstream"
else
    echo -e "${YELLOW}⚠ PARTIAL${NC} - Got HTTP $HTTP_CODE (expected 502)"
fi
echo ""

echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "Manual verification required:"
echo "  1. Check GoSniffer console for correct log format"
echo "  2. Verify no race conditions in concurrent test"
echo "  3. Test graceful shutdown with Ctrl+C"
echo ""
echo "Next: Implement Phase 4 (HTTPS MITM) to enable full TLS interception"
