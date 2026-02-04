#!/bin/bash

API_URL="http://127.0.0.1:8002"

echo "🧪 Testing Kasbah Core Integration"
echo "=================================="
echo ""

# Test 1: Health Check
echo "1. Testing Health Endpoint..."
HEALTH=$(curl -s "$API_URL/health")
if echo "$HEALTH" | grep -q "status"; then
    STATUS=$(echo "$HEALTH" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('status', 'unknown'))")
    else
    echo "   ❌ Health check failed"
fi

# Test 2: Decision Endpoint
echo ""
echo "2. Testing Decision Engine..."
DECISION=$(curl -s -X POST "$API_URL/api/rtp/decide" \
  -H "Content-Type: application/json" \
  -d '{"tool_name":"read.me","signals":{"normality":0.9},"usage":{"agent_id":"tester"}}')

if echo "$DECISION" | grep -q "decision"; then
    DECISION_RESULT=$(echo "$DECISION" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('decision', 'unknown'))")
    INTEGRITY_SCORE=$(echo "$DECISION" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('integrity_score', 0))")
    echo "   ✅ Decision: $DECISION_RESULT"
    echo "   📊 Integrity Score: $INTEGRITY_SCORE"
    
    if echo "$DECISION" | grep -q "ticket"; then
        echo "   🎫 Ticket system working"
    fi
else
    echo "   ❌ Decision engine failed"
fi

# Test 3: System Metrics
echo ""
echo "3. Testing System Metrics..."
METRICS=$(curl -s "$API_URL/api/system/metrics")
if echo "$METRICS" | grep -q "total_requests"; then
    TOTAL=$(echo "$METRICS" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('total_requests', 0))")
    ALLOWED=$(echo "$METRICS" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('allowed_requests', 0))")
    DENIED=$(echo "$METRICS" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('denied_requests', 0))")
    echo "   📈 Total Requests: $TOTAL"
    echo "   ✅ Allowed: $ALLOWED"
    echo "   ❌ Denied: $DENIED"
else
    echo "   ❌ Metrics endpoint failed"
fi

# Test 4: Moats Status
echo ""
echo "4. Testing Moats Status..."
MOATS=$(curl -s "$API_URL/api/system/moats")
if echo "$MOATS" | grep -q "active_moats"; then
    ACTIVE_COUNT=$(echo "$MOATS" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('active_moats', [])))")
    echo "   🔐 Active Moats: $ACTIVE_COUNT/13"
    if [ "$ACTIVE_COUNT" -eq 13 ]; then
        echo "   ✅ All 13 moats are active!"
    fi
else
    echo "   ❌ Moats status failed"
fi

echo ""
echo "=================================="
echo "🎉 Integration Test Complete!"
echo "🕐 Test completed at: $(date)"
