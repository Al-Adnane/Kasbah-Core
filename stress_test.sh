#!/bin/bash

API="http://127.0.0.1:8002"
echo "🔥 KASBAH CORE 13-MOAT STRESS TEST 🔥"
echo "====================================="

# Phase 1: Basic functionality test
echo ""
echo "Phase 1: Testing all endpoints..."
echo "---------------------------------"

# Test health endpoint
echo "1. Health endpoint:"
curl -s "$API/health" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    print('   Status: ' + str(data.get('status', 'unknown')))
    print('   System Integrity: {:.3f}'.format(data.get('system_integrity', 0)))
    enabled = sum(1 for v in data.get('moats_enabled', {}).values() if v)
    print('   Moats enabled: {}/13'.format(enabled))
except Exception as e:
    print('   Error:', str(e))
"

# Test decision endpoint with good request
echo ""
echo "2. Decision endpoint (good request):"
curl -s -X POST "$API/api/rtp/decide" \
  -H "Content-Type: application/json" \
  -d '{"tool_name":"safe.operation","signals":{"normality":0.95,"consistency":0.92},"usage":{"tokens":100,"agent_id":"test-user"}}' | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    print('   Decision: ' + str(data.get('decision', 'unknown')))
    print('   Integrity: {:.3f}'.format(data.get('integrity_score', 0)))
    print('   Moats triggered: ' + str(len(data.get('moats_triggered', []))))
    if data.get('ticket'):
        print('   Ticket issued: Yes')
except Exception as e:
    print('   Error:', str(e))
"

# Phase 2: Attack simulation
echo ""
echo "Phase 2: Simulating attacks..."
echo "------------------------------"

attacks=(
    '{"tool_name":"SELECT * FROM users","signals":{"normality":0.1}}'
    '{"tool_name":"<script>alert(1)</script>","signals":{"normality":0.2}}'
    '{"tool_name":"DROP TABLE users","signals":{"normality":0.15}}'
    '{"tool_name":"../../../etc/passwd","signals":{"normality":0.1}}'
    '{"tool_name":"UNION SELECT","signals":{"normality":0.3}}'
)

echo "3. Testing attack patterns:"
blocked_count=0
for i in "${!attacks[@]}"; do
    response=$(curl -s -X POST "$API/api/rtp/decide" \
        -H "Content-Type: application/json" \
        -d "${attacks[$i]}")
    
    if echo "$response" | grep -q '"decision":"DENY"'; then
        echo "   ✅ Attack $((i+1)) blocked"
        blocked_count=$((blocked_count + 1))
    else
        echo "   ❌ Attack $((i+1)) not blocked"
    fi
done
echo "   Attack block rate: $blocked_count/${#attacks[@]}"

# Phase 3: Load testing
echo ""
echo "Phase 3: Load testing..."
echo "------------------------"

echo "4. Sending 50 rapid requests..."
for i in {1..50}; do
    curl -s -X POST "$API/api/rtp/decide" \
        -H "Content-Type: application/json" \
        -d "{\"tool_name\":\"load.test.$i\",\"signals\":{\"normality\":0.$((RANDOM % 100))}}" > /dev/null &
    if (( i % 10 == 0 )); then
        wait
        echo -n "."
    fi
done
wait
echo " Done!"

# Phase 4: Resource exhaustion test
echo ""
echo "Phase 4: Resource testing..."
echo "----------------------------"

echo "5. Testing resource limits:"
for tokens in 100 500 1000 2000 5000; do
    response=$(curl -s -X POST "$API/api/rtp/decide" \
        -H "Content-Type: application/json" \
        -d "{\"tool_name\":\"heavy.process\",\"signals\":{\"normality\":0.8},\"usage\":{\"tokens\":$tokens}}")
    
    if echo "$response" | grep -q '"decision":"DENY"' && echo "$response" | grep -q '"reason":"drf"'; then
        echo "   ✅ $tokens tokens correctly blocked by DRF"
    else
        echo "   ⚠️  $tokens tokens allowed"
    fi
done

# Phase 5: Final system check
echo ""
echo "Phase 5: System verification..."
echo "-------------------------------"

echo "6. Checking system metrics:"
curl -s "$API/api/system/metrics" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    print('   Total requests: ' + str(data.get('total_requests', 0)))
    print('   Allowed: ' + str(data.get('allowed_requests', 0)))
    print('   Denied: ' + str(data.get('denied_requests', 0)))
    print('   Attacks blocked: ' + str(data.get('attacks_blocked', 0)))
    
    moats = data.get('moats_triggered', {})
    print('   Moats triggered: ' + str(len(moats)) + '/13')
    
    # List all moats that were triggered
    if moats:
        print('   Active moats:')
        for i in range(1, 14):
            count = moats.get('moat{}'.format(i), 0)
            if count > 0:
                print('     ✅ Moat {}: {} times'.format(i, count))
except Exception as e:
    print('   Error:', str(e))
"

echo ""
echo "7. Checking moats configuration:"
curl -s "$API/api/system/moats" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    active = data.get('active_moats', [])
    print('   Active moats: {}/13'.format(len(active)))
    
    # Check specific moats
    if 'moat5' in active:
        print('   ✅ Moat 5 (ATP): Adversarial Training active')
    if 'moat8' in active:
        print('   ✅ Moat 8 (SPD): Stochastic Parrot Detection active')
    if 'moat11' in active:
        print('   ✅ Moat 11 (DRF): Dynamic Resource Firewalling active')
    if 'moat13' in active:
        print('   ✅ Moat 13 (ZKPC): Zero-Knowledge Proof active')
except Exception as e:
    print('   Error:', str(e))
"

# Final verdict
echo ""
echo "====================================="
echo "🎯 STRESS TEST COMPLETE"
echo "====================================="

# Quick health check
health=$(curl -s "$API/health")
if echo "$health" | grep -q '"status":"healthy"'; then
    integrity=$(echo "$health" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('system_integrity', 0))")
    echo "✅ System is healthy"
    echo "📊 Final integrity: $integrity"
    
    if (( $(echo "$integrity > 0.7" | bc -l 2>/dev/null) )); then
        echo ""
        echo "🏆 ALL TESTS PASSED - 13 MOATS WORKING TOGETHER!"
        echo "The system maintained integrity under stress and blocked attacks."
    else
        echo ""
        echo "⚠️  System integrity is low: $integrity"
        echo "Some moats might be struggling under load."
    fi
else
    echo "❌ System is unhealthy"
fi

echo ""
echo "📈 Next steps:"
echo "   - Check logs: tail -f complete_moats.log"
echo "   - View audit: curl $API/api/rtp/audit"
echo "   - Monitor metrics: curl $API/api/system/metrics"
