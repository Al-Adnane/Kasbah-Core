from fastapi import FastAPI
import time
import uvicorn

app = FastAPI(title='Kasbah Core - Phase 1 (Moats 1-3)')

# Moats configuration
MOATS_ENABLED = {
    'moat1': True,  # Bidirectional Feedback
    'moat2': True,  # Geometric Integrity
    'moat3': True,  # QIFT Processing
    'moat4': False,
    'moat5': False,
    'moat6': False,
    'moat7': False,
    'moat8': False,
    'moat9': False,
    'moat10': False,
    'moat11': False,
    'moat12': False,
    'moat13': False
}

# System state
system_integrity = 0.85
total_requests = 0
allowed_requests = 0
denied_requests = 0

print('🚀 PHASE 1 STARTED: Moats 1-3')
print('✅ Moat 1: Bidirectional Feedback')
print('✅ Moat 2: Geometric Integrity')
print('✅ Moat 3: QIFT Processing')

def calculate_integrity(signals):
    # Moat 2: Geometric Integrity
    if not signals:
        return 0.5
    values = [v for v in signals.values() if isinstance(v, (int, float)) and 0 <= v <= 1]
    if not values:
        return 0.5
    product = 1.0
    for v in values:
        product *= max(0.01, v)
    return product ** (1.0 / len(values))

def process_qift(signals):
    # Moat 3: QIFT Processing
    if not signals:
        return signals
    processed = {}
    for key, value in signals.items():
        if value > 0.8:
            processed[key] = min(1.0, value * 1.05)
        elif value < 0.3:
            processed[key] = max(0.0, value * 0.95)
        else:
            processed[key] = value
    return processed

@app.get('/health')
def health():
    enabled = sum(1 for v in MOATS_ENABLED.values() if v)
    return {
        'status': 'healthy',
        'phase': 1,
        'moats_enabled': enabled,
        'moats_enabled_list': [k for k, v in MOATS_ENABLED.items() if v],
        'system_integrity': system_integrity,
        'total_requests': total_requests
    }

@app.post('/api/rtp/decide')
def decide(request: dict):
    global total_requests, allowed_requests, denied_requests, system_integrity

    total_requests += 1
    tool_name = request.get('tool_name', 'unknown')
    signals = request.get('signals', {})

    moats_triggered = []

    # MOAT 3: QIFT Processing
    if MOATS_ENABLED['moat3'] and signals:
        signals = process_qift(signals)
        moats_triggered.append('moat3')

    # MOAT 2: Geometric Integrity
    integrity = 0.5
    if MOATS_ENABLED['moat2']:
        integrity = calculate_integrity(signals)
        moats_triggered.append('moat2')

    # MOAT 1: Bidirectional Feedback
    threshold = 0.7
    if MOATS_ENABLED['moat1']:
        threshold_adjust = (1.0 - system_integrity) * 0.3
        threshold = max(0.5, min(0.9, 0.7 + threshold_adjust))
        moats_triggered.append('moat1')

    # Decision
    if integrity < threshold:
        decision = 'DENY'
        reason = f'low_integrity_{integrity:.2f}'
        denied_requests += 1
        system_integrity = max(0.1, system_integrity - 0.02)
    else:
        decision = 'ALLOW'
        reason = 'integrity_ok'
        allowed_requests += 1
        system_integrity = min(1.0, system_integrity + 0.01)

    return {
        'decision': decision,
        'reason': reason,
        'integrity_score': round(integrity, 4),
        'threshold': round(threshold, 4),
        'system_integrity': round(system_integrity, 4),
        'moats_triggered': moats_triggered,
        'moats_count': len(moats_triggered),
        'phase': 1
    }

if __name__ == '__main__':
    uvicorn.run(app, host='0.0.0.0', port=8002, access_log=False)
