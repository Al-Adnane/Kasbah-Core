#!/bin/bash

# Kasbah API Builder - Complete in one command

cd /Users/mac/Projects/kasbah-core

# Create API directory
mkdir -p api

# Create Flask server
cat > api/server.py << 'PYEOF'
from flask import Flask, request, jsonify
from flask_cors import CORS
import hmac
import hashlib
import time

app = Flask(__name__)
CORS(app)

# In-memory storage (Redis optional)
CONSUMED_TICKETS = {}
SECRET_KEY = "kasbah-demo-secret-2024"

def sign_ticket(tool, agent_id, timestamp):
    payload = f"{tool}:{agent_id}:{timestamp}"
    signature = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}:{signature}"

def verify_ticket(ticket, tool):
    try:
        parts = ticket.split(':')
        if len(parts) != 4:
            return False, "invalid_format"
        ticket_tool, agent_id, timestamp, signature = parts
        if ticket_tool != tool:
            return False, "tool_mismatch"
        if time.time() - int(timestamp) > 900:
            return False, "expired"
        expected = hmac.new(SECRET_KEY.encode(), f"{ticket_tool}:{agent_id}:{timestamp}".encode(), hashlib.sha256).hexdigest()
        return signature == expected, "valid" if signature == expected else "invalid_signature"
    except:
        return False, "error"

@app.route('/api/decide', methods=['POST'])
def decide():
    data = request.json
    tool = data.get('tool')
    agent_id = data.get('agent_id', 'demo')
    signals = data.get('signals', {})
    integrity = sum(signals.values()) / len(signals) if signals else 0.95
    timestamp = str(int(time.time()))
    ticket = sign_ticket(tool, agent_id, timestamp)
    return jsonify({'allowed': integrity > 0.7, 'ticket': ticket, 'integrity': integrity})

@app.route('/api/consume', methods=['POST'])
def consume():
    data = request.json
    ticket = data.get('ticket')
    tool = data.get('tool')
    if not ticket or not tool:
        return jsonify({'allowed': False, 'reason': 'missing_params'}), 400
    valid, reason = verify_ticket(ticket, tool)
    if not valid:
        return jsonify({'allowed': False, 'reason': reason}), 403
    if ticket in CONSUMED_TICKETS:
        return jsonify({'allowed': False, 'reason': 'already_consumed'}), 403
    CONSUMED_TICKETS[ticket] = time.time()
    return jsonify({'allowed': True, 'consumed': True})

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'tickets_consumed': len(CONSUMED_TICKETS)})

if __name__ == '__main__':
    print("🏰 Kasbah API: http://localhost:5000")
    app.run(port=5000, debug=True)
PYEOF

# Create requirements
cat > api/requirements.txt << 'REQEOF'
flask==3.0.0
flask-cors==4.0.0
REQEOF

# Create README
cat > api/README.md << 'READEOF'
# Kasbah API

Real backend for Kasbah demos.

## Start
```bash
cd api
pip install -r requirements.txt
python server.py
```

## Test
```bash
curl http://localhost:5000/api/health
```
READEOF

# Commit everything
git add api/
git commit -m "Add working Kasbah API backend"
git push

echo ""
echo "✅ API created!"
echo ""
echo "To start:"
echo "  cd api"
echo "  pip install -r requirements.txt"
echo "  python server.py"
echo ""
echo "Test:"
echo "  curl http://localhost:5000/api/health"

