from flask import Flask, request, jsonify
from kasbah_core import KasbahEngine

app = Flask(__name__)
engine = KasbahEngine()

@app.route('/api/decide', methods=['POST'])
def decide():
    data = request.json
    result = engine.decide(
        tool=data['tool'],
        agent_id=data.get('agent_id', 'demo'),
        signals=data.get('signals', {})
    )
    return jsonify(result)

@app.route('/api/consume', methods=['POST'])
def consume():
    data = request.json
    result = engine.consume(
        ticket=data['ticket'],
        tool=data.get('tool')
    )
    return jsonify(result)

if __name__ == '__main__':
    app.run(port=8080)
