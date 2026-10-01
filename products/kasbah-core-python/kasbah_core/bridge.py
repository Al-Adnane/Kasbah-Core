"""
kasbah_core.bridge — JSON-over-stdio bridge for Node.js integration.

Usage:
    python3 -m kasbah_core.bridge
"""

import sys
import json
import traceback

from kasbah_core import KasbahPipeline


def handle_request(request, pipeline):
    action = request.get('action')
    request_id = request.get('id')

    if action == 'init':
        return {'id': request_id, 'action': 'init', 'status': 'ready'}

    elif action == 'detect':
        content = request.get('content', {})
        result = pipeline.detect(content)
        return {'id': request_id, 'result': result}

    elif action == 'moats_status':
        status = pipeline.get_moats_status()
        return {'id': request_id, 'status': status}

    elif action == 'integrity_index':
        integrity = pipeline.get_integrity_index()
        return {'id': request_id, 'integrity': integrity}

    elif action == 'export_audit':
        options = request.get('options', {})
        audit = pipeline.export_audit_ledger(**options)
        return {'id': request_id, 'audit': audit}

    elif action == 'shutdown':
        pipeline.shutdown()
        return {'id': request_id, 'status': 'shutdown'}

    else:
        return {'id': request_id, 'error': f'Unknown action: {action}'}


def main():
    pipeline = KasbahPipeline()
    pipeline.initialize()

    # Signal ready
    print(json.dumps({'action': 'init', 'status': 'ready'}), flush=True)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
            response = handle_request(request, pipeline)
            print(json.dumps(response), flush=True)
        except Exception as exc:
            print(json.dumps({'error': str(exc), 'traceback': traceback.format_exc()}), flush=True)


if __name__ == '__main__':
    main()
