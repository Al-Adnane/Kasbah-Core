/**
 * ============================================================================
 * KASBAH CORE - Python Bridge
 * ============================================================================
 * 
 * Python bridge for JavaScript/Node.js integration.
 * Handles communication between Node.js and Python core.
 * 
 * Usage:
 *   python3 -m kasbah_core.bridge
 */

import sys
import json
from kasbah_core import KasbahPipeline

def main():
    """Main bridge loop."""
    pipeline = KasbahPipeline()
    pipeline.initialize()
    
    # Send ready signal
    print(json.dumps({
        'action': 'init',
        'status': 'ready'
    }), flush=True)
    
    # Process requests
    for line in sys.stdin:
        try:
            request = json.loads(line.strip())
            response = handle_request(request, pipeline)
            print(json.dumps(response), flush=True)
        except Exception as e:
            print(json.dumps({
                'error': str(e)
            }), flush=True)

def handle_request(request, pipeline):
    """Handle incoming request."""
    action = request.get('action')
    request_id = request.get('id')
    
    if action == 'init':
        return {
            'id': request_id,
            'action': 'init',
            'status': 'ready'
        }
    
    elif action == 'detect':
        content = request.get('content', {})
        result = pipeline.detect(content)
        return {
            'id': request_id,
            'result': result
        }
    
    elif action == 'moats_status':
        status = pipeline.get_moats_status()
        return {
            'id': request_id,
            'status': status
        }
    
    elif action == 'integrity_index':
        integrity = pipeline.get_integrity_index()
        return {
            'id': request_id,
            'integrity': integrity
        }
    
    elif action == 'export_audit':
        options = request.get('options', {})
        audit = pipeline.export_audit_ledger(**options)
        return {
            'id': request_id,
            'audit': audit
        }
    
    elif action == 'shutdown':
        pipeline.shutdown()
        return {
            'id': request_id,
            'status': 'shutdown'
        }
    
    else:
        return {
            'id': request_id,
            'error': f'Unknown action: {action}'
        }

if __name__ == '__main__':
    main()
