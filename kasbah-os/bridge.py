#!/usr/bin/env python3
"""
kasbah-os/bridge.py — stdio JSON-RPC bridge.

Wires the standalone kasbah-os Python package into the Node system without any
HTTP (the host sandbox intercepts localhost). Node spawns this process and
exchanges newline-delimited JSON: {"id","method","params"} -> {"id","result"|"error"}.

DEFENSIVE modules are exposed as live callable methods:
  - governance.process_turn / governance.approve / governance.health
  - audit.record / audit.verify

OFFENSIVE / Mythos modules (zeroday, exploit, kernel-fuzz, binary, self-play,
neuromorphic, mythos) are exposed for INTROSPECTION ONLY (name + docstring).
Their functions are NOT invoked here. They remain inert simulation; this bridge
deliberately does not provide a path to execute them.
"""

import sys, os, json, importlib, inspect

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

_gov = None
_audit = None


def _governance():
    global _gov
    if _gov is None:
        import governance_proxy as g
        _gov = g.get_governance()
    return _gov


def _audit_store():
    global _audit
    if _audit is None:
        import crypto_audit as c
        _audit = c.ZeroTrustAudit()
    return _audit


def _to_clearance(val):
    try:
        import governance_proxy as g
        return g.ClearanceLevel(int(val if val is not None else 2))
    except Exception:
        return 2


OFFENSIVE = ['zeroday_engine', 'exploit_pipeline', 'kernel_fuzzer',
             'binary_engine', 'adversarial_selfplay', 'neuromorphic_engine',
             'kasbah_mythos']


def handle(method, params):
    params = params or {}
    if method == 'health':
        gp = _governance()
        h = gp.health() if hasattr(gp, 'health') else {}
        return {'ok': True, 'governance': h, 'auditIntegrity': _audit_store().verify_system_integrity()}

    if method == 'governance.process_turn':
        gp = _governance()
        out = gp.process_turn_sync(
            messages=params.get('messages', []),
            tools=params.get('tools', []),
            clearance=_to_clearance(params.get('clearance', 2)),
        )
        return _jsonable(out)

    if method == 'governance.approve':
        gp = _governance()
        return _jsonable(gp.approve_action(params.get('action_id', '')))

    if method == 'audit.record':
        aid = _audit_store().record_event(
            params.get('engine', 'node'),
            params.get('event_type', 'event'),
            params.get('data', {}),
        )
        return {'eventId': aid}

    if method == 'audit.verify':
        return {'integrity': bool(_audit_store().verify_system_integrity())}

    if method == 'offensive.info':
        info = {}
        for m in OFFENSIVE:
            try:
                mod = importlib.import_module(m)
                doc = (inspect.getdoc(mod) or '').strip().split('\n')[0]
                classes = [n for n, o in vars(mod).items()
                           if inspect.isclass(o) and getattr(o, '__module__', '') == m]
                info[m] = {'summary': doc[:120], 'classes': classes[:8], 'invocable': False,
                           'note': 'simulation only — not executed via bridge'}
            except Exception as e:
                info[m] = {'error': str(e)[:80]}
        return {'offensiveModules': info,
                'note': 'Introspection only. Offensive functions are inert simulation and are not callable here.'}

    raise ValueError(f'unknown method: {method}')


def _jsonable(x):
    """Best-effort convert numpy / enums / dataclasses to plain JSON."""
    try:
        json.dumps(x)
        return x
    except (TypeError, ValueError):
        import numpy as np
        if isinstance(x, dict):
            return {str(k): _jsonable(v) for k, v in x.items()}
        if isinstance(x, (list, tuple)):
            return [_jsonable(v) for v in x]
        if isinstance(x, (np.floating,)):
            return float(x)
        if isinstance(x, (np.integer,)):
            return int(x)
        if isinstance(x, np.ndarray):
            return x.tolist()
        if hasattr(x, 'value'):     # enum
            return x.value
        return str(x)


def main():
    sys.stderr.write('[kasbah-os bridge] ready\n'); sys.stderr.flush()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue
        rid = req.get('id')
        try:
            result = handle(req.get('method', ''), req.get('params'))
            sys.stdout.write(json.dumps({'id': rid, 'result': result}) + '\n')
        except Exception as e:
            sys.stdout.write(json.dumps({'id': rid, 'error': str(e)[:200]}) + '\n')
        sys.stdout.flush()


if __name__ == '__main__':
    main()
