#!/usr/bin/env python3
"""ssi_cli.py — JSON CLI bridge: Node (api-server/desktop) <-> Python SSI cores.

Protocol: one JSON object on stdin -> one JSON object on stdout.
  {"cmd": "selftest"}                        both cores' suites + calibrate
  {"cmd": "screen", "rights": [...], "sub": [...], "tel": [...]}
  {"cmd": "admit", "rights": [...], "scope": 1, "ttl_ms": 200,
   "sub": [...], "tel": [...], "inner": null|string, "manifest": "hex"|null}
  {"cmd": "engine_admit", "consent": true, ...}   Engine Max request() flow
  {"cmd": "engine_selftest"}                 Engine Max suite (slow-ish)

Stdlib only. Exit 0 always (errors reported in JSON) so callers never hang.
"""

import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ssi_universal_core import (
    Config, Decision, DomainKeyring, SoftwareProvider, SovereignProver,
    SovereignStateSnapshot, SovereignProof, ValidatedSnapshot,
    TicketAuthority, ChronicleAuditLedger, UniversalAdmissionGate,
    HumanEngine, InnerSpeechGate, SovereignGate, calibrate_epsilon,
    ksg1_mi_estimate, H,
)


def _gate():
    hw = SoftwareProvider()
    kr = DomainKeyring(hw)
    return UniversalAdmissionGate(SovereignProver(kr), TicketAuthority(kr),
                                  ChronicleAuditLedger(kr)), kr


def do_selftest():
    # Fast deterministic spot-checks (full 18/18 lives in
    # ssi_universal_core.py __main__; Engine Max 13/13 in selftest cmd).
    try:
        gate, _ = _gate()
        human = HumanEngine()
        h = human.score(r_signal=0.9, e_hrv=0.8, e_f0=0.85, e_text=0.9)
        assert 0.0 < h <= 1.0
        assert ksg1_mi_estimate([0.5] * 8, [0.5] * 8) < 0.25
        assert gate.admit("x", None, b"m", 1) == Decision.DENY_TYPE
        cal = calibrate_epsilon(n_cohorts=50)
        return {"ok": True, "human_score": round(h, 4),
                "calibration": cal, "suites": "run ssi_universal_core.py directly for 18/18"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def main():
    try:
        req = json.loads(sys.stdin.read() or "{}")
    except Exception as e:
        print(json.dumps({"ok": False, "error": f"bad json: {e}"}))
        return
    cmd = req.get("cmd")
    try:
        if cmd == "selftest":
            print(json.dumps(do_selftest()))
        elif cmd == "screen":
            rights = req.get("rights") or [1.0, 0.8, 0.5, 1.0]
            base = list(Config.RIGHTS_BASE)
            failed = [j for j, (r, b) in enumerate(zip(rights, base)) if r - b < 0]
            out = {"ok": True, "rights_ok": not failed, "rights_failed": failed}
            sub, tel = req.get("sub"), req.get("tel")
            if sub and tel and len(sub) >= 4 and len(sub) == len(tel):
                mi = ksg1_mi_estimate([float(v) for v in sub], [float(v) for v in tel])
                out["mi"] = round(mi, 4)
                out["leak"] = mi > Config.EPSILON_LEAK
            print(json.dumps(out))
        elif cmd == "admit":
            gate, kr = _gate()
            if req.get("inner") is not None:
                isg = InnerSpeechGate()
                isg.enroll(req.get("enrolled") or "execute")
                gate.inner_speech = isg
            human = HumanEngine()
            r = req.get("rights") or [1.0, 0.8, 0.5, 1.0]
            raw = SovereignStateSnapshot.build(
                human.score(r_signal=0.9, e_hrv=0.8, e_f0=0.85, e_text=0.9),
                0.95, 0.90, tuple(float(v) for v in r))
            proof, perr = gate.prover.prove(raw)
            if proof is None:
                print(json.dumps({"ok": True, "admitted": False,
                                  "deny": perr.name}))
                return
            man_hex = req.get("manifest")
            manifest = bytes.fromhex(man_hex) if man_hex else H(b"ssi-cli-action")
            scope = int(req.get("scope", 1))
            ticket = gate.tickets.issue(raw.state_hash, manifest, scope,
                                        int(req.get("ttl_ms", 200)))
            dec = gate.admit(ValidatedSnapshot(raw, proof, req.get("inner")),
                             ticket, manifest, scope, req.get("sub"), req.get("tel"))
            print(json.dumps({"ok": True, "admitted": dec == Decision.ADMIT,
                              "deny": dec.name}))
        elif cmd == "engine_admit":
            from sovereign_engine_max import SovereignEngineMax, Decision as MD
            eng = SovereignEngineMax()
            eng.collective.publish(0.85)
            d, v, tk, cap = eng.request(consent=bool(req.get("consent", True)))
            out = {"ok": True, "admitted": d == MD.ADMIT, "deny": d.value}
            if cap is not None:
                out["cap_ok"] = eng.execute_with_capability(cap)
            print(json.dumps(out))
        elif cmd == "engine_selftest":
            import io
            from contextlib import redirect_stdout
            import sovereign_engine_max as mx
            buf = io.StringIO()
            with redirect_stdout(buf):
                mx.self_test()
            print(json.dumps({"ok": True, "log_tail": buf.getvalue()[-500:]}))
        else:
            print(json.dumps({"ok": False, "error": f"unknown cmd: {cmd}"}))
    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e)}))


if __name__ == "__main__":
    main()
