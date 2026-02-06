import os

"""
Kernel Gate: The Core Orchestrator (Telemetry Enabled)
"""
from .integrity import GeometricIntegrityCalculator, BidirectionalFeedbackLoop
from .signals import SignalTracker, QIFTProcessor, HyperGraphAnalyzer
from .merkle_moat import AuditLogger
from .policy import MoEHorizonFusion, ThermodynamicProtocol
from .persona import persona_for
from apps.api.rtp.agent_state import update_state
from apps.api.rtp.geometry import geometry_score, geometry_threshold_for, geometry_penalty
from apps.api.rtp.tickets import mint_ticket

class KernelGate:
    def __init__(self):
        self.integrity_calc = GeometricIntegrityCalculator()
        self.feedback_loop = BidirectionalFeedbackLoop()
        self.qift = QIFTProcessor()
        self.topology = HyperGraphAnalyzer()
        self.audit = AuditLogger()
        self.moe = MoEHorizonFusion()
        self.thermo = ThermodynamicProtocol()
        self.signal_tracker = SignalTracker()

    def decide(self, payload: dict) -> dict:
        triggered_moats = []
        tool_name = payload.get("tool_name", "unknown")
        agent_id = payload.get("agent_id", "anonymous")
        persona = persona_for(agent_id)
        raw_signals = payload.get("signals", {})
        
        # Moat 3
        transformed_signals = self.qift.transform(raw_signals)
        triggered_moats.append(3)
        
        # Moat 13
        is_botnet = self.topology.log_interaction(agent_id, tool_name)
        if is_botnet:
            triggered_moats.append(13)
        
        # Moat 2
        integrity_score = self.integrity_calc.calculate(transformed_signals)
        triggered_moats.append(2)
        
        # Moat 6
        prediction_confidence = self.moe.predict(transformed_signals)
        triggered_moats.append(6)
        
        # Moat 11
        current_load = 0.6 
        pre_defense_state = self.thermo.get_defense_state()
        self.thermo.update_entropy(current_load, 1.0 - integrity_score)
        post_defense_state = self.thermo.get_defense_state()
        triggered_moats.append(11)
        
        # Moat 1
        # --- F: constraint geometry gating ---
        geom_score = geometry_score(tool_name, raw_signals)
        geom_thr = geometry_threshold_for(tool_name)
        geom_pen = geometry_penalty(geom_score, geom_thr)

        # --- F1: HARD GEOMETRY GATE (no read.me bypass) ---
        geometry_blocked = bool(geom_score < geom_thr)
        if geometry_blocked:
            allow = False
            reason = f"GEOMETRY_BLOCK: score {geom_score:.3f} < thr {geom_thr:.3f}"
            decision_kind = "DECIDE_DENY_GEOMETRY"

        threshold = self.feedback_loop.get_threshold()
        threshold = min(0.99, max(0.0, threshold + geom_pen))
        threshold = max(0.0, min(1.0, threshold - float(persona.integrity_bias)))
        triggered_moats.append(1)
        
        if pre_defense_state == "LOCKDOWN":
            threshold += 0.2

        # Demo-stability: keep read.me testable even during LOCKDOWN
        if tool_name == "read.me":
            threshold = min(threshold, float(persona.lockdown_cap))

        allow = False
        reason = ""
        decision_kind = None

        # Persona floor
        prediction_confidence = max(prediction_confidence, float(persona.confidence_floor))

        if is_botnet:
            allow = False
            reason = "Moat 13: Suspicious topology pattern detected"
            decision_kind = "DECIDE_DENY_BOTNET"
        # Moat F1: geometry hard deny (must not be overwritten)
        elif geom_score < geom_thr:
            allow = False
            reason = f"GEOMETRY_BLOCK: score {geom_score:.3f} < thr {geom_thr:.3f}"
            decision_kind = "DECIDE_DENY_GEOMETRY"
        elif (integrity_score >= threshold or (tool_name == "read.me" and prediction_confidence > 0.9)) and prediction_confidence > 0.5:
            allow = True
            decision_kind = "DECIDE_ALLOW"
            reason = f"Integrity {integrity_score:.2f} > Threshold {threshold:.2f}"
        else:
            allow = False
            decision_kind = "DECIDE_DENY_INTEGRITY"
            reason = f"Integrity {integrity_score:.2f} < Threshold {threshold:.2f}"

        decision_str = "ALLOW" if allow else "DENY"
        if decision_kind is None:
            decision_kind = "DECIDE_ALLOW" if allow else "DECIDE_DENY"
        self.feedback_loop.update(integrity_score, decision_str)

        # Moat 5 & 7
        audit_entry = self.audit.log(agent_id, tool_name, decision_str, integrity_score)
        triggered_moats.extend([5, 7])

        # --- E: per-agent stateful risk (EMA brittleness) ---
        agent_state_error = None
        try:
            _aid = str(agent_id or "unknown")
            _sig = raw_signals if isinstance(raw_signals, dict) else {}

            _n = _sig.get("normality", _sig.get("normality_score", _sig.get("normalityScore", 1.0)))
            try:
                _n = float(_n)
            except Exception:
                _n = 1.0

            if _n < 0.0:
                _n = 0.0
            if _n > 1.0:
                _n = 1.0

            _b = 1.0 - _n
            if _b < 0.0:
                _b = 0.0
            if _b > 1.0:
                _b = 1.0

            agent_state = update_state(_aid, _b)

            # --- G: state-bound execution (EMA tightening) ---
            try:
                _ema = float((agent_state or {}).get("ema", 0.0))
            except Exception:
                _ema = 0.0

            # --- H: TTL tightening (state-bound tickets) ---
            base_ttl = 60
            ttl_factor = 1.0
            if _ema >= 0.90:
                ttl_factor = 0.10
            elif _ema >= 0.80:
                ttl_factor = 0.20
            elif _ema >= 0.60:
                ttl_factor = 0.50
            ttl_seconds = max(1, int(base_ttl * ttl_factor))

            # Raise threshold as EMA rises (soft)
            if _ema >= 0.60:
                threshold = min(0.99, threshold + 0.10)
            if _ema >= 0.80:
                threshold = min(0.99, threshold + 0.20)

            # Hard-stop for high-risk tools only (keep read.me demo-safe)
            if _ema >= 0.90 and tool_name not in ("read.me",):
                allow = False
                reason = "E+++++: EMA extreme -> deny (state-bound execution)"
                decision_kind = "DECIDE_DENY_EMA"

            # reason refresh after EMA tightening (keep logs coherent)
            if allow:
                reason = f"Integrity {integrity_score:.2f} > Threshold {threshold:.2f}"
            else:
                # if we denied for EMA, keep that message; otherwise keep integrity-vs-threshold
                if ("EMA extreme" not in (reason or "")) and ("GEOMETRY_BLOCK" not in (reason or "")) and ("Moat 13" not in (reason or "")):
                    reason = f"Integrity {integrity_score:.2f} < Threshold {threshold:.2f}"
    
    
        except Exception as e:
            agent_state = None
            agent_state_error = repr(e)





        
        # --- H4: mint TTL-bound ticket ---
        ticket = mint_ticket(tool_name, payload.get("args", {}), ttl_seconds=ttl_seconds, agent_id=str(agent_id or "anonymous"), ema=float(_ema), geom=float(geom_score))

        return {
            "decision": decision_str,
            "decision_kind": decision_kind,
            "reason": reason,
            "integrity_score": round(integrity_score, 4),
            "threshold": round(threshold, 4),
            "ttl_seconds": ttl_seconds,
            "ttl_factor": ttl_factor,
            "ticket": ticket,
            "pre_defense_state": pre_defense_state,
            "geometry_score": geom_score,
            "geometry_threshold": geom_thr,
            "geometry_penalty": geom_pen,
            "agent_state_error": agent_state_error,
            "agent_state": agent_state,
            "defense_state": post_defense_state,
            "audit_signature": audit_entry["signature"],
            "merkle_root": audit_entry["current_root"][:16] + "...",
            "moats_triggered": sorted(list(set(triggered_moats)))
        }


# --- consume wiring (locked for good) ---

def consume(self, payload: dict) -> dict:
    from apps.api.rtp.tickets import consume_ticket
    ticket = payload.get("ticket") or payload.get("ticket_dict") or payload.get("ticket_obj") or payload.get("ticket") or {}
    if not isinstance(ticket, dict):
        return {"ok": False, "reason": "bad ticket type"}

    tool = payload.get("tool") or ticket.get("tool_name") or ""
    usage = payload.get("usage") or {}
    agent = usage.get("agent_id") or payload.get("agent_id")

    if agent is not None:
        ticket = dict(ticket)
        ticket["provided_agent_id"] = agent

    ok, reason = consume_ticket(ticket, tool)
    return {"ok": bool(ok), "reason": str(reason), "jti": str(ticket.get("jti",""))}


try:
    KernelGate.consume = consume
except Exception:
    pass
