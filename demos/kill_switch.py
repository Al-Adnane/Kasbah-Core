#!/usr/bin/env python3
"""
Kasbah kill-switch — the one product feature unique to the consumer market.
If the VPN drops, tool calls queue. They drain only when the tunnel returns.
Every decision is receipted. Chain is tamper-evident.
"""
import asyncio, hashlib, json, time, uuid
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional


@dataclass
class ToolCall:
    tool: str
    args: Dict[str, Any]


@dataclass
class Receipt:
    receipt_id: str
    timestamp_ns: int
    decision: str
    tool: str
    args_hash: str
    prev_hash: str
    hash: str


class KillSwitch:
    def __init__(self, vpn_is_up: Callable[[], bool]):
        self.vpn_is_up = vpn_is_up
        self.queue: List[ToolCall] = []
        self.receipts: List[Receipt] = []
        self.prev_hash = "0" * 64
        self.executor: Optional[Callable[[ToolCall], Any]] = None

    def _receipt(self, decision: str, call: ToolCall) -> Receipt:
        ts = time.time_ns()
        ah = hashlib.sha3_256(json.dumps(call.args, sort_keys=True).encode()).hexdigest()
        payload = f"{ts}|{decision}|{call.tool}|{ah}|{self.prev_hash}"
        h = hashlib.sha3_256(payload.encode()).hexdigest()
        r = Receipt(str(uuid.uuid4()), ts, decision, call.tool, ah, self.prev_hash, h)
        self.receipts.append(r)
        self.prev_hash = h
        return r

    def verify_chain(self) -> bool:
        prev = "0" * 64
        for r in self.receipts:
            payload = f"{r.timestamp_ns}|{r.decision}|{r.tool}|{r.args_hash}|{r.prev_hash}"
            if r.prev_hash != prev:
                return False
            if hashlib.sha3_256(payload.encode()).hexdigest() != r.hash:
                return False
            prev = r.hash
        return True

    async def call(self, c: ToolCall) -> Dict[str, Any]:
        if not self.vpn_is_up():
            self.queue.append(c)
            return {
                "status": "queued",
                "depth": len(self.queue),
                "receipt": self._receipt("queued_vpn_down", c).receipt_id,
            }
        result = self.executor(c) if self.executor else None
        return {
            "status": "executed",
            "result": result,
            "receipt": self._receipt("executed", c).receipt_id,
        }

    async def drain(self) -> List[Dict[str, Any]]:
        if not self.vpn_is_up():
            return []
        out = []
        while self.queue:
            c = self.queue.pop(0)
            result = self.executor(c) if self.executor else None
            self._receipt("executed_after_recovery", c)
            out.append({"tool": c.tool, "result": result})
        return out


# ─── Demo ─────────────────────────────────────────────────────────────────────

class VPN:
    def __init__(self):
        self.up = True

    def is_up(self) -> bool:
        return self.up


async def main():
    vpn = VPN()
    ks = KillSwitch(vpn.is_up)
    ks.executor = lambda c: f"ok:{c.tool}"

    print("VPN up:")
    for t in ["read_file", "http_get", "send_payment"]:
        r = await ks.call(ToolCall(t, {"i": t}))
        print(f"  {t:<15} -> {r['status']}")

    print("\nVPN down:")
    vpn.up = False
    for t in ["read_file", "http_get", "send_payment"]:
        r = await ks.call(ToolCall(t, {"i": t}))
        print(f"  {t:<15} -> {r['status']} (depth={r['depth']})")
    print(f"\nQueue depth: {len(ks.queue)}  Chain valid: {ks.verify_chain()}")

    print("\nVPN back up:")
    vpn.up = True
    for d in await ks.drain():
        print(f"  {d['tool']:<15} -> drained")
    print(f"Chain valid: {ks.verify_chain()}  Receipts: {len(ks.receipts)}")


if __name__ == "__main__":
    asyncio.run(main())
