"""
E3 Telemetry - Performance Metrics Tracking
"""

import time
from typing import Dict, List
from collections import defaultdict


class TelemetryTracker:
    """Track detection performance metrics"""
    
    def __init__(self):
        self.reset()
    
    def reset(self):
        self.total_detections = 0
        self.total_latency_ms = 0.0
        self.detections_by_type = defaultdict(int)
        self.latency_by_type = defaultdict(list)
        self.moat_triggers = defaultdict(int)
        self.start_time = time.time()
    
    def record(self, detection_type: str, latency_ms: float):
        """Record a detection event"""
        self.total_detections += 1
        self.total_latency_ms += latency_ms
        self.detections_by_type[detection_type] += 1
        
        self.latency_by_type[detection_type].append(latency_ms)
        if len(self.latency_by_type[detection_type]) > 1000:
            self.latency_by_type[detection_type].pop(0)
    
    def record_moat_trigger(self, moat_name: str):
        """Record a moat trigger event"""
        self.moat_triggers[moat_name] += 1
    
    def _percentile(self, arr: List[float], p: int) -> float:
        if not arr:
            return 0.0
        sorted_arr = sorted(arr)
        idx = int(len(sorted_arr) * p / 100)
        return sorted_arr[min(idx, len(sorted_arr) - 1)]
    
    def get_stats(self) -> Dict:
        """Get telemetry statistics"""
        uptime = time.time() - self.start_time
        avg_latency = self.total_latency_ms / max(self.total_detections, 1)
        
        latency_stats = {}
        for det_type, latencies in self.latency_by_type.items():
            if latencies:
                latency_stats[det_type] = {
                    'count': len(latencies),
                    'p50': self._percentile(latencies, 50),
                    'p95': self._percentile(latencies, 95),
                    'p99': self._percentile(latencies, 99),
                    'min': min(latencies),
                    'max': max(latencies)
                }
        
        return {
            'uptime_seconds': uptime,
            'total_detections': self.total_detections,
            'avg_latency_ms': avg_latency,
            'detections_by_type': dict(self.detections_by_type),
            'moat_triggers': dict(self.moat_triggers),
            'latency_by_type': latency_stats
        }


# Global telemetry tracker
_tracker = TelemetryTracker()


def get_telemetry() -> Dict:
    """Get current telemetry stats"""
    return _tracker.get_stats()


def reset_telemetry():
    """Reset telemetry counters"""
    _tracker.reset()


def record_telemetry(detection_type: str, latency_ms: float):
    """Record a detection event"""
    _tracker.record(detection_type, latency_ms)


__all__ = ['get_telemetry', 'reset_telemetry', 'record_telemetry', 'TelemetryTracker']
