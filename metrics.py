import threading
import time
from typing import Dict, List, Optional
import resource


class MetricsCollector(threading.Thread):
    def __init__(self, bus) -> None:
        super().__init__(daemon=True)
        self.bus = bus
        self.attacks: Dict[str, Dict] = {}
        self.alerts: List[Dict] = []
        self.latencies: List[float] = []

    def run(self) -> None:
        while not self.bus.stop_event.is_set():
            try:
                msg = self.bus.metrics.get(timeout=0.5)
            except Exception:
                continue
            if not isinstance(msg, dict):
                continue
            mtype = msg.get("type")
            if mtype == "attack_start":
                self.attacks[msg["attack_id"]] = {
                    "attack": msg.get("attack"),
                    "start": msg.get("ts"),
                    "end": None,
                }
            elif mtype == "attack_end":
                attack = self.attacks.get(msg.get("attack_id"))
                if attack:
                    attack["end"] = msg.get("ts")
            elif mtype == "alert":
                alert = msg.get("alert", {})
                self.alerts.append(alert)
                attack_id = alert.get("attack_id")
                attack = self.attacks.get(attack_id)
                if attack and attack.get("start") is not None:
                    self.latencies.append(alert.get("ts", time.time()) - attack["start"])

    def summarize(self) -> Dict:
        tp = 0
        fp = 0
        fn = 0
        matched_attacks = set()
        for alert in self.alerts:
            attack_id = alert.get("attack_id")
            if attack_id and attack_id in self.attacks:
                tp += 1
                matched_attacks.add(attack_id)
            else:
                fp += 1
        for attack_id in self.attacks:
            if attack_id not in matched_attacks:
                fn += 1
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        avg_latency = sum(self.latencies) / len(self.latencies) if self.latencies else 0.0
        usage = resource.getrusage(resource.RUSAGE_SELF)
        return {
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1": round(f1, 3),
            "false_positive_rate": round(fp / max(1, len(self.alerts)), 3),
            "false_negative_rate": round(fn / max(1, len(self.attacks)), 3),
            "alert_latency_avg_seconds": round(avg_latency, 3),
            "cpu_user_seconds": round(usage.ru_utime, 3),
            "cpu_system_seconds": round(usage.ru_stime, 3),
            "memory_max_rss_kb": usage.ru_maxrss,
            "alerts": len(self.alerts),
            "attacks": len(self.attacks),
        }
