import threading
import time
from collections import deque
from typing import Any, Dict, List, Optional

from anomaly_detector import AnomalyDetector


class CorrelationEngine(threading.Thread):
    def __init__(self, bus, window_seconds: int = 60, slow_window_seconds: int = 120) -> None:
        super().__init__(daemon=True)
        self.bus = bus
        self.window_seconds = window_seconds
        self.slow_window_seconds = slow_window_seconds
        self.max_window = max(window_seconds, slow_window_seconds)
        self.window = deque()
        self.anomaly = AnomalyDetector()

    def run(self) -> None:
        while not self.bus.stop_event.is_set():
            try:
                event = self.bus.normalized.get(timeout=0.5)
            except Exception:
                continue
            if not isinstance(event, dict):
                continue
            now = event.get("ts", time.time())
            self.window.append(event)
            self._prune_window(now)
            detections = self._evaluate_rules(now)
            for det in detections:
                self.bus.detections.put(det)

    def _prune_window(self, now: float) -> None:
        while self.window and now - self.window[0].get("ts", now) > self.max_window:
            self.window.popleft()

    def _events_in_window(self, now: float, seconds: int) -> List[Dict[str, Any]]:
        return [e for e in self.window if now - e.get("ts", now) <= seconds]

    def _extract_attack_id(self, events: List[Dict[str, Any]]) -> Optional[str]:
        for e in events:
            label = e.get("label", {})
            if label.get("attack_id"):
                return label["attack_id"]
        return None

    def _evaluate_rules(self, now: float) -> List[Dict[str, Any]]:
        detections: List[Dict[str, Any]] = []
        fast_window = self._events_in_window(now, self.window_seconds)
        slow_window = self._events_in_window(now, self.slow_window_seconds)

        detections.extend(self._rule_bruteforce(fast_window, now))
        detections.extend(self._rule_port_scan(fast_window, now))
        detections.extend(self._rule_slow_scan(slow_window, now))
        detections.extend(self._rule_replay_attack(fast_window, now))
        detections.extend(self._rule_process_after_fail(fast_window, now))
        detections.extend(self._rule_sensor_failure(fast_window, now))
        detections.extend(self._anomaly_rules(fast_window, now))
        return detections

    def _rule_bruteforce(self, events: List[Dict[str, Any]], now: float) -> List[Dict[str, Any]]:
        detections = []
        fails = [e for e in events if e["event_type"] == "login_fail" and e["source"] == "host"]
        by_user_ip: Dict[str, List[Dict[str, Any]]] = {}
        for e in fails:
            key = f"{e.get('user')}|{e.get('src_ip')}"
            by_user_ip.setdefault(key, []).append(e)
        for key, items in by_user_ip.items():
            if len(items) >= 5:
                user, src_ip = key.split("|", 1)
                net_hits = [
                    e
                    for e in events
                    if e["source"] == "network" and e.get("src_ip") == src_ip and e.get("dst_port") == 22
                ]
                sources = {"host"}
                if net_hits:
                    sources.add("network")
                detections.append(
                    {
                        "rule_id": "bruteforce",
                        "title": "Brute-force login attempts",
                        "ts": now,
                        "severity": "High",
                        "sources": list(sources),
                        "entity": {"user": user, "src_ip": src_ip},
                        "details": {"failures": len(items), "window": self.window_seconds},
                        "multi_step": False,
                        "attack_id": self._extract_attack_id(items + net_hits),
                    }
                )
        return detections

    def _rule_port_scan(self, events: List[Dict[str, Any]], now: float) -> List[Dict[str, Any]]:
        detections = []
        flows = [e for e in events if e["source"] == "network" and e.get("dst_port") is not None]
        by_src: Dict[str, List[Dict[str, Any]]] = {}
        for e in flows:
            by_src.setdefault(e.get("src_ip") or "unknown", []).append(e)
        for src_ip, items in by_src.items():
            ports = {e.get("dst_port") for e in items}
            if len(ports) >= 10:
                detections.append(
                    {
                        "rule_id": "port_scan",
                        "title": "Port scan detected",
                        "ts": now,
                        "severity": "High",
                        "sources": ["network"],
                        "entity": {"src_ip": src_ip},
                        "details": {"unique_ports": len(ports), "window": self.window_seconds},
                        "multi_step": False,
                        "attack_id": self._extract_attack_id(items),
                    }
                )
        return detections

    def _rule_slow_scan(self, events: List[Dict[str, Any]], now: float) -> List[Dict[str, Any]]:
        detections = []
        flows = [e for e in events if e["source"] == "network" and e.get("dst_port") is not None]
        by_src: Dict[str, List[Dict[str, Any]]] = {}
        for e in flows:
            by_src.setdefault(e.get("src_ip") or "unknown", []).append(e)
        for src_ip, items in by_src.items():
            ports = {e.get("dst_port") for e in items}
            if 5 <= len(ports) < 10:
                detections.append(
                    {
                        "rule_id": "slow_scan",
                        "title": "Slow scan pattern",
                        "ts": now,
                        "severity": "Medium",
                        "sources": ["network"],
                        "entity": {"src_ip": src_ip},
                        "details": {"unique_ports": len(ports), "window": self.slow_window_seconds},
                        "multi_step": False,
                        "attack_id": self._extract_attack_id(items),
                    }
                )
        return detections

    def _rule_replay_attack(self, events: List[Dict[str, Any]], now: float) -> List[Dict[str, Any]]:
        detections = []
        flows = [e for e in events if e["source"] == "network"]
        by_sig: Dict[str, List[Dict[str, Any]]] = {}
        for e in flows:
            sig = (e.get("meta") or {}).get("payload_sig")
            if not sig:
                continue
            key = f"{e.get('src_ip')}|{e.get('dst_port')}|{sig}"
            by_sig.setdefault(key, []).append(e)
        for key, items in by_sig.items():
            if len(items) >= 3:
                src_ip, dst_port, sig = key.split("|", 2)
                detections.append(
                    {
                        "rule_id": "replay_attack",
                        "title": "Replay-like repeated payloads",
                        "ts": now,
                        "severity": "Medium",
                        "sources": ["network"],
                        "entity": {"src_ip": src_ip, "dst_port": dst_port},
                        "details": {"repeats": len(items), "payload_sig": sig},
                        "multi_step": False,
                        "attack_id": self._extract_attack_id(items),
                    }
                )
        return detections

    def _rule_process_after_fail(self, events: List[Dict[str, Any]], now: float) -> List[Dict[str, Any]]:
        detections = []
        fails = [e for e in events if e["event_type"] == "login_fail" and e["source"] == "host"]
        execs = [e for e in events if e["event_type"] == "process_exec" and e["source"] == "host"]
        risky = [e for e in execs if (e.get("process") or "") in {"nc", "nmap", "sudo", "python"}]
        if len(fails) >= 3 and risky:
            detections.append(
                {
                    "rule_id": "post_fail_exec",
                    "title": "Suspicious process after failed logins",
                    "ts": now,
                    "severity": "Critical",
                    "sources": ["host"],
                    "entity": {"user": risky[-1].get("user")},
                    "details": {"failures": len(fails), "processes": [e.get("process") for e in risky]},
                    "multi_step": True,
                    "attack_id": self._extract_attack_id(fails + risky),
                }
            )
        return detections

    def _rule_sensor_failure(self, events: List[Dict[str, Any]], now: float) -> List[Dict[str, Any]]:
        detections = []
        host_hb = [e for e in events if e["event_type"] == "sensor_heartbeat" and e["source"] == "host"]
        if host_hb:
            last_hb = max([e.get("ts", now) for e in host_hb])
            time_since_hb = now - last_hb
            if time_since_hb > 8:
                detections.append(
                    {
                        "rule_id": "sensor_failure",
                        "title": "Host sensor heartbeat missing (>8s gap)",
                        "ts": now,
                        "severity": "High",
                        "sources": ["system"],
                        "entity": {"sensor": "host"},
                        "details": {"gap_seconds": round(time_since_hb, 2)},
                        "multi_step": False,
                        "attack_id": None,
                    }
                )
        return detections

    def _anomaly_rules(self, events: List[Dict[str, Any]], now: float) -> List[Dict[str, Any]]:
        detections = []
        login_fails = [e for e in events if e["event_type"] == "login_fail" and e["source"] == "host"]
        by_user = {}
        for e in login_fails:
            by_user.setdefault(e.get("user") or "unknown", []).append(e)
        for user, items in by_user.items():
            z = self.anomaly.update(f"fails:{user}", len(items))
            if z > 3.0 and len(items) >= 4:
                detections.append(
                    {
                        "rule_id": "anomaly_login_fail_rate",
                        "title": "Anomalous failed login rate",
                        "ts": now,
                        "severity": "Medium",
                        "sources": ["host"],
                        "entity": {"user": user},
                        "details": {"zscore": round(z, 2), "count": len(items)},
                        "multi_step": False,
                        "attack_id": self._extract_attack_id(items),
                    }
                )
        flows = [e for e in events if e["source"] == "network" and e.get("dst_port") is not None]
        by_src = {}
        for e in flows:
            by_src.setdefault(e.get("src_ip") or "unknown", []).append(e)
        for src_ip, items in by_src.items():
            z = self.anomaly.update(f"ports:{src_ip}", len({e.get('dst_port') for e in items}))
            if z > 3.0 and len(items) >= 6:
                detections.append(
                    {
                        "rule_id": "anomaly_port_access_rate",
                        "title": "Anomalous port access rate",
                        "ts": now,
                        "severity": "Medium",
                        "sources": ["network"],
                        "entity": {"src_ip": src_ip},
                        "details": {"zscore": round(z, 2), "flows": len(items)},
                        "multi_step": False,
                        "attack_id": self._extract_attack_id(items),
                    }
                )
        return detections
