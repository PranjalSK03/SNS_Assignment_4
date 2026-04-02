import json
import threading
import time
from typing import Dict, List

from event_schema import SEVERITY_LEVELS


class AlertManager(threading.Thread):
    def __init__(self, bus, cooldown_seconds: int = 30, log_path: str = "alerts.jsonl") -> None:
        super().__init__(daemon=True)
        self.bus = bus
        self.cooldown_seconds = cooldown_seconds
        self.log_path = log_path
        self.last_alert: Dict[str, float] = {}

    def run(self) -> None:
        while not self.bus.stop_event.is_set():
            try:
                det = self.bus.detections.get(timeout=0.5)
            except Exception:
                continue
            if not isinstance(det, dict):
                continue
            alert = self._build_alert(det)
            if not alert:
                continue
            key = f"{alert['rule_id']}|{json.dumps(alert.get('entity', {}), sort_keys=True)}"
            now = alert["ts"]
            if now - self.last_alert.get(key, 0) < self.cooldown_seconds:
                continue
            self.last_alert[key] = now
            self._emit(alert)

    def _build_alert(self, det: Dict) -> Dict:
        sources = set(det.get("sources", []))
        multi_step = bool(det.get("multi_step"))
        independent_sources = {s for s in sources if s in {"host", "network"}}
        severity = det.get("severity", "Low")
        if severity == "Critical" and not (multi_step or len(independent_sources) >= 2):
            severity = "High"
        if len(independent_sources) <= 1 and severity == "Critical":
            severity = "High"
        if severity not in SEVERITY_LEVELS:
            severity = "Low"
        alert = dict(det)
        alert["severity"] = severity
        alert["type"] = "alert"
        return alert

    def _emit(self, alert: Dict) -> None:
        line = json.dumps(alert, sort_keys=True)
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
        self.bus.alerts.put(alert)
        self.bus.metrics.put({"type": "alert", "alert": alert, "ts": alert["ts"]})
        print(f"ALERT {alert['severity']}: {alert['title']}")
