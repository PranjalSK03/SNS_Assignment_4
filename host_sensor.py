import threading
import time
from typing import Any, Dict

from event_schema import make_event


class HostSensor(threading.Thread):
    def __init__(self, bus, sensor_id: str = "host-1", heartbeat_interval: int = 5) -> None:
        super().__init__(daemon=True)
        self.bus = bus
        self.sensor_id = sensor_id
        self.heartbeat_interval = heartbeat_interval
        self._next_heartbeat = time.time() + heartbeat_interval

    def run(self) -> None:
        while not self.bus.stop_event.is_set():
            now = time.time()
            if now >= self._next_heartbeat:
                hb = make_event(
                    source="host",
                    event_type="sensor_heartbeat",
                    meta={"sensor_id": self.sensor_id},
                )
                self.bus.normalized.put(hb)
                self._next_heartbeat = now + self.heartbeat_interval
            try:
                raw = self.bus.raw_host.get(timeout=0.5)
            except Exception:
                continue
            if not isinstance(raw, dict):
                continue
            if raw.get("control") == "pause":
                pause_for = float(raw.get("duration", 1))
                time.sleep(pause_for)
                continue
            event_type = raw.get("type", "host_event")
            event = make_event(
                source="host",
                event_type=event_type,
                ts=raw.get("ts"),
                src_ip=raw.get("src_ip"),
                user=raw.get("user"),
                process=raw.get("process"),
                outcome=raw.get("outcome"),
                meta=raw.get("meta"),
                label=raw.get("label"),
            )
            self.bus.normalized.put(event)
