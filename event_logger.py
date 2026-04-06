import json
import threading
from typing import Dict


class EventLogger(threading.Thread):
    def __init__(self, bus, log_path: str = "events.jsonl") -> None:
        super().__init__(daemon=True)
        self.bus = bus
        self.log_path = log_path

    def run(self) -> None:
        while not self.bus.stop_event.is_set():
            try:
                event = self.bus.normalized_log.get(timeout=0.5)
            except Exception:
                continue
            if not isinstance(event, dict):
                continue
            line = json.dumps(event, sort_keys=True)
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
