from dataclasses import dataclass
from queue import Queue
import threading


@dataclass
class EventBus:
    raw_network: Queue
    raw_host: Queue
    normalized: Queue
    normalized_log: Queue
    detections: Queue
    alerts: Queue
    metrics: Queue
    stop_event: threading.Event


def create_bus() -> EventBus:
    return EventBus(
        raw_network=Queue(),
        raw_host=Queue(),
        normalized=Queue(),
        normalized_log=Queue(),
        detections=Queue(),
        alerts=Queue(),
        metrics=Queue(),
        stop_event=threading.Event(),
    )
