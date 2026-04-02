import json
import time
from typing import Any, Dict, Optional

SCHEMA_VERSION = 1
SEVERITY_LEVELS = ["Info", "Low", "Medium", "High", "Critical"]


def now_ts() -> float:
    return time.time()


def make_event(
    *,
    source: str,
    event_type: str,
    ts: Optional[float] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    protocol: Optional[str] = None,
    user: Optional[str] = None,
    process: Optional[str] = None,
    outcome: Optional[str] = None,
    host: Optional[str] = None,
    subject: Optional[str] = None,
    meta: Optional[Dict[str, Any]] = None,
    label: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    event = {
        "schema_version": SCHEMA_VERSION,
        "ts": ts if ts is not None else now_ts(),
        "source": source,
        "event_type": event_type,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "user": user,
        "process": process,
        "outcome": outcome,
        "host": host,
        "subject": subject,
        "meta": meta or {},
        "label": label or {},
    }
    validate_event(event)
    return event


def validate_event(event: Dict[str, Any]) -> None:
    required = ["schema_version", "ts", "source", "event_type", "meta", "label"]
    for key in required:
        if key not in event:
            raise ValueError(f"missing required field: {key}")
    if not isinstance(event["schema_version"], int):
        raise ValueError("schema_version must be int")
    if not isinstance(event["ts"], (int, float)):
        raise ValueError("ts must be number")
    if not isinstance(event["source"], str):
        raise ValueError("source must be string")
    if not isinstance(event["event_type"], str):
        raise ValueError("event_type must be string")
    if not isinstance(event["meta"], dict):
        raise ValueError("meta must be dict")
    if not isinstance(event["label"], dict):
        raise ValueError("label must be dict")


def to_json(event: Dict[str, Any]) -> str:
    return json.dumps(event, sort_keys=True)
