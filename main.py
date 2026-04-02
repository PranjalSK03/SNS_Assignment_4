import argparse
import json
import time

from alert_manager import AlertManager
from attack_simulator import AttackSimulator
from correlation_engine import CorrelationEngine
from event_bus import create_bus
from host_sensor import HostSensor
from metrics import MetricsCollector
from network_sensor import NetworkSensor


def run_experiment(scenario: str, baseline_seconds: int, seed: int) -> None:
    bus = create_bus()
    network_sensor = NetworkSensor(bus)
    host_sensor = HostSensor(bus)
    correlation = CorrelationEngine(bus)
    alerts = AlertManager(bus)
    metrics = MetricsCollector(bus)
    simulator = AttackSimulator(bus, seed=seed)

    threads = [network_sensor, host_sensor, correlation, alerts, metrics, simulator]
    for t in threads:
        t.start()

    simulator.start_baseline(baseline_seconds)
    time.sleep(baseline_seconds + 1)
    simulator.start_scenario(scenario)

    time.sleep(10)
    bus.stop_event.set()
    simulator.stop()
    time.sleep(1)

    summary = metrics.summarize()
    with open("metrics.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, sort_keys=True)
    print("Metrics:")
    print(json.dumps(summary, indent=2, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser(description="Multi-source IDS with correlation")
    parser.add_argument(
        "--scenario",
        choices=["brute_force", "port_scan", "noise_injection", "replay_attack", "sensor_failure"],
        required=True,
    )
    parser.add_argument("--baseline-seconds", type=int, default=5)
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()
    run_experiment(args.scenario, args.baseline_seconds, args.seed)


if __name__ == "__main__":
    main()
