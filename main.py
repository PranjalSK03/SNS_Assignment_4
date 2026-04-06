import argparse
import json
import time

from alert_manager import AlertManager
from attack_simulator import AttackSimulator
from correlation_engine import CorrelationEngine
from event_logger import EventLogger
from event_bus import create_bus
from host_sensor import HostSensor
from metrics import MetricsCollector
from network_sensor import NetworkSensor


def run_experiment(scenario: str = None, scenarios: list = None, baseline_seconds: int = 5, seed: int = 7) -> None:
    bus = create_bus()
    network_sensor = NetworkSensor(bus)
    host_sensor = HostSensor(bus)
    correlation = CorrelationEngine(bus)
    event_logger = EventLogger(bus)
    alerts = AlertManager(bus)
    metrics = MetricsCollector(bus)
    simulator = AttackSimulator(bus, seed=seed)

    threads = [network_sensor, host_sensor, correlation, event_logger, alerts, metrics, simulator]
    for t in threads:
        t.start()

    simulator.start_baseline(baseline_seconds)
    time.sleep(baseline_seconds + 1)
    
    # Support both single scenario and multiple scenarios
    if scenarios:
        scenario_list = [s.strip() for s in scenarios.split(",") if s.strip()]
        simulator.start_scenarios(scenario_list)
        # Wait longer for multiple scenarios (2s per scenario + base 10s)
        wait_time = 10 + (2 * len(scenario_list))
    else:
        simulator.start_scenario(scenario)
        wait_time = 10
    
    time.sleep(wait_time)
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
        default=None,
        help="Single attack scenario to run",
    )
    parser.add_argument(
        "--scenarios",
        type=str,
        default=None,
        help="Comma-separated list of scenarios to run (e.g., 'brute_force,port_scan,replay_attack')",
    )
    parser.add_argument("--baseline-seconds", type=int, default=5)
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()
    
    # Validate that exactly one of --scenario or --scenarios is provided
    if not args.scenario and not args.scenarios:
        parser.error("Either --scenario or --scenarios must be provided")
    if args.scenario and args.scenarios:
        parser.error("Cannot use both --scenario and --scenarios at the same time")
    
    run_experiment(scenario=args.scenario, scenarios=args.scenarios, baseline_seconds=args.baseline_seconds, seed=args.seed)


if __name__ == "__main__":
    main()
