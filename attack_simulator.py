import queue
import random
import threading
import time
from typing import Dict, Optional


class AttackSimulator(threading.Thread):
    def __init__(self, bus, seed: int = 7) -> None:
        super().__init__(daemon=True)
        self.bus = bus
        self.rng = random.Random(seed)
        self.command_queue: queue.Queue = queue.Queue()

    def run(self) -> None:
        while not self.bus.stop_event.is_set():
            try:
                cmd = self.command_queue.get(timeout=0.5)
            except Exception:
                continue
            if not isinstance(cmd, dict):
                continue
            action = cmd.get("action")
            if action == "baseline":
                self._baseline(cmd.get("duration", 5))
            elif action == "scenario":
                name = cmd.get("name")
                self._run_scenario(name)
            elif action == "stop":
                return

    def start_baseline(self, duration: int) -> None:
        self.command_queue.put({"action": "baseline", "duration": duration})

    def start_scenario(self, name: str) -> None:
        self.command_queue.put({"action": "scenario", "name": name})

    def stop(self) -> None:
        self.command_queue.put({"action": "stop"})

    def _emit_raw_network(self, data: Dict) -> None:
        self.bus.raw_network.put(data)

    def _emit_raw_host(self, data: Dict) -> None:
        self.bus.raw_host.put(data)

    def _emit_truth(self, attack: str, attack_id: str, phase: str) -> None:
        self.bus.metrics.put({
            "type": phase,
            "attack": attack,
            "attack_id": attack_id,
            "ts": time.time(),
        })

    def _baseline(self, duration: int) -> None:
        end = time.time() + duration
        while time.time() < end and not self.bus.stop_event.is_set():
            if self.rng.random() < 0.6:
                self._emit_raw_network(self._benign_flow())
            if self.rng.random() < 0.6:
                self._emit_raw_host(self._benign_host_event())
            time.sleep(0.2)

    def _run_scenario(self, name: Optional[str]) -> None:
        if not name:
            return
        attack_id = f"{name}-{int(time.time())}"
        self._emit_truth(name, attack_id, "attack_start")
        if name == "brute_force":
            self._scenario_bruteforce(attack_id)
        elif name == "port_scan":
            self._scenario_port_scan(attack_id)
        elif name == "noise_injection":
            self._scenario_noise_injection(attack_id)
        elif name == "replay_attack":
            self._scenario_replay_attack(attack_id)
        elif name == "sensor_failure":
            self._scenario_sensor_failure(attack_id)
        self._emit_truth(name, attack_id, "attack_end")

    def _scenario_bruteforce(self, attack_id: str) -> None:
        src_ip = "10.0.0.5"
        for _ in range(8):
            self._emit_raw_network(
                {
                    "type": "conn_attempt",
                    "src_ip": src_ip,
                    "dst_ip": "127.0.0.1",
                    "dst_port": 22,
                    "protocol": "tcp",
                    "label": {"attack": "brute_force", "attack_id": attack_id},
                }
            )
            self._emit_raw_host(
                {
                    "type": "login_fail",
                    "user": "alice",
                    "src_ip": src_ip,
                    "outcome": "fail",
                    "label": {"attack": "brute_force", "attack_id": attack_id},
                }
            )
            time.sleep(0.2)
        self._emit_raw_host(
            {
                "type": "login_success",
                "user": "alice",
                "src_ip": src_ip,
                "outcome": "success",
                "label": {"attack": "brute_force", "attack_id": attack_id},
            }
        )

    def _scenario_port_scan(self, attack_id: str) -> None:
        src_ip = "10.0.0.6"
        for port in range(20, 35):
            self._emit_raw_network(
                {
                    "type": "conn_attempt",
                    "src_ip": src_ip,
                    "dst_ip": "127.0.0.1",
                    "dst_port": port,
                    "protocol": "tcp",
                    "label": {"attack": "port_scan", "attack_id": attack_id},
                }
            )
            time.sleep(0.1)

    def _scenario_noise_injection(self, attack_id: str) -> None:
        end = time.time() + 6
        while time.time() < end:
            self._emit_raw_network(
                {
                    "type": "flow",
                    "src_ip": f"10.0.0.{self.rng.randint(10, 40)}",
                    "dst_ip": "127.0.0.1",
                    "dst_port": self.rng.randint(1000, 1010),
                    "protocol": "tcp",
                    "label": {"attack": "noise_injection", "attack_id": attack_id},
                }
            )
            self._emit_raw_host(
                {
                    "type": "process_exec",
                    "user": "bob",
                    "process": "curl",
                    "outcome": "success",
                    "label": {"attack": "noise_injection", "attack_id": attack_id},
                }
            )
            time.sleep(0.05)

    def _scenario_replay_attack(self, attack_id: str) -> None:
        src_ip = "10.0.0.7"
        sig = "abc123"
        for _ in range(5):
            self._emit_raw_network(
                {
                    "type": "flow",
                    "src_ip": src_ip,
                    "dst_ip": "127.0.0.1",
                    "dst_port": 8080,
                    "protocol": "tcp",
                    "meta": {"payload_sig": sig},
                    "label": {"attack": "replay_attack", "attack_id": attack_id},
                }
            )
            time.sleep(0.15)

    def _scenario_sensor_failure(self, attack_id: str) -> None:
        self._emit_raw_host({"control": "pause", "duration": 10, "label": {"attack": "sensor_failure", "attack_id": attack_id}})
        time.sleep(10)

    def _benign_flow(self) -> Dict:
        return {
            "type": "flow",
            "src_ip": f"10.0.0.{self.rng.randint(2, 8)}",
            "dst_ip": "127.0.0.1",
            "dst_port": self.rng.choice([80, 443, 8080]),
            "protocol": "tcp",
        }

    def _benign_host_event(self) -> Dict:
        if self.rng.random() < 0.7:
            return {
                "type": "login_success",
                "user": self.rng.choice(["alice", "bob", "charlie"]),
                "src_ip": f"10.0.0.{self.rng.randint(2, 8)}",
                "outcome": "success",
            }
        return {
            "type": "process_exec",
            "user": self.rng.choice(["alice", "bob", "charlie"]),
            "process": "bash",
            "outcome": "success",
        }
