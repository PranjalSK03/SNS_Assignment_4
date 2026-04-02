import math
from typing import Dict, Tuple


class AnomalyDetector:
    def __init__(self, alpha: float = 0.2, min_samples: int = 5) -> None:
        self.alpha = alpha
        self.min_samples = min_samples
        self.state: Dict[str, Tuple[int, float, float]] = {}

    def update(self, key: str, value: float) -> float:
        count, mean, var = self.state.get(key, (0, 0.0, 0.0))
        count += 1
        if count == 1:
            mean = value
            var = 0.0
        else:
            delta = value - mean
            mean += self.alpha * delta
            var = (1 - self.alpha) * (var + self.alpha * delta * delta)
        self.state[key] = (count, mean, var)
        if count < self.min_samples:
            return 0.0
        std = math.sqrt(var) if var > 0 else 0.0
        return (value - mean) / (std + 1e-6)
