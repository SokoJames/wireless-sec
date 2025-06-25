"""
statistics_engine.py

Calculates real-time statistics and traffic metrics for network flows.
Supports rolling statistics, time windows, and summary statistics for security monitoring and anomaly detection.
Designed for modular use in the Wi-Fi Traffic Analyzer; emphasizes clarity and performance.
"""

import logging
from typing import List, Dict, Any, Optional
import numpy as np
import pandas as pd
import time

DEFAULT_CONFIG = {
    "window_size": 60,  # seconds for rolling stats
    "metrics": ["packet_count", "byte_count", "avg_packet_size", "max_packet_size", "min_packet_size", "flow_duration"]
}

class StatisticsEngine:
    """
    Computes real-time and summary statistics for network flows.
    Supports rolling windows, entropy, burstiness, protocol breakdown, anomaly detection, and efficient updates.
    """
    def __init__(self, config: Optional[Dict[str, Any]] = None, logger: Optional[logging.Logger] = None):
        self.config = DEFAULT_CONFIG.copy()
        if config:
            self.config.update(config)
        self.logger = logger or logging.getLogger("StatisticsEngine")
        self.window_size = self.config["window_size"]
        self.metrics = self.config["metrics"]
        self.flow_data: Dict[str, List[Dict[str, Any]]] = {}  # flow_id -> list of packet dicts
        self.protocol_counts: Dict[str, Dict[str, int]] = {}  # flow_id -> protocol:count
        self.anomaly_threshold = self.config.get("anomaly_threshold", 3.0)  # z-score threshold

    def add_packet(self, flow_id: str, packet_info: Dict[str, Any]) -> None:
        """
        Add a packet to the statistics engine for the given flow.
        packet_info: dict with keys like 'timestamp', 'size', 'protocol', etc.
        """
        if flow_id not in self.flow_data:
            self.flow_data[flow_id] = []
            self.protocol_counts[flow_id] = {}
        self.flow_data[flow_id].append(packet_info)
        proto = packet_info.get('protocol', 'UNKNOWN')
        self.protocol_counts[flow_id][proto] = self.protocol_counts[flow_id].get(proto, 0) + 1
        # Remove old packets outside the rolling window
        now = packet_info.get('timestamp', time.time())
        self.flow_data[flow_id] = [p for p in self.flow_data[flow_id] if now - p['timestamp'] <= self.window_size]

    def compute_stats(self, flow_id: str) -> Dict[str, Any]:
        """
        Compute statistics for the given flow over the rolling window.
        Returns a dict with metrics as keys, including advanced metrics.
        """
        packets = self.flow_data.get(flow_id, [])
        if not packets:
            return {k: 0 for k in self.metrics}
        sizes = [p['size'] for p in packets]
        timestamps = [p['timestamp'] for p in packets]
        protocols = [p.get('protocol', 'UNKNOWN') for p in packets]
        stats = {
            "packet_count": len(packets),
            "byte_count": int(np.sum(sizes)),
            "avg_packet_size": float(np.mean(sizes)),
            "max_packet_size": int(np.max(sizes)),
            "min_packet_size": int(np.min(sizes)),
            "flow_duration": float(max(timestamps) - min(timestamps)) if len(timestamps) > 1 else 0.0,
            "entropy": self._calc_entropy(sizes),
            "burstiness": self._calc_burstiness(timestamps),
            "protocol_breakdown": dict(pd.Series(protocols).value_counts()),
        }
        # Anomaly detection (z-score on packet size)
        stats["anomaly"] = self._detect_anomaly(sizes)
        # Only return requested metrics plus extras
        all_keys = set(self.metrics) | {"entropy", "burstiness", "protocol_breakdown", "anomaly"}
        return {k: stats[k] for k in all_keys if k in stats}

    def _calc_entropy(self, arr: list) -> float:
        """
        Calculate entropy of the size distribution.
        """
        if not arr or len(arr) == 1:
            return 0.0
        values, counts = np.unique(arr, return_counts=True)
        probs = counts / counts.sum()
        entropy = -np.sum(probs * np.log2(probs))
        return float(entropy)

    def _calc_burstiness(self, timestamps: list) -> float:
        """
        Calculate burstiness as stddev/mean of inter-arrival times.
        """
        if len(timestamps) < 2:
            return 0.0
        iats = np.diff(sorted(timestamps))
        mean = np.mean(iats)
        std = np.std(iats)
        return float(std / mean) if mean > 0 else 0.0

    def _detect_anomaly(self, arr: list) -> bool:
        """
        Simple anomaly detection using z-score threshold on packet sizes.
        """
        if len(arr) < 2:
            return False
        z = np.abs((arr[-1] - np.mean(arr[:-1])) / (np.std(arr[:-1]) + 1e-9))
        if z > self.anomaly_threshold:
            self.logger.warning(f"Anomaly detected: z-score {z:.2f} exceeds threshold {self.anomaly_threshold}")
            return True
        return False

    def get_all_flow_stats(self) -> Dict[str, Dict[str, Any]]:
        """
        Return statistics for all active flows.
        """
        return {fid: self.compute_stats(fid) for fid in self.flow_data}

    def export_stats_csv(self, path: str) -> None:
        """
        Export all flow stats to a CSV file.
        """
        import pandas as pd
        df = pd.DataFrame.from_dict(self.get_all_flow_stats(), orient='index')
        df.to_csv(path)
        self.logger.info(f"Exported flow stats to {path}")

    def export_stats_json(self, path: str) -> None:
        """
        Export all flow stats to a JSON file.
        """
        import json
        with open(path, 'w') as f:
            json.dump(self.get_all_flow_stats(), f, indent=2)
        self.logger.info(f"Exported flow stats to {path}")

    def plot_flow_metric(self, flow_id: str, metric: str) -> None:
        """
        Plot a time series of a metric for a given flow (requires matplotlib).
        """
        try:
            import matplotlib.pyplot as plt
        except ImportError:
            self.logger.error("matplotlib is not installed.")
            return
        packets = self.flow_data.get(flow_id, [])
        if not packets:
            self.logger.warning(f"No data for flow {flow_id}")
            return
        times = [p['timestamp'] for p in packets]
        values = [p.get(metric, 0) if metric != 'timestamp' else p['timestamp'] for p in packets]
        plt.figure(figsize=(8, 3))
        plt.plot(times, values, marker='o')
        plt.title(f"{metric} over time for {flow_id}")
        plt.xlabel("Timestamp")
        plt.ylabel(metric)
        plt.tight_layout()
        plt.show()

    def reset(self) -> None:
        """
        Clear all flow data (for testing or reset).
        """
        self.flow_data.clear()
        self.protocol_counts.clear()

    def add_packet(self, flow_id: str, packet_info: Dict[str, Any]) -> None:
        """
        Add a packet to the statistics engine for the given flow.
        packet_info: dict with keys like 'timestamp', 'size', etc.
        """
        if flow_id not in self.flow_data:
            self.flow_data[flow_id] = []
        self.flow_data[flow_id].append(packet_info)
        # Remove old packets outside the rolling window
        now = packet_info.get('timestamp', time.time())
        self.flow_data[flow_id] = [p for p in self.flow_data[flow_id] if now - p['timestamp'] <= self.window_size]

    def compute_stats(self, flow_id: str) -> Dict[str, Any]:
        """
        Compute statistics for the given flow over the rolling window.
        Returns a dict with metrics as keys.
        """
        packets = self.flow_data.get(flow_id, [])
        if not packets:
            return {k: 0 for k in self.metrics}
        sizes = [p['size'] for p in packets]
        timestamps = [p['timestamp'] for p in packets]
        stats = {
            "packet_count": len(packets),
            "byte_count": int(np.sum(sizes)),
            "avg_packet_size": float(np.mean(sizes)),
            "max_packet_size": int(np.max(sizes)),
            "min_packet_size": int(np.min(sizes)),
            "flow_duration": float(max(timestamps) - min(timestamps)) if len(timestamps) > 1 else 0.0
        }
        return {k: stats[k] for k in self.metrics if k in stats}

    def get_all_flow_stats(self) -> Dict[str, Dict[str, Any]]:
        """
        Return statistics for all active flows.
        """
        return {fid: self.compute_stats(fid) for fid in self.flow_data}

    def reset(self) -> None:
        """
        Clear all flow data (for testing or reset).
        """
        self.flow_data.clear()

if __name__ == "__main__":
    import random
    logging.basicConfig(level=logging.INFO)
    se = StatisticsEngine()
    # Simulate packets for two flows
    now = time.time()
    for i in range(20):
        se.add_packet("flow1", {"timestamp": now + i, "size": random.randint(60, 1500)})
        se.add_packet("flow2", {"timestamp": now + i*2, "size": random.randint(500, 2000)})
    print("Flow1 stats:", se.compute_stats("flow1"))
    print("Flow2 stats:", se.compute_stats("flow2"))
    print("All flows:", se.get_all_flow_stats())
