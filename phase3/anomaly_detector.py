"""
anomaly_detector.py

Statistical anomaly detection for Wi-Fi Traffic Analyzer.
Detects traffic spikes, protocol changes, and abnormal device behavior using configurable thresholds and rolling statistics.
Emphasizes tunable sensitivity, robust logging, and modular alerting.
"""

import logging
from typing import Dict, Any, Optional, List
import numpy as np

DEFAULT_CONFIG = {
    "traffic_volume_threshold": 1000000,  # bytes per window
    "packet_rate_threshold": 1000,        # packets per window
    "protocol_change_alert": True,
    "device_anomaly_threshold": 5,        # e.g., max associations/min
    "alert_on_anomaly": True
}

class AnomalyDetector:
    """
    Detects statistical anomalies in traffic and device behavior.
    """
    def __init__(self, config: Optional[Dict[str, Any]] = None, logger: Optional[logging.Logger] = None):
        self.config = DEFAULT_CONFIG.copy()
        if config:
            self.config.update(config)
        self.logger = logger or logging.getLogger("AnomalyDetector")
        self.last_protocol = None
        self.baselines = {}  # Optional: store rolling means, etc.

    def check_traffic_anomaly(self, stats: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Check for traffic anomalies based on stats (bytes, packets, protocol, etc.).
        Returns anomaly event dict if detected, else None.
        """
        anomalies = []
        if stats.get("byte_count", 0) > self.config["traffic_volume_threshold"]:
            anomalies.append("traffic_spike")
        if stats.get("packet_count", 0) > self.config["packet_rate_threshold"]:
            anomalies.append("packet_rate_spike")
        protocol = stats.get("protocol")
        if self.config["protocol_change_alert"] and protocol and self.last_protocol and protocol != self.last_protocol:
            anomalies.append("protocol_change")
        if protocol:
            self.last_protocol = protocol
        if anomalies:
            event = {"type": "traffic_anomaly", "anomalies": anomalies, "stats": stats}
            self.logger.warning(f"Traffic anomaly detected: {event}")
            return event
        return None

    def check_device_anomaly(self, device_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Check for abnormal device behavior (e.g., excessive associations).
        Returns anomaly event dict if detected, else None.
        """
        events = device_info.get("events", [])
        now = device_info.get("last_seen")
        # Count associations in the last minute
        recent_assoc = [e for e in events if e[0] == "association" and now - e[1] < 60]
        if len(recent_assoc) > self.config["device_anomaly_threshold"]:
            event = {"type": "device_anomaly", "mac": device_info.get("mac"), "count": len(recent_assoc)}
            self.logger.warning(f"Device anomaly detected: {event}")
            return event
        return None

    def update_baseline(self, stats: Dict[str, Any]) -> None:
        """
        Optionally update rolling baselines for adaptive anomaly detection.
        """
        # Example: rolling mean for byte_count
        bc = stats.get("byte_count")
        if bc is not None:
            if "byte_count" not in self.baselines:
                self.baselines["byte_count"] = []
            self.baselines["byte_count"].append(bc)
            if len(self.baselines["byte_count"]) > 100:
                self.baselines["byte_count"] = self.baselines["byte_count"][-100:]

    def run_batch(self, stats_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Batch anomaly detection for a list of stats dicts.
        Returns list of detected anomaly events.
        """
        results = []
        for stats in stats_list:
            event = self.check_traffic_anomaly(stats)
            if event:
                results.append(event)
        return results

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    ad = AnomalyDetector()
    # Simulate normal and anomalous stats
    normal = {"byte_count": 50000, "packet_count": 100, "protocol": "TCP"}
    spike = {"byte_count": 2000000, "packet_count": 2000, "protocol": "TCP"}
    proto_change = {"byte_count": 10000, "packet_count": 50, "protocol": "UDP"}
    print("Normal:", ad.check_traffic_anomaly(normal))
    print("Spike:", ad.check_traffic_anomaly(spike))
    print("Protocol change:", ad.check_traffic_anomaly(proto_change))
    # Simulate device anomaly
    now = 1000000
    device_info = {"mac": "AA:BB:CC:DD:EE:01", "last_seen": now, "events": [("association", now-10, None)]*6}
    print("Device anomaly:", ad.check_device_anomaly(device_info))
