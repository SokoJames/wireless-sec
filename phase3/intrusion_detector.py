"""
intrusion_detector.py

Aggregates anomalies and attack detections to identify likely intrusions or ongoing attacks.
Supports rule-based and (optionally) statistical/ML-based intrusion detection.
Designed for integration with anomaly_detector, attack_detector, and alert_manager.
"""

import logging
from typing import List, Dict, Any, Optional
import time

DEFAULT_CONFIG = {
    "alert_threshold": 3,      # Number of anomalies/attacks in window to trigger intrusion
    "window_size": 60,         # seconds
    "use_ml": False            # Placeholder for future ML-based detection
}

class IntrusionDetector:
    """
    Aggregates anomaly and attack events to detect intrusions.
    Supports rule-based detection and ML extension.
    """
    def __init__(self, config: Optional[Dict[str, Any]] = None, logger: Optional[logging.Logger] = None):
        self.config = DEFAULT_CONFIG.copy()
        if config:
            self.config.update(config)
        self.logger = logger or logging.getLogger("IntrusionDetector")
        self.event_log: List[Dict[str, Any]] = []

    def add_event(self, event: Dict[str, Any]) -> None:
        """
        Add an anomaly or attack event to the log.
        """
        now = event.get("timestamp", time.time())
        event["timestamp"] = now
        self.event_log.append(event)
        # Remove old events outside the window
        self.event_log = [e for e in self.event_log if now - e["timestamp"] <= self.config["window_size"]]

    def detect_intrusion(self) -> Optional[Dict[str, Any]]:
        """
        Detects intrusion based on the number and type of recent events.
        Returns intrusion alert dict if detected, else None.
        """
        now = time.time()
        window_events = [e for e in self.event_log if now - e["timestamp"] <= self.config["window_size"]]
        if len(window_events) >= self.config["alert_threshold"]:
            alert = {
                "type": "intrusion_alert",
                "event_count": len(window_events),
                "events": window_events,
                "timestamp": now
            }
            self.logger.critical(f"INTRUSION DETECTED: {alert}")
            return alert
        return None

    def run_batch(self, events: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Adds a batch of events and checks for intrusion.
        Returns intrusion alert dict if detected, else None.
        """
        for event in events:
            self.add_event(event)
        return self.detect_intrusion()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    idet = IntrusionDetector()
    now = time.time()
    # Simulate adding events
    events = [
        {"type": "traffic_anomaly", "timestamp": now-10},
        {"type": "deauth_attack", "timestamp": now-5},
        {"type": "probe_scan_attack", "timestamp": now-2}
    ]
    for e in events:
        idet.add_event(e)
    print("Intrusion alert:", idet.detect_intrusion())
    # Test batch
    print("Batch intrusion alert:", idet.run_batch([
        {"type": "device_anomaly", "timestamp": now}
    ]))
