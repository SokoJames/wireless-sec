"""
attack_detector.py

Detects known Wi-Fi/network attacks using signature-based and heuristic methods.
Supports detection of deauthentication, disassociation, spoofing, flooding, and scanning attacks.
Modular, with configurable signatures and thresholds. Designed for integration with anomaly_detector and alert_manager.
"""

import logging
from typing import Dict, Any, List, Optional
import time

DEFAULT_CONFIG = {
    "deauth_threshold": 5,        # Deauth frames per window
    "disassoc_threshold": 5,      # Disassoc frames per window
    "spoofing_mac_window": 3,    # Distinct MACs per device per window
    "flood_packet_rate": 1000,   # Packets/sec for flooding
    "scan_probe_threshold": 10,  # Probe requests per window
    "window_size": 60            # seconds
}

class AttackDetector:
    """
    Detects Wi-Fi and network attacks using signatures and heuristics.
    """
    def __init__(self, config: Optional[Dict[str, Any]] = None, logger: Optional[logging.Logger] = None):
        self.config = DEFAULT_CONFIG.copy()
        if config:
            self.config.update(config)
        self.logger = logger or logging.getLogger("AttackDetector")
        self.event_log: List[Dict[str, Any]] = []
        self.last_check = time.time()

    def detect_deauth_attack(self, events: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Detects deauthentication attack based on event list.
        """
        now = time.time()
        deauths = [e for e in events if e.get("type") == "deauth" and now - e.get("timestamp", now) < self.config["window_size"]]
        if len(deauths) > self.config["deauth_threshold"]:
            event = {"type": "deauth_attack", "count": len(deauths), "timestamp": now}
            self.logger.warning(f"Deauth attack detected: {event}")
            return event
        return None

    def detect_disassoc_attack(self, events: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        now = time.time()
        disassocs = [e for e in events if e.get("type") == "disassoc" and now - e.get("timestamp", now) < self.config["window_size"]]
        if len(disassocs) > self.config["disassoc_threshold"]:
            event = {"type": "disassoc_attack", "count": len(disassocs), "timestamp": now}
            self.logger.warning(f"Disassoc attack detected: {event}")
            return event
        return None

    def detect_mac_spoofing(self, mac_events: List[str]) -> Optional[Dict[str, Any]]:
        """
        Detects MAC spoofing by counting unique MACs seen for a device within a window.
        """
        if len(set(mac_events)) > self.config["spoofing_mac_window"]:
            event = {"type": "mac_spoofing", "distinct_macs": list(set(mac_events))}
            self.logger.warning(f"MAC spoofing detected: {event}")
            return event
        return None

    def detect_flooding(self, packet_rate: float) -> Optional[Dict[str, Any]]:
        """
        Detects flooding attack based on packet rate.
        """
        if packet_rate > self.config["flood_packet_rate"]:
            event = {"type": "flooding_attack", "packet_rate": packet_rate}
            self.logger.warning(f"Flooding attack detected: {event}")
            return event
        return None

    def detect_probe_scan(self, probe_count: int) -> Optional[Dict[str, Any]]:
        """
        Detects scanning/probe attacks based on probe request count.
        """
        if probe_count > self.config["scan_probe_threshold"]:
            event = {"type": "probe_scan_attack", "probe_count": probe_count}
            self.logger.warning(f"Probe scan attack detected: {event}")
            return event
        return None

    def run_all(self, events: List[Dict[str, Any]], mac_events: List[str], packet_rate: float, probe_count: int) -> List[Dict[str, Any]]:
        """
        Runs all attack detection checks and returns list of detected attacks.
        """
        results = []
        for func in [self.detect_deauth_attack, self.detect_disassoc_attack]:
            event = func(events)
            if event:
                results.append(event)
        spoof = self.detect_mac_spoofing(mac_events)
        if spoof:
            results.append(spoof)
        flood = self.detect_flooding(packet_rate)
        if flood:
            results.append(flood)
        probe = self.detect_probe_scan(probe_count)
        if probe:
            results.append(probe)
        return results

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    ad = AttackDetector()
    now = time.time()
    # Simulate events
    events = ([{"type": "deauth", "timestamp": now-10}] * 6) + ([{"type": "disassoc", "timestamp": now-5}] * 7)
    macs = ["AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02", "AA:BB:CC:DD:EE:03", "AA:BB:CC:DD:EE:04"]
    print("Deauth:", ad.detect_deauth_attack(events))
    print("Disassoc:", ad.detect_disassoc_attack(events))
    print("MAC spoofing:", ad.detect_mac_spoofing(macs))
    print("Flooding:", ad.detect_flooding(1500))
    print("Probe scan:", ad.detect_probe_scan(15))
    print("Run all:", ad.run_all(events, macs, 1500, 15))
