"""
test_phase3_integration.py

Demonstrates end-to-end integration of all Phase 3 modules:
- anomaly_detector.py
- attack_detector.py
- intrusion_detector.py
- alert_manager.py

Simulates a security event pipeline:
1. Anomaly and attack detection on synthetic stats/events.
2. Aggregation into intrusion alerts.
3. Alert management (deduplication, escalation, logging).
"""

import time
import logging
from anomaly_detector import AnomalyDetector
from attack_detector import AttackDetector
from intrusion_detector import IntrusionDetector
from alert_manager import AlertManager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Phase3Integration")

def simulate_stats_and_events():
    now = time.time()
    # Simulate traffic stats (normal, spike, protocol change)
    stats_list = [
        {"byte_count": 50000, "packet_count": 100, "protocol": "TCP"},
        {"byte_count": 2000000, "packet_count": 2000, "protocol": "TCP"},
        {"byte_count": 10000, "packet_count": 50, "protocol": "UDP"}
    ]
    # Simulate device info (normal, anomaly)
    device_info = {"mac": "AA:BB:CC:DD:EE:01", "last_seen": now, "events": [("association", now-10, None)]*6}
    # Simulate attack events and MAC spoofing
    attack_events = ([{"type": "deauth", "timestamp": now-10}] * 6) + ([{"type": "disassoc", "timestamp": now-5}] * 7)
    spoof_macs = ["AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02", "AA:BB:CC:DD:EE:03", "AA:BB:CC:DD:EE:04"]
    packet_rate = 1500
    probe_count = 15
    return stats_list, device_info, attack_events, spoof_macs, packet_rate, probe_count

def main():
    # Initialize modules
    ad = AnomalyDetector()
    atk = AttackDetector()
    idet = IntrusionDetector()
    am = AlertManager()

    # Simulate stats and events
    stats_list, device_info, attack_events, spoof_macs, packet_rate, probe_count = simulate_stats_and_events()

    # 1. Anomaly detection
    anomaly_alerts = []
    for stats in stats_list:
        res = ad.check_traffic_anomaly(stats)
        if res:
            anomaly_alerts.append(res)
    device_anom = ad.check_device_anomaly(device_info)
    if device_anom:
        anomaly_alerts.append(device_anom)

    # 2. Attack detection
    attack_alerts = []
    attack_alerts += [atk.detect_deauth_attack(attack_events)]
    attack_alerts += [atk.detect_disassoc_attack(attack_events)]
    attack_alerts += [atk.detect_mac_spoofing(spoof_macs)]
    attack_alerts += [atk.detect_flooding(packet_rate)]
    attack_alerts += [atk.detect_probe_scan(probe_count)]
    attack_alerts = [a for a in attack_alerts if a]

    # 3. Intrusion detection (aggregate all alerts)
    all_alerts = anomaly_alerts + attack_alerts
    intrusion_alert = idet.run_batch(all_alerts)
    if intrusion_alert:
        all_alerts.append(intrusion_alert)

    # 4. Alert management (deduplication, escalation, logging)
    am.run_batch(all_alerts)
    print("\nIntegration pipeline complete. See logs above for alert flow.")

if __name__ == "__main__":
    main()
