"""
test_security_pipeline.py

End-to-end demonstration: Connects Phase 1-3 modules for live or offline PCAP analysis and security monitoring.
- Captures or loads packets (packet_capture.py)
- Tracks devices (device_tracker.py)
- Extracts features and computes statistics (feature_extractor, statistics_engine)
- Detects anomalies, attacks, and intrusions (Phase 3)
- Manages alerts (alert_manager)

Usage:
    python3 test_security_pipeline.py --pcap test.pcap
    # Or for live capture (requires root):
    # python3 test_security_pipeline.py --live --interface wlan0
"""

import argparse
import logging
import time
from packet_capture import PacketCapture
from device_tracker import DeviceTracker
from phase2.feature_extractor import FeatureExtractor
from phase2.statistics_engine import StatisticsEngine
from phase3.anomaly_detector import AnomalyDetector
from phase3.attack_detector import AttackDetector
from phase3.intrusion_detector import IntrusionDetector
from phase3.alert_manager import AlertManager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SecurityPipeline")

def main():
    parser = argparse.ArgumentParser(description="Wi-Fi Security Pipeline Demo")
    parser.add_argument('--pcap', type=str, help='Path to PCAP file for offline analysis')
    parser.add_argument('--live', action='store_true', help='Enable live capture (requires root)')
    parser.add_argument('--interface', type=str, default='wlan0', help='Wireless interface for live capture')
    args = parser.parse_args()

    # Initialize modules
    fe = FeatureExtractor()
    se = StatisticsEngine()
    ad = AnomalyDetector()
    atk = AttackDetector()
    idet = IntrusionDetector()
    am = AlertManager()
    dt = DeviceTracker()

    # Packet source
    if args.pcap:
        logger.info(f"Loading packets from {args.pcap}")
        pc = PacketCapture(config={"pcap_file": args.pcap})
        packets = list(pc.read_pcap_file())
    elif args.live:
        logger.info(f"Starting live capture on {args.interface}")
        pc = PacketCapture(config={"interface": args.interface})
        packets = []
        pc.start_live_capture(async_mode=False)
        # Collect packets from the queue (demo: up to 100 packets or until stopped)
        try:
            for _ in range(100):
                pkt = pc.get_packet(timeout=2)
                if pkt:
                    packets.append(pkt)
        except KeyboardInterrupt:
            logger.info("Live capture stopped by user.")
        finally:
            pc.stop()
    else:
        logger.error("Specify --pcap or --live mode.")
        return

    flow_id = 0
    flow_packets = []
    for pkt in packets:
        # Device tracking
        dt.process_packet(pkt)
        # Feature extraction
        pkt_features = fe.extract_packet_features(pkt)
        # Simple flow grouping by src/dst MAC (could be improved)
        flow_key = f"{pkt_features.get('src_mac')}-{pkt_features.get('dst_mac')}"
        se.add_packet(flow_key, pkt_features)
        flow_packets.append(pkt)
        # For demo, process every 50 packets as a flow
        if len(flow_packets) >= 50:
            # Compute stats
            stats = se.compute_stats(flow_key)
            # Anomaly detection
            anomaly = ad.check_traffic_anomaly(stats)
            if anomaly:
                am.handle_alert(anomaly)
            # Attack detection (simulate events)
            # For demo, use device_tracker events if available
            device_info = dt.device_registry.get(pkt_features.get('src_mac'), {})
            attack_alerts = []
            if 'events' in device_info:
                attack_alerts += [atk.detect_deauth_attack(device_info.get('events', []))]
                attack_alerts += [atk.detect_disassoc_attack(device_info.get('events', []))]
            attack_alerts = [a for a in attack_alerts if a]
            for alert in attack_alerts:
                am.handle_alert(alert)
            # Intrusion detection
            all_alerts = [a for a in [anomaly] + attack_alerts if a]
            intrusion = idet.run_batch(all_alerts)
            if intrusion:
                am.handle_alert(intrusion)
            flow_packets = []
    logger.info("Pipeline complete. Check logs for alerts and detections.")

if __name__ == "__main__":
    main()
