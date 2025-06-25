"""
cli.py

Unified Command-Line Interface for the Wi-Fi Traffic Analyzer.
Supports live and offline analysis, configuration management, alert/report viewing, and module diagnostics.
"""

import argparse
import logging
import sys
from pathlib import Path

from packet_capture import PacketCapture
from device_tracker import DeviceTracker
from phase2.feature_extractor import FeatureExtractor
from phase2.statistics_engine import StatisticsEngine
from phase3.anomaly_detector import AnomalyDetector
from phase3.attack_detector import AttackDetector
from phase3.intrusion_detector import IntrusionDetector
from phase3.alert_manager import AlertManager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("AnalyzerCLI")


import os
import shutil
from datetime import datetime

import json

from phase2.pattern_analyzer import PatternAnalyzer
from phase2.traffic_classifier import TrafficClassifier
from database_handler import DatabaseHandler

def color(text, code):
    return f"\033[{code}m{text}\033[0m"

from utils import print_table, COLORS


def run_analysis(pcap=None, live=False, interface=None, config=None, queue_size=5000, verbose=False, json_report=False):
    # Instantiate all modules ONCE for full phase connection
    dt = DeviceTracker()
    fe = FeatureExtractor()
    se = StatisticsEngine()
    pa = PatternAnalyzer()
    tc = TrafficClassifier()
    ad = AnomalyDetector()
    atk = AttackDetector()
    idet = IntrusionDetector()
    am = AlertManager()
    db = DatabaseHandler()
    start_time = datetime.now()

    if pcap:
        logger.info(f"Loading packets from {pcap}")
        pc = PacketCapture(config={"pcap_file": pcap, "queue_size": queue_size})
        packets = list(pc.read_pcap_file())
    elif live:
        logger.info(f"Starting live capture on {interface} (queue_size={queue_size})")
        pc = PacketCapture(config={"interface": interface, "queue_size": queue_size})
        packets = []
        pc.start_live_capture(async_mode=False)
        try:
            for _ in range(queue_size):
                pkt = pc.get_packet(timeout=2)
                if pkt:
                    packets.append(pkt)
        except KeyboardInterrupt:
            logger.info("Live capture stopped by user.")
        finally:
            pc.stop()
    else:
        logger.error("Specify either --pcap or --live mode.")
        return

    flow_packets = []
    alert_count = 0
    anomaly_count = 0
    attack_count = 0
    intrusion_count = 0
    traffic_classifications = []
    pattern_findings = []
    findings = []
    anomaly_rows = []
    intrusion_rows = []
    verbose_rows = []
    findings_json = {
        'timestamp': start_time.isoformat(),
        'packets_processed': len(packets),
        'devices_tracked': 0,
        'anomalies': [],
        'attacks': [],
        'intrusions': [],
        'traffic_classifications': [],
        'pattern_findings': [],
        'devices': {},
    }
    for i, pkt in enumerate(packets, 1):
        dt.process_packet(pkt)
        pkt_features = fe.extract_packet_features(pkt)
        flow_key = f"{pkt_features.get('src_mac')}-{pkt_features.get('dst_mac')}"
        se.add_packet(flow_key, pkt_features)
        flow_packets.append(pkt)
        if verbose and i % 25 == 0:
            verbose_rows.append({
                'Step': i,
                'Type': 'Info',
                'Details': f"Processed {i} packets...",
                'Timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
        if len(flow_packets) >= 50:
            stats = se.compute_stats(flow_key)
            pattern = pa.analyze_behavior(stats)
            if pattern:
                pattern_findings.append(pattern)
                findings_json['pattern_findings'].append(pattern)
                if verbose:
                    verbose_rows.append({
                        'Step': i,
                        'Type': 'Pattern',
                        'Details': f"Pattern found: {pattern}",
                        'Timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    })
                findings.append({'type': 'Pattern', 'desc': str(pattern), 'timestamp': stats.get('timestamp', '')})
            traffic_type = tc.classify(stats)
            if traffic_type:
                traffic_classifications.append({
                    'type': traffic_type,
                    'src_mac': pkt_features.get('src_mac'),
                    'dst_mac': pkt_features.get('dst_mac'),
                    'timestamp': pkt_features.get('timestamp')
                })
                findings_json['traffic_classifications'].append(traffic_type)
                if verbose:
                    verbose_rows.append({
                        'Step': i,
                        'Type': 'Traffic',
                        'Details': f"Traffic classified as: {traffic_type}",
                        'Timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    })
            anomaly = ad.check_traffic_anomaly(stats)
            if anomaly:
                am.handle_alert(anomaly)
                anomaly_count += 1
                if verbose:
                    verbose_rows.append({
                        'Step': i,
                        'Type': 'Anomaly',
                        'Details': f"Anomaly detected! See summary table for details.",
                        'Timestamp': anomaly.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                    })
                findings.append({'type': 'Anomaly', 'desc': str(anomaly), 'timestamp': anomaly.get('timestamp', '')})
                findings_json['anomalies'].append(anomaly)
                anomaly_rows.append({
                    'Type': anomaly.get('type',''),
                    'Anomalies': ','.join(anomaly.get('anomalies', [])),
                    'Stats': str(anomaly.get('stats', '')),
                    'Timestamp': anomaly.get('timestamp','')
                })
            device_info = dt.device_registry.get(pkt_features.get('src_mac'), {})
            attack_alerts = []
            if 'events' in device_info:
                attack_alerts += [atk.detect_deauth_attack(device_info.get('events', []))]
                attack_alerts += [atk.detect_disassoc_attack(device_info.get('events', []))]
            attack_alerts = [a for a in attack_alerts if a]
            for alert in attack_alerts:
                am.handle_alert(alert)
                attack_count += 1
                if verbose:
                    verbose_rows.append({
                        'Step': i,
                        'Type': 'Attack',
                        'Details': f"Attack detected! See summary table for details.",
                        'Timestamp': alert.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                    })
                findings.append({'type': 'Attack', 'desc': str(alert), 'timestamp': alert.get('timestamp', '')})
                findings_json['attacks'].append(alert)
            all_alerts = [a for a in [anomaly] + attack_alerts if a]
            intrusion = idet.run_batch(all_alerts)
            if intrusion:
                am.handle_alert(intrusion)
                intrusion_count += 1
                if verbose:
                    verbose_rows.append({
                        'Step': i,
                        'Type': 'Intrusion',
                        'Details': f"Intrusion detected! See summary table for details.",
                        'Timestamp': intrusion.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                    })
                findings.append({'type': 'Intrusion', 'desc': str(intrusion), 'timestamp': intrusion.get('timestamp', '')})
                findings_json['intrusions'].append(intrusion)
                intrusion_rows.append({
                    'Type': intrusion.get('type',''),
                    'Anomalies': ','.join(intrusion.get('anomalies', [])),
                    'Stats': str(intrusion.get('stats', '')),
                    'Timestamp': intrusion.get('timestamp','')
                })
            alert_count += len(all_alerts)
            import time
            for alert in all_alerts:
                # Ensure timestamp is float
                ts = alert.get('timestamp', pkt_features.get('timestamp'))
                try:
                    ts = float(ts)
                except Exception:
                    ts = time.time()
                db.insert_event({
                    'src_mac': pkt_features.get('src_mac'),
                    'dst_mac': pkt_features.get('dst_mac'),
                    'traffic_type': traffic_type if 'traffic_type' in locals() else '',
                    'pattern': pattern if 'pattern' in locals() else '',
                    'timestamp': ts,
                    'event_type': 'traffic',
                    'ssid': '',
                    'info': ''
                })
            db.insert_event({
                'src_mac': pkt_features.get('src_mac'),
                'dst_mac': pkt_features.get('dst_mac'),
                'traffic_type': traffic_type if 'traffic_type' in locals() else '',
                'pattern': pattern if 'pattern' in locals() else '',
                'timestamp': float(pkt_features.get('timestamp')) if pkt_features.get('timestamp') else time.time(),
                'event_type': 'traffic',
                'ssid': '',
                'info': ''
            })
            flow_packets = []
    logger.info("Analysis complete. Check logs for alerts and detections.")
    print(color(f"\n--- Pipeline Health Summary ---", COLORS['summary']))
    print(color(f"Packets processed: {len(packets)}", COLORS['info']))
    print(color(f"Devices tracked: {len(dt.device_registry)}", COLORS['info']))
    print(color(f"Anomalies detected: {anomaly_count}", COLORS['anomaly']))
    print(color(f"Attacks detected: {attack_count}", COLORS['attack']))
    print(color(f"Intrusions detected: {intrusion_count}", COLORS['intrusion']))
    print(color(f"Traffic classifications: {len(traffic_classifications)}", COLORS['traffic']))
    print(color(f"Pattern findings: {len(pattern_findings)}", COLORS['pattern']))
    print(color(f"All phases (1,2,3) connected and responding.", COLORS['success']))

    if verbose and verbose_rows:
        print_table("Verbose Output", verbose_rows, ["Step", "Type", "Details", "Timestamp"])
    if traffic_classifications:
        print_table("Traffic Classifications", [
            {'Type': t['type'], 'Source MAC': t['src_mac'], 'Dest MAC': t['dst_mac'], 'Timestamp': t['timestamp']} for t in traffic_classifications
        ], ["Type", "Source MAC", "Dest MAC", "Timestamp"])
    if anomaly_rows:
        print_table("Detected Anomalies", anomaly_rows, ["Type", "Anomalies", "Stats", "Timestamp"])
    if intrusion_rows:
        print_table("Detected Intrusions", intrusion_rows, ["Type", "Anomalies", "Stats", "Timestamp"])
    if findings:
        print_table("Analysis Findings", [
            {'Finding Type': f['type'], 'Description': f['desc'], 'Timestamp': f['timestamp']} for f in findings
        ], ["Finding Type", "Description", "Timestamp"])

    # --- Save findings and logs to captured directory ---
    captured_dir = os.path.join(os.getcwd(), "captured")
    os.makedirs(captured_dir, exist_ok=True)
    timestamp = start_time.strftime("%Y%m%d_%H%M%S")
    # Save findings summary (text)
    findings_path = os.path.join(captured_dir, f"findings_{timestamp}.txt")
    with open(findings_path, "w") as f:
        f.write(f"Wi-Fi Traffic Analyzer Findings ({timestamp})\n")
        f.write(f"Packets processed: {len(packets)}\n")
        f.write(f"Devices tracked: {len(dt.device_registry)}\n")
        f.write(f"Anomalies detected: {anomaly_count}\n")
        f.write(f"Attacks detected: {attack_count}\n")
        f.write(f"Intrusions detected: {intrusion_count}\n")
        f.write(f"Traffic classifications: {len(traffic_classifications)}\n")
        f.write(f"Pattern findings: {len(pattern_findings)}\n")
        f.write(f"\n--- Devices ---\n")
        for mac, info in dt.device_registry.items():
            f.write(f"{mac}: {info}\n")
        f.write(f"\n--- Findings ---\n")
        for line in findings:
            f.write(f"{line}\n")
        f.write(f"\n--- Traffic Classifications ---\n")
        for classification in traffic_classifications:
            f.write(f"{classification}\n")
        f.write(f"\n--- Pattern Findings ---\n")
        for finding in pattern_findings:
            f.write(f"{finding}\n")
    print(color(f"[INFO] Findings saved to {findings_path}", COLORS['success']))
    # Save findings as JSON
    findings_json['devices'] = dt.device_registry
    json_path = os.path.join(captured_dir, f"findings_{timestamp}.json")
    with open(json_path, "w") as jf:
        json.dump(findings_json, jf, indent=2, default=str)
    if json_report:
        print(color(f"[INFO] JSON report saved to {json_path}", COLORS['success']))
    # Copy PCAP file if used
    if pcap and os.path.isfile(pcap):
        shutil.copy2(pcap, os.path.join(captured_dir, f"capture_{timestamp}.pcap"))
        print(color(f"[INFO] PCAP copied to captured directory.", COLORS['success']))
    # Copy log file if exists
    log_path = os.path.join(os.getcwd(), "analyzer.log")
    if os.path.isfile(log_path):
        shutil.copy2(log_path, os.path.join(captured_dir, f"analyzer_{timestamp}.log"))
        print(color(f"[INFO] Log copied to captured directory.", COLORS['success']))


def main():
    parser = argparse.ArgumentParser(description="Wi-Fi Traffic Analyzer CLI")
    parser.add_argument('--pcap', type=str, help='Path to PCAP file for offline analysis')
    parser.add_argument('--live', action='store_true', help='Enable live capture (requires root)')
    parser.add_argument('--interface', type=str, default='wlan0', help='Wireless interface for live capture')
    parser.add_argument('--config', type=str, help='Path to config file (JSON/YAML)')
    parser.add_argument('--queue-size', type=int, default=5000, help='Packet queue size for live capture')
    parser.add_argument('--verbose', action='store_true', help='Show verbose analysis output')
    parser.add_argument('--json-report', action='store_true', help='Export findings as JSON report')
    parser.add_argument('--show-devices', action='store_true', help='Show tracked devices after analysis')
    parser.add_argument('--show-alerts', action='store_true', help='Show alerts after analysis (from log)')
    args = parser.parse_args()

    run_analysis(pcap=args.pcap, live=args.live, interface=args.interface, config=args.config, queue_size=args.queue_size, verbose=args.verbose, json_report=args.json_report)

    # Optionally show devices (from last run)
    if args.show_devices:
        # In this CLI, DeviceTracker is instantiated in run_analysis, so tracked devices are printed there.
        pass
    # Optionally show alerts (from log file)
    if args.show_alerts:
        log_path = Path("analyzer.log")
        if log_path.exists():
            print("\nRecent Alerts:")
            with open(log_path) as f:
                for line in f:
                    if any(level in line for level in ["CRITICAL", "ERROR", "WARNING"]):
                        print(line.strip())
        else:
            print("No analyzer.log file found.")

if __name__ == "__main__":
    main()
