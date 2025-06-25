from scapy.all import sniff
from collections import defaultdict, deque
import time
from ml_model import load_model, predict
from utils import extract_features_from_packet, classify_traffic_heuristic, check_intrusion, extract_macs

# State for DoS and anomaly detection
packet_times = deque(maxlen=100)
syn_counts = defaultdict(int)
port_hits = defaultdict(set)

def detect_anomaly():
    now = time.time()
    packet_times.append(now)
    if len(packet_times) >= 100 and (now - packet_times[0]) < 5:
        return "[ANOMALY] High packet rate detected!"
    return None

def detect_dos(pkt):
    alerts = []
    if pkt.haslayer("IP") and pkt.haslayer("TCP"):
        flags = pkt["TCP"].flags
        src = pkt["IP"].src
        if flags == 'S':  # SYN flag
            syn_counts[src] += 1
            if syn_counts[src] > 50:
                alerts.append(f"[DoS] SYN flood suspect from {src}")
        port_hits[src].add(pkt["TCP"].dport)
        if len(port_hits[src]) > 20:
            alerts.append(f"[Port Scan] Suspicious scan from {src}")
    return alerts

def live_sniff(interface, use_ml=False, detect_intrusion=False, detect_anomaly=False, detect_dos=False):
    print(f"[*] Starting live sniffing on interface: {interface}")
    model = load_model() if use_ml else None

    def process_packet(pkt):
        try:
            mac_src, mac_dst = extract_macs(pkt)
            if detect_intrusion:
                intrusion_msg = check_intrusion(pkt)
                if intrusion_msg:
                    print(intrusion_msg)

            if detect_anomaly:
                anomaly_msg = detect_anomaly()
                if anomaly_msg:
                    print(anomaly_msg)

            if detect_dos:
                dos_alerts = detect_dos(pkt)
                for alert in dos_alerts:
                    print(alert)

            if use_ml:
                features = extract_features_from_packet(pkt)
                if features:
                    label = predict(model, features)
                else:
                    label = "Unknown"
                print(f"[ML Classification] {label} | Src MAC: {mac_src} | Dst MAC: {mac_dst} | Packet: {pkt.summary()}")
            else:
                label = classify_traffic_heuristic(pkt)
                print(f"[Heuristic Classification] {label} | Src MAC: {mac_src} | Dst MAC: {mac_dst} | Packet: {pkt.summary()}")
        except Exception as e:
            print(f"[Error] Packet processing error: {e}")

    sniff(iface=interface, prn=process_packet, store=False)
