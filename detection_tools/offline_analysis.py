from scapy.all import rdpcap
from ml_model import load_model, predict
from utils import extract_features_from_packet, classify_traffic_heuristic, check_intrusion, extract_macs
from live_capture import detect_anomaly, detect_dos

def analyze_pcap(pcap_file, use_ml=False, detect_intrusion=False, detect_anomaly=False, detect_dos=False):
    print(f"[*] Analyzing PCAP file: {pcap_file}")
    packets = rdpcap(pcap_file)
    model = load_model() if use_ml else None

    for pkt in packets:
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
