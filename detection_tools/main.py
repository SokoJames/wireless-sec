import argparse
from live_capture import live_sniff
from offline_analysis import analyze_pcap

def main():
    parser = argparse.ArgumentParser(description="Wi-Fi Traffic Analyzer with full detection")

    parser.add_argument('--mode', choices=['live', 'offline'], required=True, help="Choose mode: live or offline")
    parser.add_argument('--interface', default='Wi-Fi', help="Network interface for live capture")
    parser.add_argument('--pcap', help="Path to PCAP file for offline analysis")

    parser.add_argument('--classify', choices=['ml', 'heuristic'], help="Traffic classification method")
    parser.add_argument('--detect_intrusion', action='store_true', help="Enable intrusion detection")
    parser.add_argument('--detect_anomaly', action='store_true', help="Enable anomaly detection")
    parser.add_argument('--detect_dos', action='store_true', help="Enable DoS detection")

    args = parser.parse_args()
    print("\n GROUP 4")
    print("\n====== Wi-Fi Analyzer Config ======")
    print(f"Mode: {args.mode}")
    print(f"Interface: {args.interface}")
    print(f"PCAP file: {args.pcap or 'N/A'}")
    print(f"Classification: {args.classify or 'Disabled'}")
    print(f"Intrusion Detection: {'Enabled' if args.detect_intrusion else 'Disabled'}")
    print(f"Anomaly Detection: {'Enabled' if args.detect_anomaly else 'Disabled'}")
    print(f"DoS Detection: {'Enabled' if args.detect_dos else 'Disabled'}")
    print("==================================\n")

    if args.mode == 'live':
        live_sniff(
            interface=args.interface,
            use_ml=(args.classify == 'ml'),
            detect_intrusion=args.detect_intrusion,
            detect_anomaly=args.detect_anomaly,
            detect_dos=args.detect_dos
        )
    else:
        if not args.pcap:
            print("[ERROR] Provide --pcap file path for offline mode")
            return
        analyze_pcap(
            pcap_file=args.pcap,
            use_ml=(args.classify == 'ml'),
            detect_intrusion=args.detect_intrusion,
            detect_anomaly=args.detect_anomaly,
            detect_dos=args.detect_dos
        )

if __name__ == "__main__":
    main()
