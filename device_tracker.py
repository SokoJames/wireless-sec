"""
device_tracker.py

Tracks all observed devices on the Wi-Fi network by MAC address, SSID association, and event history.
Supports real-time detection of new/unauthorized devices and suspicious association patterns.
Emphasizes security, performance, and educational clarity.
"""

import logging
from typing import Optional, Set, Dict, Any
from scapy.all import Dot11, Packet
import threading
import time

# Default configuration
DEFAULT_CONFIG = {
    "authorized_macs": set(),
    "authorized_ssids": set(),
    "association_rate_threshold": 10,  # max associations per minute
    "log_unknown_devices": True
}

import csv
import json

class DeviceTracker:
    """
    Tracks devices (MACs), their SSID associations, and event history.
    Detects new/unauthorized devices and suspicious activity.
    Now supports:
    - Exporting device registry to CSV/JSON
    - MAC spoofing and rapid association/disassociation anomaly detection
    - Event callback registration for custom event handling
    """
    def __init__(self,
                 authorized_macs: Optional[Set[str]] = None,
                 authorized_ssids: Optional[Set[str]] = None,
                 config: Optional[dict] = None,
                 logger: Optional[logging.Logger] = None):
        self.config = DEFAULT_CONFIG.copy()
        if config:
            self.config.update(config)
        self.authorized_macs = authorized_macs or self.config["authorized_macs"]
        self.authorized_ssids = authorized_ssids or self.config["authorized_ssids"]
        self.association_rate_threshold = self.config["association_rate_threshold"]
        self.log_unknown = self.config["log_unknown_devices"]
        self.device_registry: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.Lock()
        self.logger = logger or logging.getLogger("DeviceTracker")
        # Event callbacks: event_type -> list of callables
        self.event_callbacks = {"new_device": [], "unauthorized_device": [], "anomaly": []}

    def process_packet(self, pkt: Packet) -> None:
        """
        Parse a packet, update device registry, and detect events.
        Only processes 802.11 management frames.
        Also detects:
        - MAC spoofing (same MAC, different SSIDs/BSSIDs rapidly)
        - Rapid association/disassociation cycles
        - Locally administered MACs (randomized MACs)
        Calls registered event callbacks on relevant events.
        """
        if not pkt.haslayer(Dot11):
            return
        dot11 = pkt[Dot11]
        mac = dot11.addr2  # Transmitter MAC
        if not mac:
            return
        ssid = None
        event = None
        now = time.time()
        # Association Request/Response
        if dot11.type == 0 and dot11.subtype in [0, 1]:
            ssid = self._extract_ssid(pkt)
            event = "association"
        elif dot11.type == 0 and dot11.subtype == 4:
            ssid = self._extract_ssid(pkt)
            event = "probe"
        elif dot11.type == 0 and dot11.subtype == 10:
            event = "disassociation"
        # Update registry
        with self.lock:
            is_new = False
            if mac not in self.device_registry:
                is_new = True
                self.device_registry[mac] = {
                    "first_seen": now,
                    "last_seen": now,
                    "ssids": set(),
                    "events": [],
                    "authorized": mac in self.authorized_macs,
                    "anomalies": []
                }
                self.logger.info(f"New device detected: {mac}")
                self._call_event_callbacks("new_device", mac)
                if not self.device_registry[mac]["authorized"] and self.log_unknown:
                    self.logger.warning(f"Unauthorized device: {mac}")
                    self._call_event_callbacks("unauthorized_device", mac)
            else:
                self.device_registry[mac]["last_seen"] = now
            if ssid:
                self.device_registry[mac]["ssids"].add(ssid)
            if event:
                self.device_registry[mac]["events"].append((event, now, ssid))
            # --- Anomaly Detection ---
            # 1. Rapid association/disassociation
            if event in ("association", "disassociation"):
                recent = [e for e in self.device_registry[mac]["events"] if e[0] in ("association", "disassociation") and now - e[1] < 60]
                if len(recent) > self.association_rate_threshold:
                    msg = f"High association/disassociation rate for {mac} (possible attack or spoofing)"
                    self.logger.warning(msg)
                    self.device_registry[mac]["anomalies"].append(("rapid_assoc", now, msg))
                    self._call_event_callbacks("anomaly", {"mac": mac, "type": "rapid_assoc", "msg": msg})
            # 2. MAC spoofing: same MAC, different SSIDs/BSSIDs rapidly
            if event == "association" and len(self.device_registry[mac]["ssids"]) > 3:
                msg = f"MAC {mac} associated with multiple SSIDs in short time (possible spoofing)"
                self.logger.warning(msg)
                self.device_registry[mac]["anomalies"].append(("mac_spoof", now, msg))
                self._call_event_callbacks("anomaly", {"mac": mac, "type": "mac_spoof", "msg": msg})
            # 3. Locally administered MAC (randomized MAC)
            if is_new and self._is_locally_administered_mac(mac):
                msg = f"Device {mac} uses a locally administered (randomized) MAC address"
                self.logger.info(msg)
                self.device_registry[mac]["anomalies"].append(("random_mac", now, msg))
                self._call_event_callbacks("anomaly", {"mac": mac, "type": "random_mac", "msg": msg})

    def _extract_ssid(self, pkt: Packet) -> Optional[str]:
        """
        Extract SSID from 802.11 packet if present.
        """
        try:
            if pkt.haslayer("Dot11Elt"):
                elt = pkt.getlayer("Dot11Elt")
                if elt.ID == 0:
                    return elt.info.decode(errors="ignore")
        except Exception:
            pass
        return None

    def get_device_info(self, mac: str) -> Optional[Dict[str, Any]]:
        """
        Return all tracked info for a given MAC address.
        """
        with self.lock:
            return self.device_registry.get(mac)

    def get_all_devices(self) -> Dict[str, Dict[str, Any]]:
        """
        Return the entire device registry.
        """
        with self.lock:
            return dict(self.device_registry)

    def reset(self) -> None:
        """
        Clear the device registry (for testing).
        """
        with self.lock:
            self.device_registry.clear()

    def export_to_csv(self, filename: str) -> None:
        """
        Export the device registry to a CSV file.
        """
        with self.lock, open(filename, 'w', newline='') as csvfile:
            fieldnames = ["mac", "first_seen", "last_seen", "authorized", "ssids", "anomalies"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for mac, info in self.device_registry.items():
                writer.writerow({
                    "mac": mac,
                    "first_seen": info["first_seen"],
                    "last_seen": info["last_seen"],
                    "authorized": info["authorized"],
                    "ssids": ";".join(info["ssids"]),
                    "anomalies": ";".join(a[2] for a in info.get("anomalies", []))
                })

    def export_to_json(self, filename: str) -> None:
        """
        Export the device registry to a JSON file.
        """
        with self.lock, open(filename, 'w') as jsonfile:
            json.dump(self.device_registry, jsonfile, default=list, indent=2)

    def register_event_callback(self, event_type: str, callback):
        """
        Register a callback for an event type ("new_device", "unauthorized_device", "anomaly").
        Callback signature: callback(event_data)
        """
        if event_type in self.event_callbacks:
            self.event_callbacks[event_type].append(callback)
        else:
            raise ValueError(f"Unknown event type: {event_type}")

    def _call_event_callbacks(self, event_type: str, event_data):
        for cb in self.event_callbacks.get(event_type, []):
            try:
                cb(event_data)
            except Exception as e:
                self.logger.error(f"Event callback error: {e}")

    def _is_locally_administered_mac(self, mac: str) -> bool:
        """
        Check if a MAC address is locally administered (randomized MAC).
        """
        try:
            first_octet = int(mac.split(":")[0], 16)
            return bool(first_octet & 0b10)
        except Exception:
            return False

# Example usage / test
if __name__ == "__main__":
    import argparse
    from scapy.all import rdpcap
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description="Wi-Fi Device Tracker")
    parser.add_argument('--pcap', type=str, help='Path to a PCAP file with 802.11 packets')
    parser.add_argument('--mac', type=str, help='Show info for a specific MAC')
    args = parser.parse_args()
    tracker = DeviceTracker()
    if args.pcap:
        packets = rdpcap(args.pcap)
        for pkt in packets:
            tracker.process_packet(pkt)
        print(f"Total devices tracked: {len(tracker.get_all_devices())}")
    if args.mac:
        info = tracker.get_device_info(args.mac)
        if info:
            print(f"Info for {args.mac}: {info}")
        else:
            print(f"No info found for {args.mac}")
    if not args.pcap and not args.mac:
        print("Specify --pcap to analyze a capture or --mac to query a device.")
