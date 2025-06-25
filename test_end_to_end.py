"""
test_end_to_end.py

End-to-end integration test for Phase 1 modules:
- packet_capture.py (offline/PCAP mode)
- device_tracker.py
- config_manager.py
- logger.py
- database_handler.py

Feeds packets from a PCAP file through the system, logs events, tracks devices, and stores results in the database.
"""

import os
import logging
from packet_capture import PacketCapture
from device_tracker import DeviceTracker
from config_manager import ConfigManager
from logger import LoggerManager
from database_handler import DatabaseHandler
from scapy.all import rdpcap

# Default config values for testing
DEFAULT_CONFIG = {
    "interface": None,
    "pcap_file": "test.pcap",
    "authorized_macs": [],
    "authorized_ssids": [],
    "association_rate_threshold": 10,
    "log_unknown_devices": True,
    "log_file": "test_e2e.log",
    "db_file": "test_e2e.db"
}


def main():
    # Set up logging
    logger_mgr = LoggerManager({
        "log_file": DEFAULT_CONFIG["log_file"],
        "level": "DEBUG",
        "console": True
    })
    logger = logger_mgr.get_logger("EndToEndTest")

    # Load config
    config_path = "test_config.json"
    config_mgr = ConfigManager(config_path, DEFAULT_CONFIG)
    config = config_mgr.as_dict()

    # Set up database
    db = DatabaseHandler(config.get("db_file", "test_e2e.db"), logger=logger_mgr.get_logger("DB"))

    # Set up device tracker
    tracker = DeviceTracker(
        authorized_macs=set(config.get("authorized_macs", [])),
        authorized_ssids=set(config.get("authorized_ssids", [])),
        config=config,
        logger=logger_mgr.get_logger("DeviceTracker")
    )

    # Register anomaly callback to log and store in DB
    def anomaly_callback(event):
        logger.warning(f"Anomaly detected: {event}")
        db.insert_event({
            "mac": event.get("mac"),
            "event_type": event.get("type"),
            "timestamp": None,
            "ssid": None,
            "info": event.get("msg")
        })
    tracker.register_event_callback("anomaly", anomaly_callback)

    # Feed packets from PCAP file
    pcap_file = config.get("pcap_file")
    if not pcap_file or not os.path.isfile(pcap_file):
        logger.error(f"PCAP file not found: {pcap_file}")
        return
    packets = rdpcap(pcap_file)
    logger.info(f"Processing {len(packets)} packets from {pcap_file}")
    for pkt in packets:
        tracker.process_packet(pkt)

    # Insert all tracked devices into DB
    for mac, info in tracker.get_all_devices().items():
        db.insert_device(mac, info)
    logger.info(f"Inserted {len(tracker.get_all_devices())} devices into database.")

    # Export device registry for review
    tracker.export_to_csv("devices_e2e.csv")
    tracker.export_to_json("devices_e2e.json")
    logger.info("Exported device registry to devices_e2e.csv and devices_e2e.json.")

    # Show DB stats
    logger.info(f"Devices in DB: {len(db.query_devices())}")
    logger.info(f"Events in DB: {len(db.query_events())}")
    db.close()
    logger.info("End-to-end test complete.")

if __name__ == "__main__":
    main()
