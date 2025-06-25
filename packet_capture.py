"""
packet_capture.py

Handles live Wi-Fi packet capture (using Scapy) and offline PCAP file reading.
Provides a thread-safe, configurable interface for feeding packets to the rest of the analyzer.
Emphasizes security, performance, and cross-platform compatibility.
"""

import logging
import threading
import queue
from typing import Optional, Callable, Iterator, Any
from scapy.all import sniff, rdpcap, Packet
import os

# Default configuration
DEFAULT_CONFIG = {
    "interface": None,
    "pcap_file": None,
    "bpf_filter": None,
    "queue_size": 1000,
    "timeout": 10,  # seconds for sniff
    "promiscuous": True
}

class PacketCapture:
    """
    Handles live packet capture and PCAP file reading.
    Provides a thread-safe queue interface for real-time packet processing.
    """
    def __init__(self, 
                 config: Optional[dict] = None,
                 config_path: Optional[str] = None,
                 logger: Optional[logging.Logger] = None):
        """
        Initialize PacketCapture with configuration.
        Loads config from dict or file, sets up logger and packet queue.
        """
        self.config = DEFAULT_CONFIG.copy()
        if config:
            self.config.update(config)
        if config_path:
            self._load_config_from_file(config_path)
        self.interface = self.config["interface"]
        self.pcap_file = self.config["pcap_file"]
        self.bpf_filter = self.config["bpf_filter"]
        self.queue_size = self.config["queue_size"]
        self.timeout = self.config["timeout"]
        self.promiscuous = self.config["promiscuous"]
        self.packet_queue = queue.Queue(maxsize=self.queue_size)
        self._stop_event = threading.Event()
        self._capture_thread = None
        self.logger = logger or logging.getLogger("PacketCapture")
        self.logger.debug(f"Initialized with config: {self.config}")

    def _load_config_from_file(self, path: str) -> None:
        """Load configuration from a JSON file."""
        import json
        try:
            with open(path, 'r') as f:
                file_config = json.load(f)
            self.config.update(file_config)
            self.logger.info(f"Loaded config from {path}")
        except Exception as e:
            self.logger.error(f"Failed to load config file {path}: {e}")

    def _packet_handler(self, pkt: Packet) -> None:
        """Internal handler to enqueue packets."""
        try:
            self.packet_queue.put(pkt, timeout=1)
        except queue.Full:
            self.logger.warning("Packet queue is full. Dropping packet.")

    def start_live_capture(self, async_mode: bool = True) -> None:
        """
        Start live packet capture on the configured interface.
        If async_mode=True, runs in a background thread.
        Runs continuously until stop() is called.
        """
        if not self.interface:
            raise ValueError("No interface specified for live capture.")
        if os.geteuid() != 0:
            self.logger.warning("Live capture may require root privileges.")
        self._stop_event.clear()
        def _sniff():
            try:
                sniff(
                    iface=self.interface,
                    prn=self._packet_handler,
                    filter=self.bpf_filter,
                    store=False,
                    stop_filter=lambda x: self._stop_event.is_set(),
                    promisc=self.promiscuous
                )
                self.logger.info("Live capture stopped.")
            except Exception as e:
                self.logger.error(f"Live capture error: {e}")
        if async_mode:
            self._capture_thread = threading.Thread(target=_sniff, daemon=True)
            self._capture_thread.start()
            self.logger.info(f"Started live capture on {self.interface} (async)")
        else:
            _sniff()

    def stop(self) -> None:
        """
        Stop live packet capture and join the capture thread.
        """
        self._stop_event.set()
        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join()
            self.logger.info("Capture thread stopped.")

    def read_pcap_file(self) -> Iterator[Packet]:
        """
        Read packets from a PCAP file and yield them one by one.
        """
        if not self.pcap_file or not os.path.isfile(self.pcap_file):
            self.logger.error(f"PCAP file not found: {self.pcap_file}")
            return
        try:
            packets = rdpcap(self.pcap_file)
            self.logger.info(f"Read {len(packets)} packets from {self.pcap_file}")
            for pkt in packets:
                yield pkt
        except Exception as e:
            self.logger.error(f"Error reading PCAP file: {e}")

    def get_packet(self, timeout: float = 1.0) -> Optional[Packet]:
        """
        Retrieve a packet from the queue, or None if timeout.
        """
        try:
            return self.packet_queue.get(timeout=timeout)
        except queue.Empty:
            return None

from utils import print_table

def test_live_capture(interface: str, verbose: bool = False):
    """Continuously capture packets live and display a summary table when stopped. If verbose, print each summary in real time."""
    logging.basicConfig(level=logging.INFO)
    pc = PacketCapture({"interface": interface})
    pc.start_live_capture()
    print("[INFO] Live capture started. Press Ctrl+C to stop.")
    summaries = []
    pkt_count = 0
    import time
    try:
        while True:
            pkt = pc.get_packet(timeout=2)
            if pkt:
                pkt_count += 1
                summary = {
                    'No.': pkt_count,
                    'Summary': pkt.summary(),
                    'Time': time.strftime("%Y-%m-%d %H:%M:%S")
                }
                summaries.append(summary)
                if verbose:
                    print(f"[{summary['No.']}] {summary['Time']} - {summary['Summary']}")
    except KeyboardInterrupt:
        print("\n[INFO] Capture stopped by user.")
    finally:
        pc.stop()
        print_table("Captured Packet Summaries", summaries, ["No.", "Summary", "Time"])

def test_read_pcap(pcap_file: str, verbose: bool = False):
    """Read packets from a PCAP file and display a summary table. If verbose, print each summary in real time."""
    logging.basicConfig(level=logging.INFO)
    pc = PacketCapture({"pcap_file": pcap_file})
    summaries = []
    pkt_count = 0
    import time
    for pkt in pc.read_pcap_file():
        pkt_count += 1
        summary = {
            'No.': pkt_count,
            'Summary': pkt.summary(),
            'Time': time.strftime("%Y-%m-%d %H:%M:%S")
        }
        summaries.append(summary)
        if verbose:
            print(f"[{summary['No.']}] {summary['Time']} - {summary['Summary']}")
    print_table("PCAP Packet Summaries", summaries, ["No.", "Summary", "Time"])

if __name__ == "__main__":
    # Example: test_live_capture('wlan0') or test_read_pcap('test.pcap')
    import argparse
    parser = argparse.ArgumentParser(description="Wi-Fi Packet Capture Module")
    parser.add_argument('--interface', type=str, help='Network interface for live capture')
    parser.add_argument('--pcap', type=str, help='Path to PCAP file')
    parser.add_argument('--verbose', action='store_true', help='Enable real-time verbose output')
    args = parser.parse_args()
    if args.interface:
        test_live_capture(args.interface, verbose=args.verbose)
    elif args.pcap:
        test_read_pcap(args.pcap, verbose=args.verbose)
    else:
        print("Specify --interface or --pcap for testing.")
