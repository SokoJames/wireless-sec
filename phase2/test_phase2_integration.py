"""
test_phase2_integration.py

Integration demo for Phase 2 modules:
- feature_extractor.py
- statistics_engine.py
- pattern_analyzer.py
- traffic_classifier.py

Simulates flow analysis pipeline:
1. Extract features from packets/flows.
2. Calculate rolling statistics.
3. Analyze timing/behavioral patterns.
4. Classify traffic type.
"""

import time
import random
import logging
from feature_extractor import FeatureExtractor
from statistics_engine import StatisticsEngine
from pattern_analyzer import PatternAnalyzer
from traffic_classifier import TrafficClassifier

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Phase2Integration")

def simulate_packets(flow_id: str, n: int = 10, proto: str = "TCP"):
    """Simulate a list of packet dicts for a flow."""
    now = time.time()
    return [
        {
            'size': random.randint(60, 1500),
            'protocol': proto,
            'src_mac': f"AA:BB:CC:DD:EE:{flow_id[-2:]}",
            'dst_mac': f"FF:EE:DD:CC:BB:{flow_id[-2:]}",
            'timestamp': now + i * random.uniform(0.5, 2.0)
        }
        for i in range(n)
    ]

def main():
    # Initialize modules
    fe = FeatureExtractor()
    se = StatisticsEngine()
    pa = PatternAnalyzer()
    tc = TrafficClassifier()

    # Simulate two flows
    flows = {
        "flow1": simulate_packets("flow1", 15, "TCP"),
        "flow2": simulate_packets("flow2", 12, "UDP")
    }

    for flow_id, packets in flows.items():
        logger.info(f"Analyzing {flow_id} with {len(packets)} packets.")
        # Feature extraction
        flow_features = fe.extract_flow_features(packets)
        logger.info(f"Extracted flow features: {flow_features}")
        # Add packets to statistics engine
        for pkt in packets:
            se.add_packet(flow_id, pkt)
        stats = se.compute_stats(flow_id)
        logger.info(f"Rolling stats: {stats}")
        # Timing pattern analysis
        timestamps = [pkt['timestamp'] for pkt in packets]
        timing = pa.analyze_timing(timestamps)
        logger.info(f"Timing analysis: {timing}")
        # Behavioral analysis
        packet_sizes = [pkt['size'] for pkt in packets]
        directions = [1 if i % 2 == 0 else -1 for i in range(len(packets))]  # Simulated directions
        behavior = pa.analyze_behavior({'packet_sizes': packet_sizes, 'directions': directions})
        logger.info(f"Behavioral analysis: {behavior}")
        # Combine features for classification
        combined = {**flow_features, **stats, **timing, **behavior}
        traffic_type = tc.classify(combined)
        logger.info(f"Classified as: {traffic_type}")
        print(f"{flow_id}: {traffic_type}")

if __name__ == "__main__":
    main()
