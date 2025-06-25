"""
feature_extractor.py

Extracts features from packets or flows for use in classification, anomaly detection, and statistical analysis.
Supports both packet-level and flow-level feature extraction.
Designed for modular integration with Wi-Fi Traffic Analyzer Phase 2 modules.
"""

import logging
from typing import Dict, Any, List, Optional
import numpy as np
import pandas as pd

DEFAULT_CONFIG = {
    "extract_flow_features": True,
    "extract_packet_features": True
}

class FeatureExtractor:
    """
    Extracts relevant features from packets or flows for analysis and ML.
    Supports modular feature groups, feature selection, and reduction.
    """
    def __init__(self, config: Optional[Dict[str, Any]] = None, logger: Optional[logging.Logger] = None):
        self.config = DEFAULT_CONFIG.copy()
        if config:
            self.config.update(config)
        self.logger = logger or logging.getLogger("FeatureExtractor")
        self.selected_features: Optional[List[str]] = self.config.get("selected_features")
        self.use_pca: bool = self.config.get("use_pca", False)
        self.pca_model = None

    def extract_packet_features(self, pkt: Any) -> Dict[str, Any]:
        """
        Extracts features from a single packet (Scapy or dict).
        Returns a dict of features (protocol, size, src/dst MAC, etc.).
        """
        features = {}
        try:
            # If Scapy packet
            if hasattr(pkt, 'summary'):
                features['size'] = len(pkt)
                features['protocol'] = pkt.payload.name if hasattr(pkt, 'payload') else 'Unknown'
                features['src_mac'] = getattr(pkt, 'addr2', None)
                features['dst_mac'] = getattr(pkt, 'addr1', None)
                features['timestamp'] = getattr(pkt, 'time', None)
                # Optionally extract more fields if present
                for attr in ['sport', 'dport', 'flags']:
                    if hasattr(pkt, attr):
                        features[attr] = getattr(pkt, attr)
            # If dict (from flow)
            elif isinstance(pkt, dict):
                features.update(pkt)
        except Exception as e:
            self.logger.error(f"Packet feature extraction error: {e}")
        return features

    def extract_flow_features(self, packets: List[Any]) -> Dict[str, Any]:
        """
        Extracts aggregate features from a list of packets (flow).
        Returns a dict of features (total bytes, avg size, duration, entropy, burstiness, etc.).
        """
        if not packets:
            return {}
        pkt_feats = [self.extract_packet_features(pkt) for pkt in packets]
        sizes = [f.get('size', 0) for f in pkt_feats]
        timestamps = [f.get('timestamp', 0) for f in pkt_feats if f.get('timestamp', 0)]
        src_macs = [f.get('src_mac') for f in pkt_feats]
        dst_macs = [f.get('dst_mac') for f in pkt_feats]
        protocols = [f.get('protocol') for f in pkt_feats]
        # Temporal features
        iats = np.diff(sorted(timestamps)) if len(timestamps) > 1 else []
        # Statistical features
        features = {
            'bytes': int(np.sum(sizes)),
            'packet_count': len(packets),
            'avg_packet_size': float(np.mean(sizes)) if sizes else 0,
            'max_packet_size': int(np.max(sizes)) if sizes else 0,
            'min_packet_size': int(np.min(sizes)) if sizes else 0,
            'size_variance': float(np.var(sizes)) if len(sizes) > 1 else 0,
            'size_skewness': float(pd.Series(sizes).skew()) if len(sizes) > 2 else 0,
            'size_kurtosis': float(pd.Series(sizes).kurt()) if len(sizes) > 3 else 0,
            'duration': float(max(timestamps) - min(timestamps)) if len(timestamps) > 1 else 0.0,
            'src_mac': src_macs[0] if src_macs else None,
            'dst_mac': dst_macs[0] if dst_macs else None,
            'protocol': protocols[0] if protocols else None,
            'unique_src_macs': len(set(src_macs)),
            'unique_dst_macs': len(set(dst_macs)),
            'entropy_packet_size': self._calc_entropy(sizes),
            'burstiness': self._calc_burstiness(timestamps),
            'mean_iat': float(np.mean(iats)) if len(iats) > 0 else 0,
            'std_iat': float(np.std(iats)) if len(iats) > 0 else 0,
            'min_iat': float(np.min(iats)) if len(iats) > 0 else 0,
            'max_iat': float(np.max(iats)) if len(iats) > 0 else 0,
        }
        # Feature selection
        if self.selected_features:
            features = {k: features[k] for k in self.selected_features if k in features}
        # PCA (fit/transform)
        if self.use_pca:
            features = self._apply_pca(features)
        return features

    def _calc_entropy(self, arr: list) -> float:
        """
        Calculate entropy of a value distribution.
        """
        if not arr or len(arr) == 1:
            return 0.0
        values, counts = np.unique(arr, return_counts=True)
        probs = counts / counts.sum()
        entropy = -np.sum(probs * np.log2(probs))
        return float(entropy)

    def _calc_burstiness(self, timestamps: list) -> float:
        """
        Calculate burstiness as stddev/mean of inter-arrival times.
        """
        if len(timestamps) < 2:
            return 0.0
        iats = np.diff(sorted(timestamps))
        mean = np.mean(iats)
        std = np.std(iats)
        return float(std / mean) if mean > 0 else 0.0

    def fit_pca(self, X: np.ndarray, n_components: int = 3):
        """
        Fit a PCA model for dimensionality reduction on flow features.
        """
        from sklearn.decomposition import PCA
        self.pca_model = PCA(n_components=n_components)
        self.pca_model.fit(X)
        self.logger.info(f"Fitted PCA with {n_components} components.")

    def _apply_pca(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply fitted PCA model to a single feature dict.
        """
        if not self.pca_model:
            self.logger.warning("PCA model not fitted.")
            return features
        arr = np.array([list(features.values())]).reshape(1, -1)
        reduced = self.pca_model.transform(arr)[0]
        return {f'pca_{i}': float(val) for i, val in enumerate(reduced)}

    def extract_packet_features(self, pkt: Any) -> Dict[str, Any]:
        """
        Extracts features from a single packet (Scapy or dict).
        Returns a dict of features (protocol, size, src/dst MAC, etc.).
        """
        features = {}
        try:
            # If Scapy packet
            if hasattr(pkt, 'summary'):
                features['size'] = len(pkt)
                features['protocol'] = pkt.payload.name if hasattr(pkt, 'payload') else 'Unknown'
                features['src_mac'] = getattr(pkt, 'addr2', None)
                features['dst_mac'] = getattr(pkt, 'addr1', None)
                features['timestamp'] = getattr(pkt, 'time', None)
            # If dict (from flow)
            elif isinstance(pkt, dict):
                features.update(pkt)
        except Exception as e:
            self.logger.error(f"Packet feature extraction error: {e}")
        return features

    def extract_flow_features(self, packets: List[Any]) -> Dict[str, Any]:
        """
        Extracts aggregate features from a list of packets (flow).
        Returns a dict of features (total bytes, avg size, duration, etc.).
        """
        if not packets:
            return {}
        sizes = [self.extract_packet_features(pkt).get('size', 0) for pkt in packets]
        timestamps = [self.extract_packet_features(pkt).get('timestamp', 0) for pkt in packets if self.extract_packet_features(pkt).get('timestamp', 0)]
        src_macs = [self.extract_packet_features(pkt).get('src_mac') for pkt in packets]
        dst_macs = [self.extract_packet_features(pkt).get('dst_mac') for pkt in packets]
        protocols = [self.extract_packet_features(pkt).get('protocol') for pkt in packets]
        features = {
            'bytes': int(np.sum(sizes)),
            'packet_count': len(packets),
            'avg_packet_size': float(np.mean(sizes)) if sizes else 0,
            'max_packet_size': int(np.max(sizes)) if sizes else 0,
            'min_packet_size': int(np.min(sizes)) if sizes else 0,
            'duration': float(max(timestamps) - min(timestamps)) if len(timestamps) > 1 else 0.0,
            'src_mac': src_macs[0] if src_macs else None,
            'dst_mac': dst_macs[0] if dst_macs else None,
            'protocol': protocols[0] if protocols else None
        }
        return features

if __name__ == "__main__":
    import time
    logging.basicConfig(level=logging.INFO)
    fe = FeatureExtractor()
    # Simulate packets (as dicts)
    now = time.time()
    packets = [
        {'size': 500, 'protocol': 'TCP', 'src_mac': 'AA:BB:CC:DD:EE:01', 'dst_mac': 'FF:EE:DD:CC:BB:01', 'timestamp': now},
        {'size': 1200, 'protocol': 'TCP', 'src_mac': 'AA:BB:CC:DD:EE:01', 'dst_mac': 'FF:EE:DD:CC:BB:01', 'timestamp': now+1},
        {'size': 800, 'protocol': 'TCP', 'src_mac': 'AA:BB:CC:DD:EE:01', 'dst_mac': 'FF:EE:DD:CC:BB:01', 'timestamp': now+2}
    ]
    print("Packet features:", fe.extract_packet_features(packets[0]))
    print("Flow features:", fe.extract_flow_features(packets))
