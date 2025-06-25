"""
traffic_classifier.py

Classifies network traffic into categories (e.g., browsing, streaming, VoIP, file transfer) using heuristics and optional ML.
Designed for modular integration with the Wi-Fi Traffic Analyzer. Emphasizes educational clarity and security concepts.
"""

import logging
from typing import Dict, Any, Optional, List
import pandas as pd
import numpy as np

# Default configuration for classification thresholds and ML
DEFAULT_CONFIG = {
    "use_ml": False,  # If True, use ML model; else use heuristics
    "ml_model_path": None,
    "classification_thresholds": {
        "streaming_min_bytes": 500000,
        "voip_max_packet_size": 300,
        "file_transfer_min_bytes": 1000000,
        "browsing_max_connections": 10
    }
}

class TrafficClassifier:
    """
    Classifies network flows/packets into traffic types using heuristics or ML.
    Now supports real-time classification from packet or feature dict, with optional context features.
    Modular ML support (RandomForest, SVM, etc.), probability/confidence output, evaluation, and model persistence.
    """
    def __init__(self, config: Optional[Dict[str, Any]] = None, logger: Optional[logging.Logger] = None):
        self.config = DEFAULT_CONFIG.copy()
        if config:
            self.config.update(config)
        self.logger = logger or logging.getLogger("TrafficClassifier")
        self.ml_model = None
        self.ml_model_type = None  # Track which type of model is loaded
        if self.config["use_ml"] and self.config["ml_model_path"]:
            self._load_ml_model(self.config["ml_model_path"])

    def set_classifier(self, model_type: str = "RandomForest", **kwargs):
        """
        Set up a new scikit-learn classifier for training. Supported: 'RandomForest', 'SVM', 'KNN'.
        """
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.svm import SVC
        from sklearn.neighbors import KNeighborsClassifier
        if model_type == "RandomForest":
            self.ml_model = RandomForestClassifier(**kwargs)
            self.ml_model_type = "RandomForest"
        elif model_type == "SVM":
            self.ml_model = SVC(probability=True, **kwargs)
            self.ml_model_type = "SVM"
        elif model_type == "KNN":
            self.ml_model = KNeighborsClassifier(**kwargs)
            self.ml_model_type = "KNN"
        else:
            raise ValueError(f"Unsupported model_type: {model_type}")
        self.logger.info(f"Initialized classifier: {model_type}")

    def train(self, X, y):
        """
        Train the current ML model. X: feature matrix, y: labels.
        """
        if self.ml_model is None:
            raise RuntimeError("ML model is not initialized. Call set_classifier() first.")
        self.ml_model.fit(X, y)
        self.logger.info("ML model trained.")

    def evaluate(self, X, y_true, verbose: bool = True, save_path: Optional[str] = None) -> dict:
        """
        Evaluate the classifier on test data. Returns metrics and optionally saves report.
        """
        from sklearn.metrics import classification_report, confusion_matrix
        if self.ml_model is None:
            raise RuntimeError("ML model is not initialized.")
        y_pred = self.ml_model.predict(X)
        report = classification_report(y_true, y_pred, output_dict=True)
        cm = confusion_matrix(y_true, y_pred)
        if verbose:
            print("Confusion Matrix:\n", cm)
            print("Classification Report:\n", classification_report(y_true, y_pred))
        if save_path:
            import json
            with open(save_path, "w") as f:
                json.dump({"confusion_matrix": cm.tolist(), "report": report}, f, indent=2)
        return {"confusion_matrix": cm, "report": report}

    def save_model(self, path: str):
        """
        Save the trained ML model to disk.
        """
        try:
            import joblib
            joblib.dump(self.ml_model, path)
            self.logger.info(f"Model saved to {path}")
        except Exception as e:
            self.logger.error(f"Failed to save model: {e}")

    def load_model(self, path: str):
        """
        Load an ML model from disk.
        """
        self._load_ml_model(path)

    def _load_ml_model(self, model_path: str):
        """
        Load a pre-trained ML model from disk (scikit-learn format).
        """
        try:
            import joblib
            self.ml_model = joblib.load(model_path)
            self.ml_model_type = type(self.ml_model).__name__
            self.logger.info(f"Loaded ML model from {model_path}")
        except Exception as e:
            self.logger.error(f"Failed to load ML model: {e}")
            self.ml_model = None
            self.ml_model_type = None

    def _load_ml_model(self, model_path: str):
        """
        Load a pre-trained ML model from disk (optional, scikit-learn format).
        """
        try:
            import joblib
            self.ml_model = joblib.load(model_path)
            self.logger.info(f"Loaded ML model from {model_path}")
        except Exception as e:
            self.logger.error(f"Failed to load ML model: {e}")
            self.ml_model = None

    def classify(self, features: Dict[str, Any]) -> str:
        """
        Classify a traffic flow or packet based on features.
        If ML is enabled and model is loaded, use it; else use heuristics.
        features: dict with keys like 'bytes', 'packet_count', 'avg_packet_size', 'duration', 'protocol', etc.
        Returns one of: 'browsing', 'streaming', 'voip', 'file_transfer', 'other'.
        """
        if self.config["use_ml"] and self.ml_model is not None:
            # Prepare features for ML model
            try:
                X = np.array([[features.get(k, 0) for k in self.ml_model.feature_names_in_]])
                pred = self.ml_model.predict(X)[0]
                return str(pred)
            except Exception as e:
                self.logger.error(f"ML classification error: {e}")
                return "other"
        # Heuristic classification
        t = self.config["classification_thresholds"]
        if features.get("bytes", 0) >= t["file_transfer_min_bytes"]:
            return "file_transfer"
        if features.get("bytes", 0) >= t["streaming_min_bytes"] and features.get("protocol") in ["TCP", "UDP"]:
            return "streaming"
        if features.get("avg_packet_size", 0) <= t["voip_max_packet_size"] and features.get("protocol") == "UDP":
            return "voip"
        if features.get("connection_count", 0) <= t["browsing_max_connections"]:
            return "browsing"
        return "other"

    def classify_with_confidence(self, features: Dict[str, Any]) -> (str, float):
        """
        Classify and return (label, confidence). For ML, confidence is probability; for heuristics, a rough score.
        """
        if self.config["use_ml"] and self.ml_model is not None:
            try:
                X = np.array([[features.get(k, 0) for k in self.ml_model.feature_names_in_]])
                pred = self.ml_model.predict(X)[0]
                proba = None
                if hasattr(self.ml_model, "predict_proba"):
                    proba_arr = self.ml_model.predict_proba(X)[0]
                    idx = list(self.ml_model.classes_).index(pred)
                    proba = float(proba_arr[idx])
                return str(pred), proba if proba is not None else 1.0
            except Exception as e:
                self.logger.error(f"ML classification error: {e}")
                return "other", 0.0
        # Heuristic: assign rough confidence
        t = self.config["classification_thresholds"]
        if features.get("bytes", 0) >= t["file_transfer_min_bytes"]:
            return "file_transfer", 0.9
        if features.get("bytes", 0) >= t["streaming_min_bytes"] and features.get("protocol") in ["TCP", "UDP"]:
            return "streaming", 0.8
        if features.get("avg_packet_size", 0) <= t["voip_max_packet_size"] and features.get("protocol") == "UDP":
            return "voip", 0.7
        if features.get("connection_count", 0) <= t["browsing_max_connections"]:
            return "browsing", 0.6
        return "other", 0.4

    def batch_classify(self, flows: List[Dict[str, Any]]) -> List[str]:
        """
        Classify a batch of flows/packets.
        Returns list of categories.
        """
        return [self.classify(f) for f in flows]

    def classify_packet_realtime(self, pkt, extra_features: Optional[Dict[str, Any]] = None):
        """
        Classify a single packet (Scapy or dict) in real time, optionally merging extra features (e.g. flow stats, behavioral analysis).
        Returns (label, details) where label is the traffic type and details is a dict with confidence/explanation.
        """
        from phase2.feature_extractor import FeatureExtractor
        fe = FeatureExtractor()
        # Extract packet features
        pkt_features = fe.extract_packet_features(pkt)
        # Merge with extra_features if provided
        features = pkt_features.copy()
        if extra_features:
            features.update(extra_features)
        label, confidence = self.classify_with_confidence(features)
        details = {"features": features, "confidence": confidence}
        # Optionally add ML probabilities
        if self.config["use_ml"] and self.ml_model is not None and hasattr(self.ml_model, "predict_proba"):
            try:
                import numpy as np
                X = np.array([[features.get(k, 0) for k in self.ml_model.feature_names_in_]])
                proba = self.ml_model.predict_proba(X)[0]
                details["proba"] = {str(cls): float(p) for cls, p in zip(self.ml_model.classes_, proba)}
            except Exception as e:
                details["proba_error"] = str(e)
        # Optionally add explanation for heuristic
        if not self.config["use_ml"]:
            t = self.config["classification_thresholds"]
            expl = []
            if features.get("bytes", 0) >= t["file_transfer_min_bytes"]:
                expl.append("large bytes: file_transfer")
            elif features.get("bytes", 0) >= t["streaming_min_bytes"] and features.get("protocol") in ["TCP", "UDP"]:
                expl.append("streaming threshold met")
            elif features.get("avg_packet_size", 0) <= t["voip_max_packet_size"] and features.get("protocol") == "UDP":
                expl.append("voip packet size/protocol")
            elif features.get("connection_count", 0) <= t["browsing_max_connections"]:
                expl.append("browsing: low connections")
            else:
                expl.append("other")
            details["explanation"] = "; ".join(expl)
        return label, details

if __name__ == "__main__":
    import random
    logging.basicConfig(level=logging.INFO)
    tc = TrafficClassifier()
    # Example test flows
    test_flows = [
        {"bytes": 2000000, "protocol": "TCP", "avg_packet_size": 1000, "connection_count": 1},  # file_transfer
        {"bytes": 800000, "protocol": "UDP", "avg_packet_size": 1200, "connection_count": 2},   # streaming
        {"bytes": 30000, "protocol": "UDP", "avg_packet_size": 200, "connection_count": 1},     # voip
        {"bytes": 10000, "protocol": "TCP", "avg_packet_size": 500, "connection_count": 5},     # browsing
        {"bytes": 5000, "protocol": "ICMP", "avg_packet_size": 100, "connection_count": 1}      # other
    ]
    for i, flow in enumerate(test_flows):
        category = tc.classify(flow)
        print(f"Test flow {i+1}: classified as {category}")
