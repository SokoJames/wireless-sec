"""
pattern_analyzer.py

Analyzes timing patterns and behavioral characteristics of network traffic flows.
Detects periodicity, burstiness, and behavioral anomalies for security and classification purposes.
Designed for modular use in Wi-Fi Traffic Analyzer; emphasizes educational clarity and security concepts.
"""

import logging
from typing import List, Dict, Any, Optional
import numpy as np
import pandas as pd

DEFAULT_CONFIG = {
    "burst_threshold": 3.0,   # Stddev multiplier for burst detection
    "periodic_min_count": 5,  # Min events to consider periodicity
    "periodic_jitter": 0.1    # Allowable jitter as fraction of period
}

class PatternAnalyzer:
    """
    Analyzes timing and behavioral patterns in network flows.
    Detects burstiness, periodicity, frequent patterns, and anomalies. Supports rule-based and user-defined pattern alerts.
    """
    def __init__(self, config: Optional[Dict[str, Any]] = None, logger: Optional[logging.Logger] = None):
        self.config = DEFAULT_CONFIG.copy()
        if config:
            self.config.update(config)
        self.logger = logger or logging.getLogger("PatternAnalyzer")
        self.user_patterns: List[Dict[str, Any]] = []  # User-defined pattern templates
        self.detected_patterns: List[Dict[str, Any]] = []  # For auditing/export
        self.rules: List[Any] = []  # List of rule functions

    def add_pattern_template(self, template: Dict[str, Any]) -> None:
        """
        Register a user-defined pattern template (e.g., sequence, value constraints).
        """
        self.user_patterns.append(template)
        self.logger.info(f"Added pattern template: {template}")

    def add_rule(self, rule_func) -> None:
        """
        Register a custom rule function. It should accept (flow_stats, timestamps) and return (matched:bool, info:dict).
        """
        self.rules.append(rule_func)
        self.logger.info("Added custom rule.")

    def analyze_timing(self, timestamps: List[float]) -> Dict[str, Any]:
        """
        Analyze a list of packet or event timestamps for burstiness, periodicity, and frequent intervals.
        Returns a dict with keys: 'is_bursty', 'is_periodic', 'period', 'jitter', 'mean_interval', 'std_interval', 'frequent_intervals'.
        """
        result = {
            'is_bursty': False,
            'is_periodic': False,
            'period': None,
            'jitter': None,
            'mean_interval': None,
            'std_interval': None,
            'frequent_intervals': [],
        }
        if len(timestamps) < 2:
            return result
        intervals = np.diff(sorted(timestamps))
        mean = np.mean(intervals)
        std = np.std(intervals)
        result['mean_interval'] = mean
        result['std_interval'] = std
        # Burstiness: stddev much greater than mean
        if std > self.config['burst_threshold'] * mean:
            result['is_bursty'] = True
        # Periodicity: intervals are similar (low jitter, enough events)
        if len(intervals) >= self.config['periodic_min_count']:
            jitter = std / mean if mean > 0 else 0
            result['jitter'] = jitter
            if jitter < self.config['periodic_jitter']:
                result['is_periodic'] = True
                result['period'] = mean
        # Frequent interval mining (simple histogram)
        counts = np.round(intervals, 2)
        vals, freqs = np.unique(counts, return_counts=True)
        frequent = [(float(v), int(f)) for v, f in zip(vals, freqs) if f > 1]
        result['frequent_intervals'] = frequent
        return result

    def analyze_behavior(self, flow_stats: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze behavioral characteristics of a flow (e.g., packet size variance, direction changes, frequent sizes).
        Returns dict with anomaly flags, stats, and frequent patterns.
        """
        result = {}
        sizes = flow_stats.get('packet_sizes', [])
        directions = flow_stats.get('directions', [])
        # Frequent packet sizes (simple frequent itemset)
        if sizes:
            result['size_mean'] = np.mean(sizes)
            result['size_std'] = np.std(sizes)
            result['size_is_bursty'] = result['size_std'] > self.config['burst_threshold'] * result['size_mean']
            vals, freqs = np.unique(sizes, return_counts=True)
            result['frequent_sizes'] = [(int(v), int(f)) for v, f in zip(vals, freqs) if f > 1]
            # Anomaly detection: IsolationForest (if enough samples)
            if len(sizes) > 10:
                try:
                    from sklearn.ensemble import IsolationForest
                    iso = IsolationForest(contamination=0.1, random_state=42)
                    preds = iso.fit_predict(np.array(sizes).reshape(-1, 1))
                    result['isolation_anomaly'] = int((preds == -1).sum()) > 0
                except ImportError:
                    result['isolation_anomaly'] = None
        if directions:
            changes = np.sum(np.diff(directions) != 0)
            result['direction_changes'] = int(changes)
            result['direction_is_dynamic'] = changes > 1
        # Rule-based pattern matching
        for rule in self.rules:
            try:
                matched, info = rule(flow_stats, sizes)
                if matched:
                    result.setdefault('rule_matches', []).append(info)
                    self.logger.info(f"Rule matched: {info}")
            except Exception as e:
                self.logger.error(f"Rule error: {e}")
        # User-defined pattern matching (simple dict match)
        for template in self.user_patterns:
            if all(flow_stats.get(k) == v for k, v in template.items()):
                result.setdefault('user_pattern_matches', []).append(template)
                self.logger.info(f"User pattern matched: {template}")
        # Audit
        if result.get('size_is_bursty') or result.get('isolation_anomaly'):
            self.detected_patterns.append({'flow_stats': flow_stats, 'result': result})
        return result

    def export_detected_patterns(self, path: str) -> None:
        """
        Export detected patterns/anomalies to a JSON file.
        """
        import json
        with open(path, 'w') as f:
            json.dump(self.detected_patterns, f, indent=2)
        self.logger.info(f"Exported detected patterns to {path}")

    def plot_timing(self, timestamps: List[float]) -> None:
        """
        Plot a timeline of packet/event timestamps (requires matplotlib).
        """
        try:
            import matplotlib.pyplot as plt
        except ImportError:
            self.logger.error("matplotlib is not installed.")
            return
        if not timestamps:
            self.logger.warning("No timestamps to plot.")
            return
        plt.figure(figsize=(8, 2))
        plt.eventplot(timestamps, orientation='horizontal', colors='blue')
        plt.xlabel("Time")
        plt.title("Event Timeline")
        plt.tight_layout()
        plt.show()

    def analyze_timing(self, timestamps: List[float]) -> Dict[str, Any]:
        """
        Analyze a list of packet or event timestamps for burstiness and periodicity.
        Returns a dict with keys: 'is_bursty', 'is_periodic', 'period', 'jitter', 'mean_interval', 'std_interval'.
        """
        result = {
            'is_bursty': False,
            'is_periodic': False,
            'period': None,
            'jitter': None,
            'mean_interval': None,
            'std_interval': None
        }
        if len(timestamps) < 2:
            return result
        intervals = np.diff(sorted(timestamps))
        mean = np.mean(intervals)
        std = np.std(intervals)
        result['mean_interval'] = mean
        result['std_interval'] = std
        # Burstiness: stddev much greater than mean
        if std > self.config['burst_threshold'] * mean:
            result['is_bursty'] = True
        # Periodicity: intervals are similar (low jitter, enough events)
        if len(intervals) >= self.config['periodic_min_count']:
            jitter = std / mean if mean > 0 else 0
            result['jitter'] = jitter
            if jitter < self.config['periodic_jitter']:
                result['is_periodic'] = True
                result['period'] = mean
        return result

    def analyze_behavior(self, flow_stats: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze behavioral characteristics of a flow (e.g., packet size variance, direction changes).
        Returns dict with anomaly flags and stats.
        """
        result = {}
        sizes = flow_stats.get('packet_sizes', [])
        directions = flow_stats.get('directions', [])
        if sizes:
            result['size_mean'] = np.mean(sizes)
            result['size_std'] = np.std(sizes)
            result['size_is_bursty'] = result['size_std'] > self.config['burst_threshold'] * result['size_mean']
        if directions:
            changes = np.sum(np.diff(directions) != 0)
            result['direction_changes'] = int(changes)
            result['direction_is_dynamic'] = changes > 1
        return result

if __name__ == "__main__":
    import time
    logging.basicConfig(level=logging.INFO)
    pa = PatternAnalyzer()
    # Simulate periodic and bursty timestamps
    now = time.time()
    periodic = [now + i*1.0 for i in range(10)]
    bursty = [now, now+0.1, now+0.2, now+5.0, now+5.1, now+10.0]
    print("Periodic:", pa.analyze_timing(periodic))
    print("Bursty:", pa.analyze_timing(bursty))
    # Simulate flow stats
    flow_stats = {'packet_sizes': [100, 120, 90, 500, 600, 80], 'directions': [1,1,1,-1,-1,1]}
    print("Behavior:", pa.analyze_behavior(flow_stats))
