"""
alert_manager.py

Manages, logs, and dispatches security alerts from anomaly, attack, and intrusion detectors.
Supports alert formatting, deduplication, escalation, and integration with external notification systems (e.g., email, syslog, webhook).
Designed for modular use in the Wi-Fi Traffic Analyzer security pipeline.
"""

import logging
from typing import Dict, Any, List, Optional
import time

DEFAULT_CONFIG = {
    "dedup_window": 60,           # seconds to suppress duplicate alerts
    "escalation_levels": [
        {"type": "intrusion_alert", "level": "CRITICAL"},
        {"type": "attack", "level": "ERROR"},
        {"type": "anomaly", "level": "WARNING"}
    ],
    "external_notifications": False  # Placeholder for future integration
}

class AlertManager:
    """
    Handles alert logging, deduplication, escalation, and dispatch.
    """
    def __init__(self, config: Optional[Dict[str, Any]] = None, logger: Optional[logging.Logger] = None):
        self.config = DEFAULT_CONFIG.copy()
        if config:
            self.config.update(config)
        self.logger = logger or logging.getLogger("AlertManager")
        self.recent_alerts: List[Dict[str, Any]] = []

    def _is_duplicate(self, alert: Dict[str, Any]) -> bool:
        now = alert.get("timestamp", time.time())
        for a in self.recent_alerts:
            if (
                a.get("type") == alert.get("type") and
                a.get("event_count", None) == alert.get("event_count", None) and
                now - a.get("timestamp", now) < self.config["dedup_window"]
            ):
                return True
        return False

    def _get_level(self, alert_type: str) -> str:
        for lvl in self.config["escalation_levels"]:
            if lvl["type"] in alert_type:
                return lvl["level"]
        return "INFO"

    def handle_alert(self, alert: Dict[str, Any]) -> None:
        """
        Log, deduplicate, and (optionally) dispatch an alert.
        """
        now = alert.get("timestamp", time.time())
        alert["timestamp"] = now
        if self._is_duplicate(alert):
            self.logger.info(f"Duplicate alert suppressed: {alert}")
            return
        self.recent_alerts.append(alert)
        # Remove old alerts
        self.recent_alerts = [a for a in self.recent_alerts if now - a["timestamp"] < self.config["dedup_window"]]
        level = self._get_level(alert.get("type", ""))
        msg = f"ALERT [{level}]: {alert}"
        if level == "CRITICAL":
            self.logger.critical(msg)
        elif level == "ERROR":
            self.logger.error(msg)
        elif level == "WARNING":
            self.logger.warning(msg)
        else:
            self.logger.info(msg)
        # Placeholder for external notifications
        if self.config["external_notifications"]:
            self._send_external(alert)

    def _send_external(self, alert: Dict[str, Any]) -> None:
        # Placeholder for future: send email, webhook, syslog, etc.
        self.logger.info(f"External notification sent: {alert}")

    def run_batch(self, alerts: List[Dict[str, Any]]) -> None:
        for alert in alerts:
            self.handle_alert(alert)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    am = AlertManager()
    now = time.time()
    # Simulate alerts
    alerts = [
        {"type": "intrusion_alert", "event_count": 4, "timestamp": now-10},
        {"type": "deauth_attack", "timestamp": now-5},
        {"type": "traffic_anomaly", "timestamp": now-2}
    ]
    for alert in alerts:
        am.handle_alert(alert)
    # Test deduplication
    am.handle_alert({"type": "intrusion_alert", "event_count": 4, "timestamp": now})
    # Test batch
    am.run_batch(alerts)
