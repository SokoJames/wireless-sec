"""
database_handler.py

Handles all SQLite database operations for the Wi-Fi Traffic Analyzer.
Stores device records, events, and traffic statistics with secure, efficient access.
Emphasizes error handling, security, and educational clarity.
"""

import sqlite3
import threading
import logging
from typing import Optional, Dict, Any, List
import time

DEFAULT_DB_PATH = "analyzer.db"

class DatabaseHandler:
    """
    Manages SQLite database for device, event, and traffic data.
    Provides methods for inserting, querying, and updating records.
    """
    def __init__(self, db_path: str = DEFAULT_DB_PATH, logger: Optional[logging.Logger] = None):
        self.db_path = db_path
        self.logger = logger or logging.getLogger("DatabaseHandler")
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        self._create_tables()

    def _create_tables(self):
        """Create tables if they don't exist."""
        with self.lock, self.conn:
            self.conn.execute('''CREATE TABLE IF NOT EXISTS devices (
                mac TEXT PRIMARY KEY,
                first_seen REAL,
                last_seen REAL,
                authorized INTEGER,
                ssids TEXT,
                anomalies TEXT
            )''')
            self.conn.execute('''CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac TEXT,
                event_type TEXT,
                timestamp REAL,
                ssid TEXT,
                info TEXT
            )''')
            self.conn.execute('''CREATE TABLE IF NOT EXISTS traffic (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                src_mac TEXT,
                dst_mac TEXT,
                protocol TEXT,
                length INTEGER,
                info TEXT
            )''')

    def insert_device(self, mac: str, info: Dict[str, Any]) -> None:
        """
        Insert or update a device record.
        info: dict with keys: first_seen, last_seen, authorized, ssids (set), anomalies (list)
        """
        with self.lock, self.conn:
            try:
                self.conn.execute('''INSERT OR REPLACE INTO devices (mac, first_seen, last_seen, authorized, ssids, anomalies)
                    VALUES (?, ?, ?, ?, ?, ?)''',
                    (mac, info.get("first_seen"), info.get("last_seen"), int(info.get("authorized", 0)),
                     ",".join(info.get("ssids", [])),
                     ";".join(a[2] for a in info.get("anomalies", []))))
            except Exception as e:
                self.logger.error(f"Failed to insert/update device {mac}: {e}")

    def insert_event(self, event: Dict[str, Any]) -> None:
        """
        Insert a network event record.
        event: dict with keys: mac, event_type, timestamp, ssid, info
        """
        with self.lock, self.conn:
            try:
                self.conn.execute('''INSERT INTO events (mac, event_type, timestamp, ssid, info)
                    VALUES (?, ?, ?, ?, ?)''',
                    (event.get("mac"), event.get("event_type"), event.get("timestamp", time.time()),
                     event.get("ssid"), event.get("info")))
            except Exception as e:
                self.logger.error(f"Failed to insert event: {e}")

    def insert_traffic(self, traffic: Dict[str, Any]) -> None:
        """
        Insert a traffic record.
        traffic: dict with keys: timestamp, src_mac, dst_mac, protocol, length, info
        """
        with self.lock, self.conn:
            try:
                self.conn.execute('''INSERT INTO traffic (timestamp, src_mac, dst_mac, protocol, length, info)
                    VALUES (?, ?, ?, ?, ?, ?)''',
                    (traffic.get("timestamp", time.time()), traffic.get("src_mac"), traffic.get("dst_mac"),
                     traffic.get("protocol"), traffic.get("length"), traffic.get("info")))
            except Exception as e:
                self.logger.error(f"Failed to insert traffic: {e}")

    def query_devices(self, where: Optional[str] = None, params: tuple = ()) -> List[Dict[str, Any]]:
        """
        Query devices table with optional WHERE clause.
        Returns a list of dicts.
        """
        with self.lock, self.conn:
            try:
                sql = 'SELECT * FROM devices'
                if where:
                    sql += f' WHERE {where}'
                cur = self.conn.execute(sql, params)
                return [dict(row) for row in cur.fetchall()]
            except Exception as e:
                self.logger.error(f"Failed to query devices: {e}")
                return []

    def query_events(self, where: Optional[str] = None, params: tuple = ()) -> List[Dict[str, Any]]:
        """
        Query events table with optional WHERE clause.
        Returns a list of dicts.
        """
        with self.lock, self.conn:
            try:
                sql = 'SELECT * FROM events'
                if where:
                    sql += f' WHERE {where}'
                cur = self.conn.execute(sql, params)
                return [dict(row) for row in cur.fetchall()]
            except Exception as e:
                self.logger.error(f"Failed to query events: {e}")
                return []

    def query_traffic(self, where: Optional[str] = None, params: tuple = ()) -> List[Dict[str, Any]]:
        """
        Query traffic table with optional WHERE clause.
        Returns a list of dicts.
        """
        with self.lock, self.conn:
            try:
                sql = 'SELECT * FROM traffic'
                if where:
                    sql += f' WHERE {where}'
                cur = self.conn.execute(sql, params)
                return [dict(row) for row in cur.fetchall()]
            except Exception as e:
                self.logger.error(f"Failed to query traffic: {e}")
                return []

    def close(self):
        """
        Close the database connection.
        """
        with self.lock:
            self.conn.close()

if __name__ == "__main__":
    import argparse
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description="Database Handler Test")
    parser.add_argument('--db', type=str, default=DEFAULT_DB_PATH, help='SQLite DB file')
    parser.add_argument('--show-devices', action='store_true', help='Show all device records')
    parser.add_argument('--show-events', action='store_true', help='Show all event records')
    parser.add_argument('--show-traffic', action='store_true', help='Show all traffic records')
    args = parser.parse_args()
    db = DatabaseHandler(args.db)
    if args.show_devices:
        print("Devices:", db.query_devices())
    if args.show_events:
        print("Events:", db.query_events())
    if args.show_traffic:
        print("Traffic:", db.query_traffic())
    db.close()
