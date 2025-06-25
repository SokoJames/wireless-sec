import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QTabWidget, QTextEdit, QListWidget, QCheckBox, QFileDialog, QMessageBox, QTableWidget, QTableWidgetItem, QHeaderView, QDialog, QFormLayout, QLineEdit, QGroupBox, QSpacerItem, QSizePolicy
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal

# Import core modules (assume all are in PYTHONPATH)
from packet_capture import PacketCapture
from device_tracker import DeviceTracker
from phase2.feature_extractor import FeatureExtractor
from phase2.statistics_engine import StatisticsEngine
from phase2.pattern_analyzer import PatternAnalyzer
from phase2.traffic_classifier import TrafficClassifier
from phase3.anomaly_detector import AnomalyDetector
from phase3.attack_detector import AttackDetector
from phase3.intrusion_detector import IntrusionDetector
from phase3.alert_manager import AlertManager
from database_handler import DatabaseHandler
from utils import color_text, TRAFFIC_COLOR_MAP

class PacketCaptureThread(QThread):
    packet_captured = pyqtSignal(str)
    capture_stopped = pyqtSignal()

    def __init__(self, interface, verbose=False):
        super().__init__()
        self.interface = interface
        self.verbose = verbose
        self._stop = False

    def run(self):
        pc = PacketCapture({"interface": self.interface})
        pc.start_live_capture()
        while not self._stop:
            pkt = pc.get_packet(timeout=2)
            if pkt:
                self.packet_captured.emit(pkt.summary())
        pc.stop()
        self.capture_stopped.emit()

    def stop(self):
        self._stop = True

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.module_checks = {}  # Ensure this is initialized before any setup_* methods
        self.setWindowTitle("Wi-Fi Traffic Analyzer - Desktop UI")
        self.setGeometry(100, 100, 1000, 700)
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        # --- Phase2 analytics modules ---
        self.feature_extractor = FeatureExtractor()
        self.traffic_classifier = TrafficClassifier()
        self.statistics_engine = StatisticsEngine()
        self.pattern_analyzer = PatternAnalyzer()
        # --- Track all seen traffic classes this session ---
        self.seen_traffic_classes = set()

        # --- Tab widgets must be created before setup ---
        self.capture_tab = QWidget()
        self.watcher_tab = QWidget()
        self.modules_tab = QWidget()
        self.offline_tab = QWidget()
        self.device_tab = QWidget()

        self.setup_capture_tab()
        self.setup_watcher_tab()
        self.setup_modules_tab()
        self.setup_offline_tab()
        self.setup_device_tab()

        # --- Modern header navigation (horizontal tabs at the top) ---
        self.tabs = QTabWidget()
        self.tabs.setTabPosition(QTabWidget.North)
        self.setCentralWidget(self.tabs)
        self.tabs.addTab(self.capture_tab, " Packet Capture")
        self.tabs.addTab(self.watcher_tab, " Watcher")
        self.tabs.addTab(self.modules_tab, " Modules")
        self.tabs.addTab(self.offline_tab, " Offline Analysis")
        self.tabs.addTab(self.device_tab, " Device Management")
        # Tooltips for clarity
        self.tabs.setTabToolTip(0, "Capture live packets from your Wi-Fi interface")
        self.tabs.setTabToolTip(1, "Live analysis feed from all enabled modules")
        self.tabs.setTabToolTip(2, "Enable or disable analysis modules")
        self.tabs.setTabToolTip(3, "Analyze PCAP files offline with all modules")
        self.tabs.setTabToolTip(4, "Manage trusted devices and run intrusion detection")
        # --- Header/tab bar style ---
        self.tabs.setStyleSheet("")

    def setup_watcher_tab(self):
        layout = QVBoxLayout()
        header = QLabel("Watcher (Live Analysis)")
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet("font-size: 16px; font-weight: normal; color: black; margin: 16px 0;")
        layout.addWidget(header)
        group = QGroupBox()
        group.setStyleSheet("QGroupBox { border: 1px solid #cccccc; border-radius: 0px; margin-top: 8px; }")
        group_layout = QVBoxLayout()
        table_label = QLabel("Live Analysis Output:")
        table_label.setAlignment(Qt.AlignLeft)
        table_label.setStyleSheet("font-size: 13px; font-weight: normal; margin: 8px 0;")
        group_layout.addWidget(table_label)
        self.watcher_columns = ["No.", "Summary", "Traffic Type", "Confidence", "Patterns/Anomaly", "Time"]
        self.watcher_output = QTableWidget(0, len(self.watcher_columns))
        self.watcher_output.setHorizontalHeaderLabels(self.watcher_columns)
        self.watcher_output.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.watcher_output.setAlternatingRowColors(True)
        self.watcher_output.setShowGrid(False)
        self.watcher_output.setStyleSheet("")
        self.watcher_output.verticalHeader().setDefaultSectionSize(32)
        self.watcher_output.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        group_layout.addWidget(self.watcher_output)
        group.setLayout(group_layout)
        layout.addWidget(group)
        layout.addStretch()
        self.watcher_tab.setLayout(layout)

    def setup_offline_tab(self):
        layout = QVBoxLayout()
        header = QLabel("Offline PCAP Analysis")
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet("font-size: 16px; font-weight: normal; color: black; margin: 16px 0;")
        layout.addWidget(header)
        group = QGroupBox()
        group.setStyleSheet("QGroupBox { border: 1px solid #cccccc; border-radius: 0px; margin-top: 8px; }")
        group_layout = QVBoxLayout()
        file_row = QHBoxLayout()
        self.offline_file_label = QLabel("Select PCAP File:")
        self.offline_file_label.setStyleSheet("font-size: 12px; font-weight: normal;")
        self.offline_file_input = QLineEdit()
        self.offline_file_input.setStyleSheet("QLineEdit { border-radius: 0px; font-size: 14px; padding: 4px; }")
        self.offline_file_btn = QPushButton("Browse...")
        self.offline_file_btn.setStyleSheet("QPushButton { border-radius: 0px; font-size: 12px; padding: 8px 18px; font-weight: normal; } QPushButton:focus { border: 2px solid #00eaff; }")
        file_row.addWidget(self.offline_file_label)
        file_row.addWidget(self.offline_file_input)
        file_row.addWidget(self.offline_file_btn)
        group_layout.addLayout(file_row)
        self.offline_analyze_btn = QPushButton("Analyze File")
        self.offline_analyze_btn.setStyleSheet("QPushButton { border-radius: 0px; font-size: 12px; padding: 8px 18px; font-weight: normal; } QPushButton:focus { border: 2px solid #00eaff; }")
        group_layout.addWidget(self.offline_analyze_btn)
        group.setLayout(group_layout)
        layout.addWidget(group)
        layout.addSpacing(12)
        table_label = QLabel("Offline Analysis Results:")
        table_label.setAlignment(Qt.AlignLeft)
        table_label.setStyleSheet("font-size: 13px; font-weight: normal; margin: 8px 0;")
        layout.addWidget(table_label)
        self.offline_results_table = QTableWidget(0, 5)
        self.offline_results_table.setHorizontalHeaderLabels(["No.", "Summary", "Type", "Module", "Time"])
        self.offline_results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.offline_results_table.setAlternatingRowColors(True)
        self.offline_results_table.setShowGrid(False)
        self.offline_results_table.setStyleSheet("")
        self.offline_results_table.verticalHeader().setDefaultSectionSize(32)
        self.offline_results_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        layout.addWidget(self.offline_results_table)
        export_row = QHBoxLayout()
        self.offline_export_csv_btn = QPushButton("Export CSV")
        self.offline_export_json_btn = QPushButton("Export JSON")
        for btn in [self.offline_export_csv_btn, self.offline_export_json_btn]:
            btn.setStyleSheet("QPushButton { border-radius: 0px; font-size: 12px; padding: 8px 18px; font-weight: normal; } QPushButton:focus { border: 2px solid #00eaff; }")
        export_row.addWidget(self.offline_export_csv_btn)
        export_row.addWidget(self.offline_export_json_btn)
        export_row.addStretch()
        layout.addLayout(export_row)
        layout.addStretch()
        self.offline_tab.setLayout(layout)
        self.offline_file_btn.clicked.connect(self.browse_offline_file)
        self.offline_analyze_btn.clicked.connect(self.run_offline_analysis)
        self.offline_export_csv_btn.clicked.connect(self.export_offline_csv)
        self.offline_export_json_btn.clicked.connect(self.export_offline_json)

    def browse_offline_file(self):
        fname, _ = QFileDialog.getOpenFileName(self, "Select PCAP File", "", "PCAP Files (*.pcap *.cap)")
        if fname:
            self.offline_file_input.setText(fname)

    def run_offline_analysis(self):
        # TODO: Implement real analysis pipeline for PCAP file
        import scapy.all as scapy
        from datetime import datetime
        pcap_path = self.offline_file_input.text().strip()
        if not pcap_path:
            QMessageBox.warning(self, "No File", "Please select a PCAP file.")
            return
        try:
            packets = scapy.rdpcap(pcap_path)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to read PCAP: {e}")
            return
        self.offline_results_table.setRowCount(0)
        enabled = [name for name, cb in self.module_checks.items() if cb.isChecked()]
        # Dynamically set columns based on enabled modules
        base_cols = ["No.", "Summary", "Type", "Module", "Time"]
        findings_cols = []
        if 'Anomaly Detector' in enabled:
            findings_cols.append("Anomaly")
        if 'Attack Detector' in enabled:
            findings_cols.append("Attack")
        if 'Traffic Classifier' in enabled:
            findings_cols.append("Classification")
        if 'Intrusion Detector' in enabled:
            findings_cols.append("Intrusion")
        columns = base_cols + findings_cols
        self.offline_results_table.setColumnCount(len(columns))
        self.offline_results_table.setHorizontalHeaderLabels(columns)
        # Use the real analysis pipeline for each packet
        from phase2.feature_extractor import FeatureExtractor
        from phase2.statistics_engine import StatisticsEngine
        from phase2.pattern_analyzer import PatternAnalyzer
        from phase2.traffic_classifier import TrafficClassifier
        from phase3.anomaly_detector import AnomalyDetector
        from phase3.attack_detector import AttackDetector
        from phase3.intrusion_detector import IntrusionDetector
        from device_tracker import DeviceTracker
        fe = FeatureExtractor()
        se = StatisticsEngine()
        pa = PatternAnalyzer()
        tc = TrafficClassifier()
        ad = AnomalyDetector()
        atk = AttackDetector()
        idet = IntrusionDetector()
        dt = DeviceTracker()
        seen_devices = set()
        trusted_macs = getattr(self, 'trusted_macs', set())
        for i, pkt in enumerate(packets):
            summary = pkt.summary()
            # Parse MACs
            import re
            macs = re.findall(r'([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})', summary)
            src_mac = macs[0].lower() if macs else None
            dst_mac = macs[1].lower() if len(macs) > 1 else None
            new_device_alert = ''
            if src_mac and src_mac not in trusted_macs and src_mac not in seen_devices:
                new_device_alert = 'new/unknown device found'
                seen_devices.add(src_mac)
            pkt_features = {'src_mac': src_mac, 'dst_mac': dst_mac, 'timestamp': None}
            pkt_features = fe.extract_packet_features(summary) if hasattr(fe, 'extract_packet_features') else pkt_features
            dt.process_packet(pkt) if hasattr(dt, 'process_packet') else None
            stats = None
            stats = se.compute_stats(None) if hasattr(se, 'compute_stats') else None
            pattern = pa.analyze_behavior(stats) if hasattr(pa, 'analyze_behavior') and stats else None
            traffic_type = 'unknown'
            classification = ''
            if 'Traffic Classifier' in enabled and stats:
                traffic_type = tc.classify(stats) if hasattr(tc, 'classify') else 'unknown'
                classification = traffic_type
            if new_device_alert:
                classification = new_device_alert
                traffic_type = 'unknown'
            anomaly = ''
            if 'Anomaly Detector' in enabled and stats:
                res = ad.check_traffic_anomaly(stats) if hasattr(ad, 'check_traffic_anomaly') else None
                if res:
                    anomaly = res.get('type', str(res))
            attack = ''
            if 'Attack Detector' in enabled and pkt_features:
                device_info = getattr(dt, 'device_registry', {}).get(pkt_features.get('src_mac'), {})
                events = device_info.get('events', []) if device_info else []
                alerts = []
                if hasattr(atk, 'detect_deauth_attack'):
                    alerts += [atk.detect_deauth_attack(events)]
                if hasattr(atk, 'detect_disassoc_attack'):
                    alerts += [atk.detect_disassoc_attack(events)]
                alerts = [a for a in alerts if a]
                if alerts:
                    attack = ', '.join(a.get('type', str(a)) for a in alerts)
            intrusion = ''
            if 'Intrusion Detector' in enabled:
                all_alerts = []
                if anomaly: all_alerts.append({'type': anomaly})
                if attack: all_alerts.append({'type': attack})
                if new_device_alert: all_alerts.append({'type': new_device_alert})
                res = idet.run_batch(all_alerts) if hasattr(idet, 'run_batch') else None
                if res:
                    intrusion = res.get('type', str(res))
            time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            module_used = ','.join(enabled)
            row = [i+1, summary, traffic_type, module_used, time_str]
            findings_map = {'Anomaly': anomaly, 'Attack': attack, 'Classification': classification, 'Intrusion': intrusion}
            for col_name in columns[5:]:
                row.append(findings_map.get(col_name, ''))
            self.offline_results_table.insertRow(self.offline_results_table.rowCount())
            for col, val in enumerate(row):
                item = QTableWidgetItem(str(val))
                if col == 2:
                    color = TRAFFIC_COLOR_MAP.get(traffic_type, None)
                    if color:
                        item.setForeground(Qt.red if traffic_type == 'attack' else Qt.blue if traffic_type == 'browsing' else Qt.darkMagenta if traffic_type == 'streaming' else Qt.darkYellow if traffic_type == 'anomaly' else Qt.darkGreen if traffic_type == 'normal' else Qt.black)
                self.offline_results_table.setItem(self.offline_results_table.rowCount()-1, col, item)

    def export_offline_csv(self):
        from PyQt5.QtWidgets import QFileDialog
        path, _ = QFileDialog.getSaveFileName(self, "Export CSV", "offline_analysis.csv", "CSV Files (*.csv)")
        if not path:
            return
        import csv
        with open(path, 'w', newline='') as f:
            writer = csv.writer(f)
            headers = [self.offline_results_table.horizontalHeaderItem(i).text() for i in range(self.offline_results_table.columnCount())]
            writer.writerow(headers)
            for row in range(self.offline_results_table.rowCount()):
                writer.writerow([self.offline_results_table.item(row, col).text() if self.offline_results_table.item(row, col) else '' for col in range(self.offline_results_table.columnCount())])

    def export_offline_json(self):
        from PyQt5.QtWidgets import QFileDialog
        path, _ = QFileDialog.getSaveFileName(self, "Export JSON", "offline_analysis.json", "JSON Files (*.json)")
        if not path:
            return
        import json
        data = []
        headers = [self.offline_results_table.horizontalHeaderItem(i).text() for i in range(self.offline_results_table.columnCount())]
        for row in range(self.offline_results_table.rowCount()):
            entry = {headers[col]: self.offline_results_table.item(row, col).text() if self.offline_results_table.item(row, col) else '' for col in range(self.offline_results_table.columnCount())}
            data.append(entry)
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)

        # Device Management/Intrusion Tab
        self.device_tab = QWidget()
        self.tabs.addTab(self.device_tab, "Device Management / Intrusion Detection")
        self.trusted_macs = set()  # Ensure this is initialized before loading trusted devices
        self.setup_device_tab()

        # Modules Tab
        self.modules_tab = QWidget()
        # Add the tab after Watcher for workflow clarity
        self.tabs.insertTab(2, self.modules_tab, " Modules")
        self.setup_modules_tab()

        # Output area
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.statusBar().addPermanentWidget(QLabel("Ready"))

    def setup_capture_tab(self):
        layout = QVBoxLayout()
        header = QLabel("Packet Capture")
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet("font-size: 16px; font-weight: normal; color: black; margin: 16px 0;")
        layout.addWidget(header)
        group = QGroupBox()
        group_layout = QVBoxLayout()
        self.capture_interface_label = QLabel("Interface:")
        self.capture_interface_label.setAlignment(Qt.AlignLeft)
        self.capture_interface_input = QTextEdit("wlan0")
        self.capture_interface_input.setFixedHeight(30)
        self.capture_start_btn = QPushButton("Start Capture")
        self.capture_stop_btn = QPushButton("Stop Capture")
        self.capture_verbose = QCheckBox("Verbose Output")
        # --- Enhanced columns for analytics ---
        self.capture_output = QTableWidget(0, 6)
        self.capture_output.setHorizontalHeaderLabels(["No.", "Summary", "Traffic Type", "Confidence", "Patterns/Anomaly", "Time"])
        self.capture_output.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.capture_output.setAlternatingRowColors(True)
        self.capture_output.setShowGrid(False)
        self.capture_output.setStyleSheet("")

        self.capture_output.verticalHeader().setDefaultSectionSize(32)
        self.capture_output.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        group_layout.addWidget(self.capture_interface_label)
        group_layout.addWidget(self.capture_interface_input)
        group_layout.addWidget(self.capture_verbose)
        btn_row = QHBoxLayout()
        btn_row.addWidget(self.capture_start_btn)
        btn_row.addWidget(self.capture_stop_btn)
        btn_row.addStretch()
        group_layout.addLayout(btn_row)
        group_layout.addWidget(self.capture_output)
        group.setLayout(group_layout)
        layout.addWidget(group)
        self.capture_output.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        layout.addWidget(self.capture_output)
        layout.addStretch()
        self.capture_tab.setLayout(layout)
        self.capture_start_btn.clicked.connect(self.start_capture)
        self.capture_stop_btn.clicked.connect(self.stop_capture)
        self.capture_thread = None

    def setup_device_tab(self):
        # --- Main layout: horizontal split ---
        main_layout = QHBoxLayout()

        # --- Left: Tracked Devices & Intrusion Detection (full height) ---
        left_col = QVBoxLayout()
        tracked_group = QGroupBox("Tracked Devices & Intrusion Detection")
        tracked_layout = QVBoxLayout()
        tracked_layout.addWidget(QLabel("Tracked Devices:"))
        self.device_list = QListWidget()
        tracked_layout.addWidget(self.device_list)
        btn_row = QHBoxLayout()
        self.refresh_devices_btn = QPushButton("Refresh Devices")
        self.intrusion_btn = QPushButton("Run Intrusion Detection")
        btn_row.addWidget(self.refresh_devices_btn)
        btn_row.addWidget(self.intrusion_btn)
        tracked_layout.addLayout(btn_row)
        tracked_layout.addWidget(QLabel("Intrusion Detection Output:"))
        self.device_output = QTextEdit()
        self.device_output.setReadOnly(True)
        tracked_layout.addWidget(self.device_output)
        tracked_group.setLayout(tracked_layout)
        tracked_group.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.device_list.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.device_output.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        left_col.addWidget(tracked_group, stretch=1)
        left_col.addStretch()

        # --- Right: vertical stack of three group boxes ---
        right_col = QVBoxLayout()

        # Trusted Devices (top)
        trusted_group = QGroupBox("Trusted Devices")
        trusted_layout = QVBoxLayout()
        trusted_layout.setSpacing(4)
        trusted_layout.setContentsMargins(6, 6, 6, 6)
        self.trusted_list = QListWidget()
        self.trusted_list.setMaximumHeight(90)
        trusted_layout.addWidget(self.trusted_list)
        trusted_layout.addWidget(QLabel("Add Trusted Device:"))
        trusted_form = QHBoxLayout()
        trusted_form.setSpacing(4)
        self.trusted_mac_input = QTextEdit()
        self.trusted_mac_input.setPlaceholderText("MAC Address")
        self.trusted_mac_input.setFixedHeight(26)
        self.trusted_name_input = QTextEdit()
        self.trusted_name_input.setPlaceholderText("Device Name")
        self.trusted_name_input.setFixedHeight(26)
        trusted_form.addWidget(self.trusted_mac_input)
        trusted_form.addWidget(self.trusted_name_input)
        trusted_layout.addLayout(trusted_form)
        self.add_trusted_btn = QPushButton("Add Trusted Device")
        self.add_trusted_btn.setFixedHeight(26)
        self.add_trusted_btn.clicked.connect(self.add_trusted_device)
        trusted_layout.addWidget(self.add_trusted_btn)
        trusted_group.setLayout(trusted_layout)
        trusted_group.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        trusted_group.setMaximumHeight(180)
        right_col.addWidget(trusted_group)
        right_col.addSpacing(6)

        # Unknown Devices (middle)
        unknown_group = QGroupBox("Unknown Devices (Flagged)")
        unknown_layout = QVBoxLayout()
        unknown_layout.setSpacing(4)
        unknown_layout.setContentsMargins(6, 6, 6, 6)
        unknown_layout.addWidget(QLabel("Unknown/Untrusted Devices Detected:"))
        self.unknown_list = QListWidget()
        self.unknown_list.setMaximumHeight(70)
        unknown_layout.addWidget(self.unknown_list)
        btn_row2 = QHBoxLayout()
        btn_row2.setSpacing(4)
        self.deauth_btn = QPushButton("Deauth Selected")
        self.deauth_btn.setFixedHeight(24)
        self.deauth_btn.clicked.connect(self.start_deauth)
        self.stop_deauth_btn = QPushButton("Stop Deauth")
        self.stop_deauth_btn.setFixedHeight(24)
        self.stop_deauth_btn.clicked.connect(self.stop_deauth)
        self.allow_btn = QPushButton("Allow (Add to Trusted)")
        self.allow_btn.setFixedHeight(24)
        self.allow_btn.clicked.connect(self.allow_device)
        btn_row2.addWidget(self.deauth_btn)
        btn_row2.addWidget(self.stop_deauth_btn)
        btn_row2.addWidget(self.allow_btn)
        unknown_layout.addLayout(btn_row2)
        unknown_group.setLayout(unknown_layout)
        unknown_group.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        unknown_group.setMaximumHeight(130)
        right_col.addWidget(unknown_group)
        right_col.addSpacing(6)

        # Training Data (bottom)
        training_group = QGroupBox("Training Data Management")
        training_layout = QVBoxLayout()
        training_layout.setSpacing(4)
        training_layout.setContentsMargins(6, 6, 6, 6)
        training_layout.addWidget(QLabel("Add Device to Training Data:"))
        training_form = QHBoxLayout()
        training_form.setSpacing(4)
        self.training_mac_input = QTextEdit()
        self.training_mac_input.setPlaceholderText("MAC Address")
        self.training_mac_input.setFixedHeight(26)
        self.training_label_input = QTextEdit()
        self.training_label_input.setPlaceholderText("Label (e.g. device type)")
        self.training_label_input.setFixedHeight(26)
        training_form.addWidget(self.training_mac_input)
        training_form.addWidget(self.training_label_input)
        training_layout.addLayout(training_form)
        self.add_training_btn = QPushButton("Add to Training Data")
        self.add_training_btn.setFixedHeight(26)
        self.add_training_btn.clicked.connect(self.add_training_device)
        training_layout.addWidget(self.add_training_btn)
        training_layout.addWidget(QLabel("Training Devices:"))
        self.training_list = QListWidget()
        self.training_list.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        training_layout.addWidget(self.training_list)
        self.remove_training_btn = QPushButton("Remove from Training Data")
        self.remove_training_btn.setFixedHeight(26)
        self.remove_training_btn.clicked.connect(self.remove_training_device)
        training_layout.addWidget(self.remove_training_btn)
        training_group.setLayout(training_layout)
        training_group.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        right_col.addWidget(training_group, stretch=2)
        right_col.addStretch()

        main_layout.addLayout(left_col, 2)
        main_layout.addSpacing(24)
        main_layout.addLayout(right_col, 3)
        main_layout.setStretch(0, 2)
        main_layout.setStretch(2, 3)
        self.device_tab.setLayout(main_layout)

        self.refresh_devices_btn.clicked.connect(self.refresh_devices)
        self.intrusion_btn.clicked.connect(self.run_intrusion_detection)
        self.load_trusted_devices()
        self.load_training_devices()
        # Track deauth threads
        self._deauth_threads = {}
        self._flagged_macs = set()

    def setup_modules_tab(self):
        layout = QVBoxLayout()
        header = QLabel("Enable/Disable Analysis Modules")
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet("font-size: 16px; font-weight: normal; color: black; margin: 16px 0;")
        layout.addWidget(header)
        group = QGroupBox()
        group.setStyleSheet("QGroupBox { border: 1px solid #cccccc; border-radius: 0px; margin-top: 8px; }")
        group_layout = QVBoxLayout()
        module_names = [
            ("Packet Capture", True),
            ("Device Tracker", False),
            ("Feature Extractor", False),
            ("Statistics Engine", False),
            ("Pattern Analyzer", False),
            ("Traffic Classifier", False),
            ("Anomaly Detector", False),
            ("Attack Detector", False),
            ("Intrusion Detector", False),
            ("Alert Manager", False),
            ("Database Handler", False),
        ]
        for name, checked in module_names:
            cb = QCheckBox(name)
            cb.setChecked(checked)
            cb.setStyleSheet("QCheckBox { font-size: 12px; padding: 6px; }")
            cb.stateChanged.connect(self.update_watcher_modules)
            group_layout.addWidget(cb)
            self.module_checks[name] = cb
        group.setLayout(group_layout)
        layout.addWidget(group)
        layout.addStretch()
        self.modules_tab.setLayout(layout)

    def update_watcher_modules(self):
        # Called when module checkboxes change; update watcher tab accordingly
        enabled = [name for name, cb in self.module_checks.items() if cb.isChecked()]
        # Dynamically update columns for findings from active modules
        base_cols = ["No.", "Summary", "Type", "Module", "Time"]
        findings_cols = []
        if 'Anomaly Detector' in enabled:
            findings_cols.append("Anomaly")
        if 'Attack Detector' in enabled:
            findings_cols.append("Attack")
        if 'Traffic Classifier' in enabled:
            findings_cols.append("Classification")
        if 'Intrusion Detector' in enabled:
            findings_cols.append("Intrusion")
        self.watcher_columns = base_cols + findings_cols
        self.watcher_output.setColumnCount(len(self.watcher_columns))
        self.watcher_output.setHorizontalHeaderLabels(self.watcher_columns)
        self.update_watcher_status()

    def start_capture(self):
        interface = self.capture_interface_input.toPlainText().strip()
        verbose = self.capture_verbose.isChecked()
        if not interface:
            QMessageBox.warning(self, "Input Error", "Please specify an interface.")
            return
        self.capture_output.clear()
        self.capture_start_btn.setEnabled(False)
        self.capture_stop_btn.setEnabled(True)
        self.capture_thread = PacketCaptureThread(interface, verbose)
        self.capture_thread.packet_captured.connect(self.display_packet)
        self.capture_thread.packet_captured.connect(self.watcher_packet)
        self.capture_thread.capture_stopped.connect(self.capture_finished)
        self.capture_thread.start()
        self.statusBar().showMessage(f"Capturing on {interface}...")

    def stop_capture(self):
        if self.capture_thread:
            self.capture_thread.stop()
            self.capture_thread.wait()

    def watcher_packet(self, summary):
        print("[Watcher] Received packet:", summary)
        from datetime import datetime
        traffic_type = ""
        confidence = ""
        patterns = ""
        time_str = None
        try:
            import scapy.all as scapy
            pkt = None
            try:
                pkt = scapy.Ether(bytes.fromhex(summary)) if isinstance(summary, str) and len(summary) > 32 else None
            except Exception:
                pkt = None
            if pkt is None:
                pkt = summary
            features = self.feature_extractor.extract_packet_features(pkt)
            # --- Timestamp fix ---
            pkt_time = features.get('timestamp')
            if pkt_time:
                try:
                    time_str = datetime.fromtimestamp(float(pkt_time)).strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            else:
                time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            label, details = self.traffic_classifier.classify_packet_realtime(pkt)
            # --- Robust class display ---
            if label and not str(label).startswith("ERROR"):
                traffic_type = label
            else:
                traffic_type = "Unknown"
            # Track and print all seen classes
            self.seen_traffic_classes.add(traffic_type)
            print(f"[Classifier] Traffic classes seen so far: {self.seen_traffic_classes}")
            confidence = f"{details.get('confidence', ''):.2f}" if details.get('confidence') is not None else ""
            patterns = ""
            try:
                pattern_result = self.pattern_analyzer.analyze_behavior({'packet_sizes':[features.get('size',0)], 'directions':[]})
                if pattern_result.get('size_is_bursty'): patterns += "Bursty; "
                if pattern_result.get('isolation_anomaly'): patterns += "Anomaly; "
                if 'frequent_sizes' in pattern_result and pattern_result['frequent_sizes']: patterns += "FreqSz; "
            except Exception as e:
                patterns = f"PatternErr: {e}"
            flow_id = features.get('src_mac', 'unknown')
            self.statistics_engine.add_packet(flow_id, features)
        except Exception as e:
            traffic_type = f"ERROR: {e}"
            time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        row = [self.watcher_output.rowCount() + 1, summary, traffic_type, confidence, patterns, time_str]
        self.watcher_output.insertRow(self.watcher_output.rowCount())
        for col, val in enumerate(row):
            item = QTableWidgetItem(str(val))
            self.watcher_output.setItem(self.watcher_output.rowCount()-1, col, item)
        self.monitor_mac_addresses(summary)


    def display_packet(self, summary):
        print("[Capture] Received packet:", summary)
        from datetime import datetime
        traffic_type = ""
        confidence = ""
        patterns = ""
        time_str = None
        try:
            import scapy.all as scapy
            pkt = None
            try:
                pkt = scapy.Ether(bytes.fromhex(summary)) if isinstance(summary, str) and len(summary) > 32 else None
            except Exception:
                pkt = None
            if pkt is None:
                pkt = summary
            features = self.feature_extractor.extract_packet_features(pkt)
            label, details = self.traffic_classifier.classify_packet_realtime(pkt)
            # --- Robust class display ---
            if label and not str(label).startswith("ERROR"):
                traffic_type = label
            else:
                traffic_type = "Unknown"
            # Track and print all seen classes
            self.seen_traffic_classes.add(traffic_type)
            print(f"[Classifier] Traffic classes seen so far: {self.seen_traffic_classes}")
            confidence = f"{details.get('confidence', ''):.2f}" if details.get('confidence') is not None else ""
            patterns = ""
            try:
                pattern_result = self.pattern_analyzer.analyze_behavior({'packet_sizes':[features.get('size',0)], 'directions':[]})
                if pattern_result.get('size_is_bursty'): patterns += "Bursty; "
                if pattern_result.get('isolation_anomaly'): patterns += "Anomaly; "
                if 'frequent_sizes' in pattern_result and pattern_result['frequent_sizes']: patterns += "FreqSz; "
            except Exception as e:
                patterns = f"PatternErr: {e}"
            flow_id = features.get('src_mac', 'unknown')
            self.statistics_engine.add_packet(flow_id, features)
            pkt_time = features.get('timestamp')
            if pkt_time:
                try:
                    time_str = datetime.fromtimestamp(float(pkt_time)).strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            else:
                time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        except Exception as e:
            traffic_type = f"ERROR: {e}"
            time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        row = [self.capture_output.rowCount() + 1, summary, traffic_type, confidence, patterns, time_str]
        self.capture_output.insertRow(self.capture_output.rowCount())
        for col, val in enumerate(row):
            item = QTableWidgetItem(str(val))
            self.capture_output.setItem(self.capture_output.rowCount()-1, col, item)
        self.monitor_mac_addresses(summary)


    def update_watcher_status(self):
        # Optionally update watcher tab UI to reflect current enabled modules
        enabled = [name for name, cb in self.module_checks.items() if cb.isChecked()]
        self.watcher_output.insertRow(self.watcher_output.rowCount())
        item = QTableWidgetItem(f"[Modules updated] Now enabled: {', '.join(enabled)}")
        self.watcher_output.setItem(self.watcher_output.rowCount()-1, 0, item)

    def capture_finished(self):
        self.statusBar().showMessage("Capture finished.")

    def refresh_devices(self):
        dt = DeviceTracker()
        # Example: For demo, just show keys (MACs) if available
        self.device_list.clear()
        for mac in getattr(dt, 'device_registry', {}).keys():
            self.device_list.addItem(mac)
        self.device_output.append("Devices refreshed.")

    def run_intrusion_detection(self):
        dt = DeviceTracker()
        idet = IntrusionDetector()
        # Demo: Run on empty or loaded alerts
        alerts = []  # In real use, load from alert manager or DB
        result = idet.run_batch(alerts)
        self.device_output.append(f"Intrusion Detection Result:\n{result}")

    def add_training_device(self):
        import os
        import csv
        mac = self.training_mac_input.toPlainText().strip()
        label = self.training_label_input.toPlainText().strip()
        if not mac or not label:
            QMessageBox.warning(self, "Input Error", "Please enter both MAC address and label.")
            return
        # Ensure training_data directory exists
        td_dir = os.path.join(os.path.dirname(__file__), 'training_data')
        os.makedirs(td_dir, exist_ok=True)
        td_file = os.path.join(td_dir, 'training_devices.csv')
        from datetime import datetime
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        # Append to CSV
        with open(td_file, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([mac, label, now])
        self.training_mac_input.clear()
        self.training_label_input.clear()
        QMessageBox.information(self, "Added", f"Device {mac} ({label}) added to training data.")
        self.load_training_devices()

    def load_training_devices(self):
        """Load and display all training devices from training_devices.csv."""
        import os
        import csv
        self.training_list.clear()
        td_file = os.path.join(os.path.dirname(__file__), 'training_data', 'training_devices.csv')
        if not os.path.exists(td_file):
            return
        with open(td_file, 'r', newline='') as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) >= 2:
                    mac, label = row[:2]
                    self.training_list.addItem(f"{mac} | {label}")

    def remove_training_device(self):
        """Remove selected device from training_devices.csv and update list."""
        import os
        import csv
        td_file = os.path.join(os.path.dirname(__file__), 'training_data', 'training_devices.csv')
        selected = self.training_list.currentRow()
        if selected < 0:
            QMessageBox.warning(self, "No Selection", "Please select a device to remove.")
            return
        # Read all entries
        entries = []
        with open(td_file, 'r', newline='') as f:
            reader = csv.reader(f)
            entries = list(reader)
        # Remove selected
        if selected < len(entries):
            removed = entries.pop(selected)
            with open(td_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerows(entries)
            self.load_training_devices()
            QMessageBox.information(self, "Removed", f"Removed device: {removed[0]} | {removed[1]}")

    # --- Deauth Logic ---
    def start_deauth(self):
        import threading
        from scapy.all import RadioTap, Dot11, sendp
        selected = self.unknown_list.currentItem()
        if not selected:
            QMessageBox.warning(self, "No Selection", "Select a MAC to deauth.")
            return
        mac = selected.text()
        if mac in self._deauth_threads:
            QMessageBox.information(self, "Already Running", f"Deauth already running for {mac}")
            return
        def deauth_loop():
            iface = self.capture_interface_input.toPlainText().strip() or 'wlan0'
            self.device_output.append(f"[Deauth] Sending deauth to {mac} on {iface}...")
            pkt = RadioTap()/Dot11(addr1=mac, addr2='ff:ff:ff:ff:ff:ff', addr3='ff:ff:ff:ff:ff:ff')
            try:
                while mac in self._deauth_threads:
                    sendp(pkt, iface=iface, count=10, inter=0.1, verbose=0)
            except Exception as e:
                self.device_output.append(f"[Deauth ERROR] {e}")
        t = threading.Thread(target=deauth_loop, daemon=True)
        self._deauth_threads[mac] = t
        t.start()
        self.device_output.append(f"[Deauth] Started for {mac}")

    def stop_deauth(self):
        selected = self.unknown_list.currentItem()
        if not selected:
            QMessageBox.warning(self, "No Selection", "Select a MAC to stop deauth.")
            return
        mac = selected.text()
        if mac in self._deauth_threads:
            del self._deauth_threads[mac]
            self.device_output.append(f"[Deauth] Stopped for {mac}")
        else:
            QMessageBox.information(self, "Not Running", f"No deauth running for {mac}")

    def allow_device(self):
        selected = self.unknown_list.currentItem()
        if not selected:
            QMessageBox.warning(self, "No Selection", "Select a MAC to allow.")
            return
        mac = selected.text()
        # Add to trusted devices file
        import os
        trusted_path = os.path.join(os.path.dirname(__file__), 'trusted_devices')
        with open(trusted_path, 'a') as f:
            f.write(f"{mac} | Allowed via UI\n")
        self.trusted_macs.add(mac)
        self.device_output.append(f"[ALLOW] {mac} added to trusted devices.")
        self.load_trusted_devices()
        # Remove from unknowns if present
        for i in range(self.unknown_list.count()-1, -1, -1):
            if self.unknown_list.item(i).text() == mac:
                self.unknown_list.takeItem(i)
                if mac in self._flagged_macs:
                    self._flagged_macs.remove(mac)

    def show_module_settings(self, module_name):
        dlg = QDialog(self)
        dlg.setWindowTitle(f"Settings: {module_name}")
        layout = QFormLayout()
        # Example: Show/edit settings for each module
        settings = self.module_settings.get(module_name, {})
        # For demo, show 2 generic parameters
        param1 = QLineEdit(str(settings.get('param1', '')))
        param2 = QLineEdit(str(settings.get('param2', '')))
        layout.addRow("Parameter 1", param1)
        layout.addRow("Parameter 2", param2)
        save_btn = QPushButton("Save")
        save_btn.clicked.connect(lambda: self.save_module_settings(module_name, param1.text(), param2.text(), dlg))
        layout.addWidget(save_btn)
        dlg.setLayout(layout)
        dlg.exec_()

    def save_module_settings(self, module_name, param1, param2, dlg):
        self.module_settings[module_name]['param1'] = param1
        self.module_settings[module_name]['param2'] = param2

    def load_trusted_devices(self):
        import os
        self.trusted_list.clear()
        trusted_path = os.path.join(os.path.dirname(__file__), 'trusted_devices')
        if not os.path.exists(trusted_path):
            return
        with open(trusted_path, 'r') as f:
            for line in f:
                mac_name = line.strip()
                if mac_name:
                    self.trusted_list.addItem(mac_name)
        # Also update trusted_macs set
        self.trusted_macs = set()
        with open(trusted_path, 'r') as f:
            for line in f:
                mac = line.strip().split('|')[0].strip()
                if mac:
                    self.trusted_macs.add(mac)

    # Unified MAC monitoring for device management and intrusion detection
    def monitor_mac_addresses(self, summary):
        import re
        from datetime import datetime
        enabled = [name for name, cb in self.module_checks.items() if cb.isChecked()]
        if 'Intrusion Detector' not in enabled:
            return
        time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        macs = re.findall(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', summary)
        for mac in macs:
            if mac not in self.trusted_macs and mac not in self._flagged_macs:
                self._flagged_macs.add(mac)
                self.unknown_list.addItem(mac)
                self.device_output.append(f"[ALERT] Unknown device detected: {mac} at {time_str}")
        # Remove from unknown_list if added to trusted
        for i in range(self.unknown_list.count()-1, -1, -1):
            mac = self.unknown_list.item(i).text()
            if mac in self.trusted_macs:
                self.unknown_list.takeItem(i)
                if mac in self._flagged_macs:
                    self._flagged_macs.remove(mac)

    def add_trusted_device(self):
        import os
        mac = self.trusted_mac_input.toPlainText().strip()
        name = self.trusted_name_input.toPlainText().strip()
        if not mac or not name:
            QMessageBox.warning(self, "Input Error", "Please enter both MAC address and device name.")
            return
        trusted_path = os.path.join(os.path.dirname(__file__), 'trusted_devices')
        with open(trusted_path, 'a') as f:
            f.write(f"{mac} | {name}\n")
        self.trusted_mac_input.clear()
        self.trusted_name_input.clear()
        self.load_trusted_devices()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    # --- Futuristic dark mode stylesheet ---
    futuristic_stylesheet = """
    QWidget { background-color: #1b222a; color: black; font-family: 'Segoe UI', 'Roboto', 'Arial', sans-serif; }
    QTabWidget::pane { border: 2px solid #00eaff; border-radius: 0px; background: rgba(35,38,41,0.85); }
    QTabBar::tab { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #232629, stop:1 #1b222a); color: black; padding: 10px 20px; border-radius: 12px; font-weight: normal; }
    QTabBar::tab:selected { background: white; color: black; border: 2px solid #00eaff; }
    QTableWidget, QTableView {
    background: white;
    color: black;
    border-radius: 0px;
    font-size: 12px;
    selection-background-color: #cce6ff;
    alternate-background-color: #f9f9f9;
 background: rgba(27,34,42,0.92); color: black; border-radius: 0px; font-size: 12px; }
    QHeaderView::section { background: white; color: black; border-radius: 0px; font-size: 14px; }
    QLineEdit, QTextEdit { background: white; color: black; border: 1px solid #cccccc; border-radius: 0px; font-size: 14px; }
    QPushButton { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #00eaff, stop:1 #39ff14); color: #1b222a; border-radius: 0px; font-size: 12px; font-weight: normal; padding: 8px 18px; }
    QPushButton:hover { background: #39ff14; color: #232629; }
    QListWidget, QComboBox { background: white; color: black; border-radius: 0px; }
    QMessageBox { background: white; color: black; }
    QLabel { font-size: 12px; color: black; }
    QCheckBox { color: black; font-size: 14px; }
    """
    # app.setStyleSheet(futuristic_stylesheet)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
