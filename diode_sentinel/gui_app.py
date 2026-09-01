"""
DiodeSentinel - 4-Page Native Desktop Cyber Defense Application (PyQt6)
Problem Statement ID 26145 - Hardware Data Diode Passive SOC Enclave
"""

import sys
import os
import json
import time
import numpy as np
from pathlib import Path
from typing import List, Dict

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTableWidget, QTableWidgetItem, QHeaderView,
    QFileDialog, QMessageBox, QFrame, QSplitter, QGroupBox, QSlider,
    QDialog, QTextEdit, QGridLayout, QTabWidget
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor, QFont, QBrush

import matplotlib
matplotlib.use("QtAgg")
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

from diode_sentinel.engine.pipeline import ThreatPipeline
from diode_sentinel.simulator.traffic_generator import TrafficGenerator
from diode_sentinel.engine.diode_ingest import FastPcapParser
from diode_sentinel.config import MITRE_MAPPINGS


CYBER_QSS = """
QMainWindow, QDialog {
    background-color: #07090e;
    color: #f8fafc;
    font-family: 'Segoe UI', sans-serif;
}
QWidget {
    color: #f8fafc;
}
QTabWidget::pane {
    border: 1px solid #1e293b;
    background-color: #07090e;
    border-radius: 6px;
}
QTabBar::tab {
    background-color: #0d121d;
    color: #94a3b8;
    padding: 8px 18px;
    margin-right: 4px;
    border: 1px solid #1e293b;
    border-bottom: none;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    font-weight: bold;
    font-size: 11px;
}
QTabBar::tab:selected {
    background-color: #131b2e;
    color: #00f0ff;
    border-bottom: 2px solid #00f0ff;
}
QTabBar::tab:hover {
    color: #ffffff;
}
QFrame.metric-card {
    background-color: #0d121d;
    border: 1px solid #1e293b;
    border-radius: 8px;
}
QFrame.metric-card:hover {
    border: 1px solid #00f0ff;
}
QGroupBox {
    background-color: #0d121d;
    border: 1px solid #1e293b;
    border-radius: 8px;
    margin-top: 14px;
    font-weight: bold;
    font-size: 11px;
    color: #00f0ff;
    padding: 12px;
}
QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 6px;
}
QPushButton.attack-btn {
    background-color: #131b2e;
    border: 1px solid #1e293b;
    border-radius: 6px;
    color: #e2e8f0;
    font-weight: bold;
    font-size: 11px;
    padding: 8px 12px;
    text-align: left;
}
QPushButton.attack-btn:hover {
    background-color: #1a253d;
    border: 1px solid #00f0ff;
    color: #00f0ff;
}
QPushButton.action-btn {
    background-color: #004d66;
    border: 1px solid #00f0ff;
    border-radius: 6px;
    color: #ffffff;
    font-weight: bold;
    font-size: 11px;
    padding: 6px 14px;
}
QPushButton.action-btn:hover {
    background-color: #007a99;
}
QTableWidget {
    background-color: #0a0e17;
    border: 1px solid #1e293b;
    border-radius: 6px;
    gridline-color: #131b2e;
    color: #cbd5e1;
    font-family: 'Consolas', monospace;
    font-size: 11px;
}
QTableWidget::item:selected {
    background-color: #1e293b;
    color: #00f0ff;
}
QHeaderView::section {
    background-color: #0d121d;
    color: #94a3b8;
    padding: 6px;
    border: 1px solid #1e293b;
    font-weight: bold;
    font-size: 11px;
}
"""


class ForensicDialog(QDialog):
    """Detailed Forensic Evidence Dialog for inspected threat alerts."""

    def __init__(self, alert: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Forensic Threat Inspector // {alert.get('alert_id', 'ALT')}")
        self.resize(750, 520)
        self.setStyleSheet(CYBER_QSS)

        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        header_frame = QFrame()
        header_frame.setProperty("class", "metric-card")
        header_layout = QGridLayout(header_frame)
        header_layout.setContentsMargins(10, 10, 10, 10)

        severity = alert.get("severity", "MEDIUM")
        sev_color = "#ff3366" if severity == "CRITICAL" else ("#f59e0b" if severity == "HIGH" else "#3b82f6")

        sev_label = QLabel(f"SEVERITY: {severity}")
        sev_label.setStyleSheet(f"color: {sev_color}; font-weight: bold; font-size: 13px;")
        
        class_label = QLabel(f"THREAT CLASS: {alert.get('threat_class', 'UNKNOWN')} ({alert.get('subtype', '')})")
        class_label.setStyleSheet("color: #00f0ff; font-weight: bold; font-size: 13px;")

        flow_label = QLabel(f"FLOW 5-TUPLE: {alert.get('flow_id', 'N/A')}")
        flow_label.setStyleSheet("color: #fbbf24; font-family: Consolas; font-size: 11px;")

        mitre_label = QLabel(f"MITRE ATT&CK: {alert.get('mitre_technique', 'N/A')}")
        mitre_label.setStyleSheet("color: #38bdf8; font-weight: bold; font-size: 11px;")

        header_layout.addWidget(sev_label, 0, 0)
        header_layout.addWidget(class_label, 0, 1)
        header_layout.addWidget(flow_label, 1, 0)
        header_layout.addWidget(mitre_label, 1, 1)
        layout.addWidget(header_frame)

        summary_group = QGroupBox("EXECUTIVE TRIAGE SUMMARY")
        sum_layout = QVBoxLayout(summary_group)
        summary_txt = QLabel(alert.get("summary", "No description available."))
        summary_txt.setWordWrap(True)
        summary_txt.setStyleSheet("color: #f1f5f9; font-size: 12px;")
        sum_layout.addWidget(summary_txt)
        layout.addWidget(summary_group)

        evidence_group = QGroupBox("PASSIVE MATHEMATICAL & FEATURE EVIDENCE")
        ev_layout = QVBoxLayout(evidence_group)
        
        evidence_dict = alert.get("evidence", {})
        ev_text = ""
        for k, v in evidence_dict.items():
            ev_text += f"• {k.replace('_', ' ').upper()}: {v}\n"
            
        evidence_display = QTextEdit()
        evidence_display.setPlainText(ev_text)
        evidence_display.setReadOnly(True)
        evidence_display.setStyleSheet("background-color: #0a0e17; border: 1px solid #1e293b; color: #38bdf8; font-family: Consolas; font-size: 11px;")
        ev_layout.addWidget(evidence_display)
        layout.addWidget(evidence_group)

        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        close_btn = QPushButton("Close Inspector")
        close_btn.setProperty("class", "action-btn")
        close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)


class DiodeSentinelDesktopApp(QMainWindow):
    """Main 4-Page Native Desktop SOC Application."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("DIODE SENTINEL // Passive AI Threat Detection Platform (Problem ID 26145)")
        self.resize(1380, 880)
        self.setStyleSheet(CYBER_QSS)

        self.pipeline = ThreatPipeline()
        self.simulator = TrafficGenerator(self.pipeline, base_pps=140.0)
        self.simulator.start()

        self.pps_history = [0.0] * 30
        self.mbps_history = [0.0] * 30
        self.alerts_cache: List[dict] = []
        self.last_threat_counts = {}

        self._init_ui()

        self.timer = QTimer(self)
        self.timer.timeout.connect(self._update_telemetry_tick)
        self.timer.start(500)

    def _init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(14, 14, 14, 14)
        main_layout.setSpacing(10)

        # Header
        header_layout = QHBoxLayout()
        title_box = QVBoxLayout()
        app_title = QLabel("🛡️ DIODE SENTINEL")
        app_title.setStyleSheet("font-size: 20px; font-weight: 800; color: #00f0ff; letter-spacing: 1px;")
        app_sub = QLabel("PASSIVE UNIDIRECTIONAL THREAT DETECTION // 4-PAGE ENCLAVE PLATFORM")
        app_sub.setStyleSheet("font-size: 10px; color: #94a3b8; font-weight: bold;")
        title_box.addWidget(app_title)
        title_box.addWidget(app_sub)
        header_layout.addLayout(title_box)

        header_layout.addStretch()

        self.diode_status_lbl = QLabel("🟢 HARDWARE DATA DIODE: ACTIVE (RX ONLY - ZERO RETURN PATH)")
        self.diode_status_lbl.setStyleSheet("background-color: #064e3b; border: 1px solid #10b981; color: #6ee7b7; padding: 6px 14px; border-radius: 6px; font-weight: bold; font-size: 11px;")
        header_layout.addWidget(self.diode_status_lbl)

        clear_btn = QPushButton("🔄 Reset")
        clear_btn.setProperty("class", "action-btn")
        clear_btn.clicked.connect(self._reset_pipeline)
        header_layout.addWidget(clear_btn)

        export_btn = QPushButton("💾 Export Alerts")
        export_btn.setProperty("class", "action-btn")
        export_btn.clicked.connect(self._export_alerts_dialog)
        header_layout.addWidget(export_btn)

        main_layout.addLayout(header_layout)

        # Global Metric Cards Row
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(10)
        self.card_mbps = self._create_metric_card("INGEST THROUGHPUT", "0.00 Mbps", "0 pkts/sec", "#00f0ff")
        self.card_pkts = self._create_metric_card("TOTAL PROCESSED", "0 pkts", "0.0 MB total", "#3b82f6")
        self.card_flows = self._create_metric_card("ACTIVE FLOWS (10s)", "0 flows", "Sliding 5-tuple table", "#38bdf8")
        self.card_alerts = self._create_metric_card("SECURITY THREATS", "0 ALERTS", "0 Critical", "#ff3366")

        cards_layout.addWidget(self.card_mbps["frame"])
        cards_layout.addWidget(self.card_pkts["frame"])
        cards_layout.addWidget(self.card_flows["frame"])
        cards_layout.addWidget(self.card_alerts["frame"])
        main_layout.addLayout(cards_layout)

        # 4-PAGE TAB WIDGET
        self.tabs = QTabWidget()
        
        # TAB 1: Live Threat Operations
        tab1 = QWidget()
        tab1_layout = QHBoxLayout(tab1)
        tab1_layout.setContentsMargins(4, 4, 4, 4)
        tab1_layout.setSpacing(10)

        # Attack Studio (Left)
        attack_group = QGroupBox("LIVE ATTACK INJECTION STUDIO (1-CLICK)")
        att_layout = QVBoxLayout(attack_group)
        scenarios = [
            ("⚡ Volumetric SYN Flood", "syn_flood", "Layer 4 unacknowledged connection flood"),
            ("📡 Botnet C2 Beaconing", "c2_beacon", "Periodic low-jitter IAT heartbeat (Cobalt Strike)"),
            ("🚇 Covert DNS Tunneling", "dns_tunnel", "High-entropy TXT base64 data smuggling"),
            ("🌐 Algorithmic DGA Query", "dga", "Pseudo-random consonant-heavy domain"),
            ("🔒 Malware TLS (JA3 Hash)", "tls_malware", "Malicious Client Hello signature (No Decrypt)"),
            ("🔍 Recon & Port Scan", "port_scan", "25-port fan-out sweep from single source"),
            ("📤 Asymmetric Data Exfil", "data_exfil", "High-volume outbound burst (3.5MB out / 1KB in)")
        ]
        for label, code, desc in scenarios:
            btn = QPushButton(f"{label}\n→ {desc}")
            btn.setProperty("class", "attack-btn")
            btn.clicked.connect(lambda ch, c=code: self._trigger_attack(c))
            att_layout.addWidget(btn)
        tab1_layout.addWidget(attack_group, 1)

        # Charts & Alert Table (Right)
        right_tab1 = QWidget()
        right_tab1_layout = QVBoxLayout(right_tab1)
        right_tab1_layout.setContentsMargins(0, 0, 0, 0)
        
        charts_layout = QHBoxLayout()
        self.wave_fig = Figure(figsize=(5, 2.0), facecolor="#0d121d")
        self.wave_ax = self.wave_fig.add_subplot(111)
        self.wave_ax.set_facecolor("#0a0e17")
        self.wave_ax.set_title("LIVE INGEST WAVEFORM", color="#94a3b8", fontsize=9, fontweight="bold", pad=4)
        self.wave_ax.tick_params(colors="#64748b", labelsize=8)
        self.wave_ax.grid(True, color="#1e293b", linestyle=":", alpha=0.6)
        self.line_pps, = self.wave_ax.plot(self.pps_history, color="#00f0ff", label="PPS (pkts/sec)", linewidth=1.5)
        self.line_mbps, = self.wave_ax.plot([m * 50 for m in self.mbps_history], color="#3b82f6", label="Mbps x50", linestyle="--", linewidth=1.2)
        self.wave_ax.legend(loc="upper left", facecolor="#0a0e17", edgecolor="#1e293b", labelcolor="#94a3b8", fontsize=7)
        self.wave_canvas = FigureCanvas(self.wave_fig)
        self.wave_canvas.setFixedHeight(170)
        charts_layout.addWidget(self.wave_canvas)

        self.radar_fig = Figure(figsize=(3.2, 2.0), facecolor="#0d121d")
        self.radar_ax = self.radar_fig.add_subplot(111, polar=True)
        self.radar_ax.set_facecolor("#0a0e17")
        self.radar_ax.set_title("THREAT RADAR", color="#94a3b8", fontsize=9, fontweight="bold", pad=8)
        self.radar_ax.tick_params(colors="#64748b", labelsize=7)
        self.radar_ax.grid(True, color="#1e293b")
        self.radar_canvas = FigureCanvas(self.radar_fig)
        self.radar_canvas.setFixedHeight(170)
        charts_layout.addWidget(self.radar_canvas)
        right_tab1_layout.addLayout(charts_layout)

        alerts_group = QGroupBox("LIVE SECURITY THREAT ALERTS STREAM")
        al_layout = QVBoxLayout(alerts_group)
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["Time (UTC)", "Severity", "Threat Class", "Flow 5-Tuple", "Confidence", "Action"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.cellDoubleClicked.connect(self._on_table_double_click)
        al_layout.addWidget(self.table)
        right_tab1_layout.addWidget(alerts_group)

        tab1_layout.addWidget(right_tab1, 2)
        self.tabs.addTab(tab1, "1. 🚨 Live Threat Operations")

        # TAB 2: MITRE ATT&CK Matrix
        tab2 = QWidget()
        tab2_layout = QVBoxLayout(tab2)
        mitre_group = QGroupBox("MITRE ATT&CK ENTERPRISE FRAMEWORK MAPPINGS")
        m_grid = QGridLayout(mitre_group)
        row, col = 0, 0
        for t_class, info in MITRE_MAPPINGS.items():
            card = QFrame()
            card.setProperty("class", "metric-card")
            c_lay = QVBoxLayout(card)
            t_lbl = QLabel(f"<b>{t_class.replace('_', ' ')}</b>")
            t_lbl.setStyleSheet("color: #00f0ff; font-size: 12px;")
            id_lbl = QLabel(f"Technique ID: <b style='color: #38bdf8;'>{info['technique_id']}</b> ({info['name']})")
            tac_lbl = QLabel(f"Tactic: <i style='color: #94a3b8;'>{info['tactic']}</i>")
            c_lay.addWidget(t_lbl)
            c_lay.addWidget(id_lbl)
            c_lay.addWidget(tac_lbl)
            m_grid.addWidget(card, row, col)
            col += 1
            if col > 1:
                col = 0
                row += 1
        tab2_layout.addWidget(mitre_group)
        self.tabs.addTab(tab2, "2. 🔬 Forensic & MITRE ATT&CK")

        # TAB 3: SHA-256 Hash-Chain Audit Ledger
        tab3 = QWidget()
        tab3_layout = QVBoxLayout(tab3)
        l_header = QHBoxLayout()
        self.ledger_status_lbl = QLabel("🟢 All blocks cryptographically linked and verified with SHA-256.")
        self.ledger_status_lbl.setStyleSheet("color: #6ee7b7; font-weight: bold; font-size: 12px;")
        l_header.addWidget(self.ledger_status_lbl)
        l_header.addStretch()

        v_btn = QPushButton("⛓️ Verify Chain Integrity")
        v_btn.setProperty("class", "action-btn")
        v_btn.clicked.connect(self._verify_ledger_gui)
        l_header.addWidget(v_btn)
        tab3_layout.addLayout(l_header)

        self.ledger_table = QTableWidget()
        self.ledger_table.setColumnCount(5)
        self.ledger_table.setHorizontalHeaderLabels(["Block #", "Alert ID", "Threat Class", "SHA-256 Block Hash", "Previous Hash"])
        self.ledger_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.ledger_table.verticalHeader().setVisible(False)
        tab3_layout.addWidget(self.ledger_table)
        self.tabs.addTab(tab3, "3. ⛓️ SHA-256 Audit Ledger")

        # TAB 4: PCAP Lab & Benchmarks
        tab4 = QWidget()
        tab4_layout = QHBoxLayout(tab4)
        pcap_box = QGroupBox("OFFLINE FORENSIC PCAP REPLAY")
        p_lay = QVBoxLayout(pcap_box)
        p_desc = QLabel("Ingest raw binary .pcap captures to inspect historical attacks in unidirectional enclave mode:")
        p_desc.setWordWrap(True)
        p_lay.addWidget(p_desc)
        p_btn = QPushButton("📂 Open .pcap Capture File")
        p_btn.setProperty("class", "action-btn")
        p_btn.clicked.connect(self._load_pcap_dialog)
        p_lay.addWidget(p_btn)
        p_lay.addStretch()
        tab4_layout.addWidget(pcap_box)

        bench_box = QGroupBox("HIGH-THROUGHPUT BENCHMARK LAB")
        b_lay = QVBoxLayout(bench_box)
        b_desc = QLabel("Run on-demand high-rate load tests measuring sustained packet ingestion and sub-millisecond inference latency:")
        b_desc.setWordWrap(True)
        b_lay.addWidget(b_desc)
        b_btn = QPushButton("🚀 Run 25,000-Packet Benchmark")
        b_btn.setProperty("class", "action-btn")
        b_btn.clicked.connect(self._run_benchmark_gui)
        b_lay.addWidget(b_btn)
        self.bench_res_lbl = QLabel("")
        self.bench_res_lbl.setStyleSheet("color: #38bdf8; font-family: Consolas; font-size: 11px;")
        b_lay.addWidget(self.bench_res_lbl)
        b_lay.addStretch()
        tab4_layout.addWidget(bench_box)
        self.tabs.addTab(tab4, "4. ⚡ PCAP Lab & Benchmarks")

        main_layout.addWidget(self.tabs)

    def _create_metric_card(self, title: str, main_val: str, sub_val: str, color_hex: str) -> dict:
        frame = QFrame()
        frame.setProperty("class", "metric-card")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(2)

        t_lbl = QLabel(title)
        t_lbl.setStyleSheet("color: #94a3b8; font-size: 10px; font-weight: bold;")
        m_lbl = QLabel(main_val)
        m_lbl.setStyleSheet(f"color: {color_hex}; font-size: 18px; font-weight: bold; font-family: Consolas;")
        s_lbl = QLabel(sub_val)
        s_lbl.setStyleSheet("color: #64748b; font-size: 10px;")

        layout.addWidget(t_lbl)
        layout.addWidget(m_lbl)
        layout.addWidget(s_lbl)
        return {"frame": frame, "main": m_lbl, "sub": s_lbl}

    def _trigger_attack(self, scenario_code: str):
        msg = self.simulator.inject_attack(scenario_code)
        self.diode_status_lbl.setText(f"⚡ INJECTED: {scenario_code.upper()} INTO DIODE STREAM")
        self.diode_status_lbl.setStyleSheet("background-color: #7f1d1d; border: 1px solid #ef4444; color: #fecaca; padding: 6px 14px; border-radius: 6px; font-weight: bold; font-size: 11px;")
        QTimer.singleShot(2500, self._restore_diode_badge)

    def _restore_diode_badge(self):
        self.diode_status_lbl.setText("🟢 HARDWARE DATA DIODE: ACTIVE (RX ONLY - ZERO RETURN PATH)")
        self.diode_status_lbl.setStyleSheet("background-color: #064e3b; border: 1px solid #10b981; color: #6ee7b7; padding: 6px 14px; border-radius: 6px; font-weight: bold; font-size: 11px;")

    def _reset_pipeline(self):
        self.pipeline.clear_all()
        self.table.setRowCount(0)
        self.alerts_cache.clear()
        QMessageBox.information(self, "Reset Complete", "DiodeSentinel pipeline state and flow tables have been reset.")

    def _load_pcap_dialog(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select PCAP Capture for Passive Replay", "", "PCAP Files (*.pcap *.cap)")
        if file_path:
            count = 0
            for pkt in FastPcapParser.parse_pcap_file(file_path):
                self.pipeline.process_packet(pkt)
                count += 1
            QMessageBox.information(self, "PCAP Replayed", f"Successfully ingested and inspected {count:,} packets passively from:\n{file_path}")

    def _export_alerts_dialog(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Export Security Alerts JSON", "diode_alerts.json", "JSON Files (*.json)")
        if file_path:
            with open(file_path, "w") as f:
                json.dump(list(self.pipeline.alerts), f, indent=2)
            QMessageBox.information(self, "Export Complete", f"Exported {len(self.pipeline.alerts)} security alerts to:\n{file_path}")

    def _verify_ledger_gui(self):
        res = self.pipeline.audit_ledger.verify_integrity()
        if res.get("valid"):
            self.ledger_status_lbl.setText(f"✅ HASH-CHAIN INTEGRITY VERIFIED: {res.get('chain_length')} blocks intact with zero tampering.")
            self.ledger_status_lbl.setStyleSheet("color: #6ee7b7; font-weight: bold; font-size: 12px;")
        else:
            self.ledger_status_lbl.setText(f"❌ TAMPER DETECTED: {res.get('error')}")
            self.ledger_status_lbl.setStyleSheet("color: #f87171; font-weight: bold; font-size: 12px;")

    def _run_benchmark_gui(self):
        from diode_sentinel.simulator.attack_scenarios import AttackScenarios
        num_pkts = 25000
        test_pkts = [AttackScenarios.generate_benign_packet() for _ in range(num_pkts)]
        bench_pipe = ThreatPipeline()
        
        t0 = time.perf_counter()
        for p in test_pkts:
            bench_pipe.process_packet(p)
        elapsed = time.perf_counter() - t0
        
        pps = num_pkts / elapsed
        lat_us = (elapsed / num_pkts) * 1_000_000
        mbps = (bench_pipe.total_bytes_processed * 8) / (elapsed * 1_000_000)

        self.bench_res_lbl.setText(
            f"✅ Benchmark Complete ({num_pkts:,} pkts in {elapsed:.3f}s):\n"
            f"• Sustained Throughput : {pps:,.1f} pkts/sec ({mbps:.2f} Mbps)\n"
            f"• Inference Latency    : {lat_us:.2f} µs ({lat_us/1000:.4f} ms)\n"
            f"• Active Flows Tracked : {len(bench_pipe.aggregator.flows):,}"
        )

    def _on_table_double_click(self, row: int, col: int):
        if row < len(self.alerts_cache):
            alert = self.alerts_cache[row]
            dialog = ForensicDialog(alert, self)
            dialog.exec()

    def _update_telemetry_tick(self):
        try:
            telemetry = self.pipeline.get_system_telemetry()
            self.card_mbps["main"].setText(f"{telemetry['current_mbps']:.2f} Mbps")
            self.card_mbps["sub"].setText(f"{telemetry['current_pps']:.0f} pkts/sec")
            self.card_pkts["main"].setText(f"{telemetry['total_packets']:,} pkts")
            self.card_pkts["sub"].setText(f"{telemetry['total_bytes'] / (1024*1024):.1f} MB total")
            self.card_flows["main"].setText(f"{telemetry['active_flows_count']} flows")

            recent_alerts = telemetry.get("recent_alerts", [])
            criticals = sum(1 for a in recent_alerts if a.get("severity") == "CRITICAL")
            self.card_alerts["main"].setText(f"{telemetry['total_alerts']} ALERTS")
            self.card_alerts["sub"].setText(f"{criticals} Critical Threats")

            self.pps_history.pop(0)
            self.pps_history.append(telemetry["current_pps"])
            self.mbps_history.pop(0)
            self.mbps_history.append(telemetry["current_mbps"])

            self.line_pps.set_ydata(self.pps_history)
            self.line_mbps.set_ydata([m * 50 for m in self.mbps_history])
            max_val = max(100, max(self.pps_history) * 1.3)
            self.wave_ax.set_ylim(0, max_val)
            self.wave_canvas.draw_idle()

            threat_counts = telemetry.get("threat_counts", {})
            if threat_counts != self.last_threat_counts:
                self.last_threat_counts = dict(threat_counts)
                categories = ["DDoS", "C2", "DNS", "TLS", "Recon", "Exfil"]
                values = [
                    threat_counts.get("VOLUMETRIC_DDOS", 0),
                    threat_counts.get("BOTNET_C2_BEACONING", 0),
                    threat_counts.get("DGA_DNS_TUNNEL", 0),
                    threat_counts.get("ENCRYPTED_MALWARE", 0),
                    threat_counts.get("PORT_SCAN_RECON", 0),
                    threat_counts.get("DATA_EXFILTRATION", 0)
                ]
                angles = np.linspace(0, 2 * np.pi, len(categories), endpoint=False).tolist()
                values_radar = values + [values[0]]
                angles_radar = angles + [angles[0]]

                self.radar_ax.clear()
                self.radar_ax.set_xticks(angles)
                self.radar_ax.set_xticklabels(categories, color="#94a3b8", fontsize=8, fontweight="bold")
                self.radar_ax.plot(angles_radar, values_radar, color="#00f0ff", linewidth=1.8)
                self.radar_ax.fill(angles_radar, values_radar, color="#00f0ff", alpha=0.2)
                self.radar_ax.set_title("THREAT RADAR", color="#94a3b8", fontsize=9, fontweight="bold", pad=8)
                self.radar_ax.tick_params(colors="#64748b", labelsize=7)
                self.radar_ax.grid(True, color="#1e293b")
                self.radar_canvas.draw_idle()

            if len(recent_alerts) != len(self.alerts_cache):
                self.alerts_cache = recent_alerts
                self.table.setRowCount(len(recent_alerts))
                for r, a in enumerate(recent_alerts):
                    time_str = a.get("timestamp", "").split("T")[-1][:8]
                    sev = a.get("severity", "MEDIUM")
                    t_class = a.get("threat_class", "UNKNOWN")
                    flow = a.get("flow_id", "N/A")
                    conf = f"{int(a.get('confidence_score', 0.85) * 100)}%"

                    sev_item = QTableWidgetItem(sev)
                    sev_item.setForeground(QBrush(QColor("#ff3366" if sev == "CRITICAL" else ("#f59e0b" if sev == "HIGH" else "#3b82f6"))))

                    t_class_item = QTableWidgetItem(t_class.replace("_", " "))
                    t_class_item.setForeground(QBrush(QColor("#00f0ff")))

                    flow_item = QTableWidgetItem(flow)
                    flow_item.setForeground(QBrush(QColor("#fbbf24")))

                    self.table.setItem(r, 0, QTableWidgetItem(time_str))
                    self.table.setItem(r, 1, sev_item)
                    self.table.setItem(r, 2, t_class_item)
                    self.table.setItem(r, 3, flow_item)
                    self.table.setItem(r, 4, QTableWidgetItem(conf))
                    
                    insp_btn = QPushButton("Inspect")
                    insp_btn.setProperty("class", "action-btn")
                    insp_btn.clicked.connect(lambda ch, alert_obj=a: ForensicDialog(alert_obj, self).exec())
                    self.table.setCellWidget(r, 5, insp_btn)

                # Update Ledger Table (Tab 3)
                blocks = list(reversed(self.pipeline.audit_ledger.chain))[:30]
                self.ledger_table.setRowCount(len(blocks))
                for r, b in enumerate(blocks):
                    self.ledger_table.setItem(r, 0, QTableWidgetItem(f"#{b.index}"))
                    self.ledger_table.setItem(r, 1, QTableWidgetItem(b.alert_id or "GENESIS"))
                    self.ledger_table.setItem(r, 2, QTableWidgetItem(b.threat_class or "SYSTEM"))
                    self.ledger_table.setItem(r, 3, QTableWidgetItem(b.hash[:32] + "..."))
                    self.ledger_table.setItem(r, 4, QTableWidgetItem(b.previous_hash[:32] + "..."))
        except Exception:
            pass

    def closeEvent(self, event):
        self.simulator.stop()
        event.accept()


def launch_gui():
    app = QApplication(sys.argv)
    window = DiodeSentinelDesktopApp()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    launch_gui()
