import sys
import time
import collections
import joblib
import pandas as pd
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QPushButton, QTextEdit, QLabel)
from PyQt6.QtCore import QThread, pyqtSignal, pyqtSlot
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from scapy.all import sniff, IP, TCP, UDP, ICMP

class MplCanvas(FigureCanvas):
    def __init__(self, parent=None, width=8, height=6, dpi=100):
        self.fig = Figure(figsize=(width, height), dpi=dpi)
        self.ax1 = self.fig.add_subplot(2, 1, 1)
        self.ax2 = self.fig.add_subplot(2, 2, 3)
        self.ax3 = self.fig.add_subplot(2, 2, 4)
        self.fig.tight_layout(pad=3.0)
        super().__init__(self.fig)

class SnifferThread(QThread):
    packet_captured = pyqtSignal(str)
    stats_updated = pyqtSignal(dict, dict, int, int)

    def __init__(self):
        super().__init__()
        self._is_running = True
        self.packet_count = 0
        self.protocol_stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
        self.status_stats = {"Норма": 0, "Атака": 0}
        self.packets_per_sec = 0
        self.attacks_per_sec = 0
        self.last_time = time.time()

        try:
            self.model = joblib.load('traffic_ml_model.pkl')
            self.model_loaded = True
        except Exception:
            self.model_loaded = False

    def run(self):
        self._is_running = True
        self.packet_count = 0
        sniff(prn=self.process_packet, stop_filter=self.should_stop, store=False)

    def process_packet(self, packet):
        self.packet_count += 1
        self.packets_per_sec += 1

        protocol_str = "Other"
        protocol_num = 0
        src_ip = "Unknown"
        dst_ip = "Unknown"
        length = len(packet)

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            if TCP in packet:
                protocol_str = "TCP"
                protocol_num = 6
            elif UDP in packet:
                protocol_str = "UDP"
                protocol_num = 17
            elif ICMP in packet:
                protocol_str = "ICMP"
                protocol_num = 1

        self.protocol_stats[protocol_str] += 1

        anomaly_status = "OK"
        if self.model_loaded and protocol_num != 0:
            features = pd.DataFrame([[length, protocol_num]], columns=['length', 'protocol_num'])
            prediction = self.model.predict(features)[0]

            if prediction != "Норма":
                anomaly_status = f"{prediction}"
                self.status_stats["Атака"] += 1
                self.attacks_per_sec += 1
            else:
                self.status_stats["Норма"] += 1

        log_msg = f"[{time.strftime('%H:%M:%S')}] {src_ip} -> {dst_ip} | {protocol_str} | {length}b | {anomaly_status}"
        self.packet_captured.emit(log_msg)

        current_time = time.time()
        if current_time - self.last_time >= 1.0:
            self.stats_updated.emit(self.protocol_stats, self.status_stats, self.packets_per_sec, self.attacks_per_sec)
            self.packets_per_sec = 0
            self.attacks_per_sec = 0
            self.last_time = current_time

    def should_stop(self, packet):
        return not self._is_running

    def stop(self):
        self._is_running = False

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Интеллектуальный анализатор трафика (ML IDS)")
        self.setGeometry(100, 100, 1000, 800)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout()

        top_layout = QHBoxLayout()
        self.btn_start = QPushButton("▶ Запустить ML-захват")
        self.btn_stop = QPushButton("⏹ Остановить")
        self.btn_stop.setEnabled(False)
        top_layout.addWidget(self.btn_start)
        top_layout.addWidget(self.btn_stop)
        top_layout.addStretch()

        self.canvas = MplCanvas(self, width=8, height=5, dpi=100)
        self.time_data = list(range(20))
        self.intensity_total = collections.deque([0] * 20, maxlen=20)
        self.intensity_attack = collections.deque([0] * 20, maxlen=20)
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setStyleSheet("background-color: #1e1e1e; color: #00ff00; font-family: Consolas;")

        layout.addLayout(top_layout)
        layout.addWidget(self.canvas)
        layout.addWidget(QLabel("Журнал сетевой активности (ML-сканирование):"))
        layout.addWidget(self.log_area)
        central_widget.setLayout(layout)

        self.sniffer_thread = SnifferThread()
        self.sniffer_thread.packet_captured.connect(self.update_log)
        self.sniffer_thread.stats_updated.connect(self.update_graphs)
        self.btn_start.clicked.connect(self.start_sniffing)
        self.btn_stop.clicked.connect(self.stop_sniffing)
        self.draw_graphs({"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}, {"Норма": 0, "Атака": 0}, 0, 0)

    @pyqtSlot(str)
    def update_log(self, message):
        if "Атака" in message:
            self.log_area.append(f'<span style="color: #ff4444;">{message}</span>')
        else:
            self.log_area.append(f'<span style="color: #00ff00;">{message}</span>')

    @pyqtSlot(dict, dict, int, int)
    def update_graphs(self, proto_stats, status_stats, total_pps, attack_pps):
        self.intensity_total.append(total_pps)
        self.intensity_attack.append(attack_pps)
        self.draw_graphs(proto_stats, status_stats, total_pps, attack_pps)

    def draw_graphs(self, proto_stats, status_stats, total_pps, attack_pps):
        self.canvas.ax1.cla()
        self.canvas.ax1.plot(self.time_data, self.intensity_total, label='Общий трафик', color='#4C72B0', linewidth=2)
        self.canvas.ax1.plot(self.time_data, self.intensity_attack, label='Трафик атак', color='#C44E52', linewidth=2)
        self.canvas.ax1.set_title(f"Интенсивность сети (Всего: {total_pps} п/с | Атак: {attack_pps} п/с)")
        self.canvas.ax1.set_ylim(0, max(10, max(self.intensity_total) + 10))
        self.canvas.ax1.legend(loc="upper left")
        self.canvas.ax1.grid(True, linestyle='--', alpha=0.5)
        self.canvas.ax2.cla()
        protocols = list(proto_stats.keys())
        counts = list(proto_stats.values())
        self.canvas.ax2.bar(protocols, counts, color=['#4C72B0', '#55A868', '#C44E52', '#8172B2'])
        self.canvas.ax2.set_title("Распределение протоколов")
        self.canvas.ax3.cla()
        labels = list(status_stats.keys())
        sizes = list(status_stats.values())
        colors = ['#55A868', '#C44E52']
        if sum(sizes) > 0:
            self.canvas.ax3.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=140)
        self.canvas.ax3.set_title("Статус безопасности (ML)")
        self.canvas.fig.tight_layout()
        self.canvas.draw()

    def start_sniffing(self):
        self.log_area.append('<span style="color: #ffffff;">Запуск ML-сканирования</span>')
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.sniffer_thread.start()

    def stop_sniffing(self):
        self.log_area.append('<span style="color: #ffffff;">Остановка</span>')
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.sniffer_thread.stop()
        self.sniffer_thread.wait()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())