import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from scapy.all import sniff, IP, TCP
import socket
import threading
import os
import sys

SIGNATURES = [
    "unauthorized access", "malware", "sql injection",
    "ransomware", "ddos", "brute force", "port scan"
]

class IDS:
    def __init__(self, output_callback):
        self.output_callback = output_callback
        self.sniffing = False

    def analyze_packet(self, packet):
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            proto = packet[IP].proto
            summary = f"🌐 {src} → {dst} [Protocol: {proto}]"
            self.output_callback(summary)

            if packet.haslayer(TCP) and packet[TCP].payload:
                try:
                    payload = str(bytes(packet[TCP].payload)).lower()
                    for sig in SIGNATURES:
                        if sig in payload:
                            self.output_callback(f"⚠️ ALERT: '{sig}' detected from {src}")
                except:
                    pass

    def start_sniffing(self):
        self.sniffing = True
        sniff(prn=self.analyze_packet, stop_filter=lambda _: not self.sniffing, store=False)

    def stop_sniffing(self):
        self.sniffing = False

    def analyze_logs(self, log_text):
        alerts = []
        for line_num, line in enumerate(log_text.splitlines(), 1):
            for sig in SIGNATURES:
                if sig in line.lower():
                    alerts.append(f"⚠️ [Log Line {line_num}] Match: '{sig}'")
        return alerts

    def scan_ports(self, target_ip, port_range):
        self.output_callback(f"🔍 Scanning ports on {target_ip}...")
        for port in port_range:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.3)
                    result = s.connect_ex((target_ip, port))
                    if result == 0:
                        self.output_callback(f"🟢 Port {port} is OPEN")
            except Exception as e:
                self.output_callback(f"Error on port {port}: {e}")

class IDSApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ Intrusion Detection System")
        self.root.geometry("950x650")
        self.root.configure(bg="#f0f2f5")

        self.ids = IDS(self.log_output)
        self.sniff_thread = None

        self.style = ttk.Style()
        self.style.configure("TButton", font=("Segoe UI", 10))
        self.style.configure("TLabel", font=("Segoe UI", 11))

        self.build_gui()

    def build_gui(self):
        # Header
        header = tk.Label(self.root, text="Intrusion Detection System", bg="#0d6efd", fg="white",
                          font=("Segoe UI", 18, "bold"), pady=10)
        header.pack(fill=tk.X)

        control_frame = tk.Frame(self.root, bg="#f0f2f5")
        control_frame.pack(pady=10)

        ttk.Button(control_frame, text="▶ Start Packet Capture", command=self.start_sniff).grid(row=0, column=0, padx=8)
        ttk.Button(control_frame, text="⏹ Stop Capture", command=self.stop_sniff).grid(row=0, column=1, padx=8)
        ttk.Button(control_frame, text="📁 Load Log File", command=self.load_log).grid(row=0, column=2, padx=8)

        self.ip_entry = ttk.Entry(control_frame, width=20)
        self.ip_entry.grid(row=0, column=3, padx=8)
        self.ip_entry.insert(0, "127.0.0.1")

        ttk.Button(control_frame, text="📡 Scan Ports", command=self.scan_ports).grid(row=0, column=4, padx=8)

        # Output box
        self.output_box = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, height=25,
                                                    font=("Consolas", 10), bg="white", fg="black")
        self.output_box.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

    def log_output(self, msg):
        self.output_box.insert(tk.END, msg + "\n")
        self.output_box.see(tk.END)

    def start_sniff(self):
        if self.sniff_thread and self.sniff_thread.is_alive():
            messagebox.showinfo("Already Running", "Sniffing is already in progress.")
            return
        self.sniff_thread = threading.Thread(target=self.ids.start_sniffing, daemon=True)
        self.sniff_thread.start()
        self.log_output("🚀 Packet sniffing started...")

    def stop_sniff(self):
        self.ids.stop_sniffing()
        self.log_output("🛑 Packet sniffing stopped.")

    def load_log(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            try:
                with open(file_path, 'r') as file:
                    log_text = file.read()
                self.log_output(f"📄 Analyzing log file: {file_path}")
                alerts = self.ids.analyze_logs(log_text)
                if alerts:
                    for alert in alerts:
                        self.log_output(alert)
                else:
                    self.log_output("✅ No suspicious activity found in log.")
            except Exception as e:
                messagebox.showerror("Error", f"Could not read file:\n{e}")

    def scan_ports(self):
        ip = self.ip_entry.get()
        ports = range(20, 1025)  # Common ports
        thread = threading.Thread(target=self.ids.scan_ports, args=(ip, ports), daemon=True)
        thread.start()

def check_permissions():
    if os.name == 'nt':
        return True  # Assume admin if run properly
    else:
        return os.geteuid() == 0

if __name__ == "__main__":
    if not check_permissions():
        print("❌ Please run this script as Administrator or root.")
        sys.exit(1)

    root = tk.Tk()
    app = IDSApp(root)
    root.mainloop()
