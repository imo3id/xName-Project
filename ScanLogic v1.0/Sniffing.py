import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff, get_if_list, wrpcap
from scapy.layers.inet import IP, TCP, UDP
import threading
from collections import Counter

#*****kالتحقق من انكك ادمن ******

import os
import sys
import ctypes

def is_admin():
    try:
   
        if os.name == 'nt':
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
    
        else:
            return os.getuid() == 0
    except AttributeError:
        return False


if not is_admin():

    if os.name == 'nt':
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()
    else:
        print("Error: This script must be run as root (sudo).")
        sys.exit()


#*************

captured_packets = []
ip_counter=Counter()


def get_packet_info(pkt):#22
    """ دالة بسيطة لاستخراج المعلومات الأساسية من الحزمة """
    src_ip = pkt[IP].src if IP in pkt else "-"
    dst_ip = pkt[IP].dst if IP in pkt else "-"

    proto = "Other"
    if TCP in pkt:
        proto = "TCP"
    elif UDP in pkt:
        proto = "UDP"

    length = len(pkt)
    return (src_ip, dst_ip, proto, length)


def start_sniffing():
    interface = iface_box.get()
    selected_filter = filter_box.get()

    if not interface:
        messagebox.showerror("Error", "Please choose interface")
        return

    global stop_sniffing_event, captured_packets, ip_counter
    stop_sniffing_event = False
    captured_packets = []
    ip_counter.clear()

    scapy_filter = ""
    if selected_filter == "TCP":
        scapy_filter = "tcp"
    elif selected_filter == "UDP":
        scapy_filter = "udp"

    t = threading.Thread(target=process_packets, args=(interface, scapy_filter))
    t.daemon = True
    t.start()

    start_btn.config(state="disabled")
    stop_btn.config(state="normal")


def process_packets(iface, s_filter):
    def packet_callback(pkt):
        if stop_sniffing_event:
            return True
        captured_packets.append(pkt)
        src, dst, proto, length = get_packet_info(pkt)

        if src != "-":
            ip_counter[src] += 1

        table.insert("", "0", values=(src, dst, proto, length))
        update_stats(proto)

    sniff(iface=iface, prn=packet_callback, filter=s_filter, stop_filter=lambda x: stop_sniffing_event)
def stop_capture():#22
    global stop_sniffing_event
    stop_sniffing_event = True
    start_btn.config(state="normal")
    stop_btn.config(state="disabled")


def export_pcap():#22
    if not captured_packets:
        messagebox.showwarning("Alert", "No Packets to export")
        return
    wrpcap("captured_traffic.pcap", captured_packets)
    messagebox.showinfo("Successful", "File saved as: captured_traffic.pcap")


stats = {"Total": 0, "TCP": 0, "UDP": 0}


def update_stats(proto):
    stats["Total"] += 1
    if proto in stats:
        stats[proto] += 1

    total_lbl.config(text=f"Total: {stats['Total']}")
    tcp_lbl.config(text=f"TCP: {stats['TCP']}")
    udp_lbl.config(text=f"UDP: {stats['UDP']}")

    top_3 = ip_counter.most_common(3)
    top_text = " | ".join([f"{ip}({count})" for ip, count in top_3])
    top_ip_lbl.config(text=f"Top IPs: {top_text}")

def run_sniffer_ui():
    global root, iface_box, start_btn, stop_btn, total_lbl, tcp_lbl, udp_lbl, table , filter_box, top_ip_lbl
    root = tk.Tk()
    root.title("***Packing sniffing***")


    top_frame = tk.Frame(root)
    top_frame.pack(pady=10)

    tk.Label(top_frame, text="choose interface:").pack(side="left")
    iface_box = ttk.Combobox(top_frame, values=get_if_list())
    iface_box.pack(side="left", padx=5)

    tk.Label(top_frame, text="Filter:").pack(side="left", padx=5)
    filter_box = ttk.Combobox(top_frame, values=["ALL", "TCP", "UDP"], width=10)
    filter_box.current(0)
    filter_box.pack(side="left", padx=5)

    start_btn = tk.Button(top_frame, text="start", command=start_sniffing, bg="green", fg="white")
    start_btn.pack(side="left", padx=5)

    stop_btn = tk.Button(top_frame, text="stop", command=stop_capture, state="disabled", bg="red", fg="white")
    stop_btn.pack(side="left", padx=5)

    export_btn = tk.Button(top_frame, text="export PCAP", command=export_pcap)
    export_btn.pack(side="left", padx=5)


    stats_frame = tk.Frame(root)
    stats_frame.pack(pady=5)
    total_lbl = tk.Label(stats_frame, text="Total: 0")
    total_lbl.pack(side="left", padx=10)
    tcp_lbl = tk.Label(stats_frame, text="TCP: 0")
    tcp_lbl.pack(side="left", padx=10)
    udp_lbl = tk.Label(stats_frame, text="UDP: 0")
    udp_lbl.pack(side="left", padx=10)

    top_ip_lbl = tk.Label(root, text="Top IPs: Waiting...", font=("Arial", 10, "bold"), fg="blue")
    top_ip_lbl.pack(pady=5)

    table = ttk.Treeview(root, columns=("src", "dst", "proto", "len"), show="headings")
    table.heading("src", text="Source IP")
    table.heading("dst", text="Destination IP")
    table.heading("proto", text="Protocol")
    table.heading("len", text="Length")
    table.pack(padx=10, pady=10, fill="both", expand=True)

    root.mainloop()

if __name__ == "__main__":
    run_sniffer_ui()
