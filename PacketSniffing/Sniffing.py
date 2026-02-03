import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff, get_if_list, wrpcap
from scapy.layers.inet import IP, TCP, UDP
import threading

# --- 1. متغيرات عالمية (Global) لتسهيل الوصول إليها ---
captured_packets = []  # لتخزين الحزم الأصلية من أجل التصدير لاحقاً


def get_packet_info(pkt):
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


# --- 2. منطق الواجهة الرسومية ---
def start_sniffing():
    """ تشغيل عملية الالتقاط في خلفية البرنامج """
    interface = iface_box.get()
    if not interface:
        messagebox.showerror("Erorr", "Please choose interface")
        return

    global stop_sniffing_event
    stop_sniffing_event = False

    # تشغيل الالتقاط في Thread (خيط) منفصل حتى لا يتوقف البرنامج عن الاستجابة
    t = threading.Thread(target=process_packets, args=(interface,))
    t.daemon = True
    t.start()

    start_btn.config(state="disabled")
    stop_btn.config(state="normal")


def process_packets(iface):
    """ وظيفة Scapy التي تقوم بالالتقاط """

    def packet_callback(pkt):
        if stop_sniffing_event:
            return True  # يخبر Scapy بالتوقف

        captured_packets.append(pkt)  # حفظ الحزمة للتصدير

        # استخراج البيانات وعرضها في الجدول
        src, dst, proto, length = get_packet_info(pkt)
        table.insert("", "end", values=(src, dst, proto, length))

        # تحديث الإحصائيات البسيطة
        update_stats(proto)

    sniff(iface=iface, prn=packet_callback, stop_filter=lambda x: stop_sniffing_event)


def stop_capture():
    global stop_sniffing_event
    stop_sniffing_event = True
    start_btn.config(state="normal")
    stop_btn.config(state="disabled")


def export_pcap():
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


# --- 3. بناء واجهة المستخدم (GUI) ---
root = tk.Tk()
root.title("***Packing sniffing***")

# اختيار الواجهة (Interface)
top_frame = tk.Frame(root)
top_frame.pack(pady=10)

tk.Label(top_frame, text="choose interface:").pack(side="left")
iface_box = ttk.Combobox(top_frame, values=get_if_list())
iface_box.pack(side="left", padx=5)

start_btn = tk.Button(top_frame, text="start", command=start_sniffing, bg="green", fg="white")
start_btn.pack(side="left", padx=5)

stop_btn = tk.Button(top_frame, text="stop", command=stop_capture, state="disabled", bg="red", fg="white")
stop_btn.pack(side="left", padx=5)

export_btn = tk.Button(top_frame, text="export PCAP", command=export_pcap)
export_btn.pack(side="left", padx=5)

# الإحصائيات
stats_frame = tk.Frame(root)
stats_frame.pack(pady=5)
total_lbl = tk.Label(stats_frame, text="Total: 0")
total_lbl.pack(side="left", padx=10)
tcp_lbl = tk.Label(stats_frame, text="TCP: 0")
tcp_lbl.pack(side="left", padx=10)
udp_lbl = tk.Label(stats_frame, text="UDP: 0")
udp_lbl.pack(side="left", padx=10)

# الجدول
table = ttk.Treeview(root, columns=("src", "dst", "proto", "len"), show="headings")
table.heading("src", text="Source IP")
table.heading("dst", text="Destination IP")
table.heading("proto", text="Protocol")
table.heading("len", text="Length")
table.pack(padx=10, pady=10, fill="both", expand=True)

root.mainloop()
