import socket
from scapy.all import IP, TCP, sr1


def detect_windows_version_smb(target):
    try:
        pkt = IP(dst=target) / TCP(dport=445, flags="S")
        resp = sr1(pkt, timeout=1, verbose=0)
        if not resp or not resp.haslayer(TCP): return "SMB not responding"

        ttl, window = resp.ttl, resp[TCP].window
        if ttl < 100: return "Non-Windows or SMB filtered"
        if window in [8192, 16384]:
            return "Windows 7 (SMBv2.1)"
        elif window >= 65535:
            return "Windows 8 / 8.1 (SMBv3.0)"
        elif window >= 131072:
            return "Windows 10 / Windows 11 (SMBv3.1.1)"
        return "Windows detected (version unclear)"
    except:
        return "SMB detection error"


def detect_os(target):
    try:
        pkt = IP(dst=target) / TCP(dport=80, flags="S")
        resp = sr1(pkt, timeout=1, verbose=0)
        if not resp: return "OS detection failed (no response)"

        ttl = resp.ttl
        if ttl <= 64:
            return f"Linux / Unix | Kernel-based | TTL={ttl}"
        elif ttl <= 128:
            return f"Windows | {detect_windows_version_smb(target)} | TTL={ttl}"
        elif ttl <= 255:
            return f"Network Device | Router/Firewall | TTL={ttl}"
        return "Unknown OS"
    except Exception as e:
        return f"OS error: {e}"

def grab_banner(sock):
    try:
        sock.send(b"HEAD / HTTP/1.1\r\n\r\n")
        banner = sock.recv(1024).decode(errors='ignore').strip()
        return banner.replace('\n', ' ').replace('\r', '') if banner else "No banner"
    except:
        return "No banner"