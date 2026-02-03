*ScannerLogic* is a professional-grade, multi-threaded network security tool designed for rapid port discovery, service identification (Banner Grabbing), and OS fingerprinting. Built with a modular Python architecture, it offers high performance and clean, readable output for security professionals and enthusiasts.

---

## 🚀 Features
- *Modular Architecture:* Organized into distinct modules (config, network_utils, ui_reporter, scannerLogic) for easy maintenance.
- *High-Speed Scanning:* Uses Python's ThreadPoolExecutor to handle hundreds of concurrent threads.
- *Service Detection:* Performs banner grabbing to identify service versions (e.g., Apache, OpenSSH).
- *OS Fingerprinting:* Analyzes ICMP TTL values to guess the target operating system (Windows vs Linux/Unix).
- *Smart UI:* Features a sleek terminal interface with a pyfiglet ASCII banner and color-coded results.
- *Anti-Wrap Protection:* Intelligent text formatting to ensure long banners don't break the terminal layout.
- *Auto-Reporting:* Generates structured .txt reports with sorted port data and scan statistics.

---

## 🛠 Installation & Setup

### 1. Prerequisites
Ensure you have *Python 3.x* installed on your system.

### 2. Clone the Repository
```bash
git clone [https://github.com/your-username/NetworkSherlock.git](https://github.com/your-username/NetworkSherlock.git)
cd NetworkSherlock

3. Install Dependencies
Install the required Python libraries:
pip install colorama scapy pyfiglet

💻 Operating System Requirements
🐧 For Linux (Kali, Ubuntu, etc.)
To use the OS Detection feature, you must run the script with sudo because scapy requires root privileges to send/receive raw ICMP packets.
sudo python3 scannerLogic.py <target_ip> -p 1-1000 -t 200 -o report.txt

📖 Usage Guide
| Argument | Description | Default |
|---|---|---|
| target | The Target IP address (e.g., 192.168.1.1) | Required |
| -p, --ports | Range or specific ports (e.g., 1-1024 or 80,443) | 1-1024 |
| -t, --threads | Number of concurrent threads | 100 |
| -o, --output | Save results to a file (e.g., results.txt) | None |
Example Command:
sudo python3 scannerLogic.py 10.10.10.5 -p 21,22,80,445 -t 50 -o my_scan.txt

📁 File Structure
NetworkSherlock/
├── scannerLogic.py   # Main engine and entry point
├── network_utils.py  # Network functions (Banner/OS Detection)
├── ui_reporter.py    # Terminal UI and reporting logic
├── config.py         # Argument parsing and settings
└── README.md         # Documentation

🤝 Contributing
Contributions are welcome! If you'd like to improve the tool:
 * Fork the Project.
 * Create your Feature Branch (git checkout -b feature/AmazingFeature).
 * Commit your Changes (git commit -m 'Add some AmazingFeature').
 * Push to the Branch (git push origin feature/AmazingFeature).
 * Open a Pull Request.
⚖️ Disclaimer
This tool is strictly for educational and ethical hacking purposes. Unauthorized scanning of networks is illegal. The author is not responsible for any misuse of this tool.
