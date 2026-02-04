import socket
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore
import config
import network_utils
import ui_reporter

class ScannerLogic:
    def __init__(self):
        self.args = config.get_arguments()
        self.results = []
        self.lock = threading.Lock()
        self.ports = self.parse_ports(self.args.ports)

    def parse_ports(self, port_str):
        if '-' in port_str:
            start, end = map(int, port_str.split('-'))
            return range(start, end + 1)
        return [int(p) for p in port_str.split(',')]

    def scan_port(self, port):
        try:
            with socket.create_connection((self.args.target, port), timeout=1) as sock:
                banner = network_utils.grab_banner(sock)
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                with self.lock:
                    self.results.append({"port": port, "service": service, "banner": banner})
                    print(f"{Fore.BLUE}{port:<4}{Fore.WHITE}/tcp  {Fore.GREEN}{'open':<8} {Fore.WHITE}{service:<15} {Fore.YELLOW}{banner}")
        except: pass

    def run(self):
        os_info = network_utils.detect_os(self.args.target)
        ui_reporter.print_header(self.args.target, os_info, self.args.threads)
        start_time = time.time()
        with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            executor.map(self.scan_port, self.ports)
        duration = time.time() - start_time
        duration_str = f"{int(duration // 60)} minute {round(duration % 60, 2)} second"
        ui_reporter.print_footer(duration_str)
        ui_reporter.save_report(self.args.output, self.results, self.args.target, os_info, duration_str)

if __name__ == "__main__":
    scanner = ScannerLogic()
    scanner.run()
