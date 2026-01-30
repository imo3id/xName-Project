import threading
from queue import Queue
from scapy.all import sniff
from scapy.layers.inet import TCP, UDP

from .parser import packet_to_record

class CaptureWorker:
    ""
    def __init__(self):
        self.queue = Queue()
        self._stop_event = threading.Event()
        self._thread = None

    def start(self, iface, proto_filter="ALL"):
        self._stop_event.clear()

        def _lfilter(pkt):
            if proto_filter == "TCP":
                return TCP in pkt
            if proto_filter == "UDP":
                return UDP in pkt
            return True  # ALL

        def _on_packet(pkt):
            record = packet_to_record(pkt)
            self.queue.put(record)

        def _should_stop(_):
            return self._stop_event.is_set()

        self._thread = threading.Thread(
            target=lambda: sniff(
                iface=iface,
                prn=_on_packet,
                lfilter=_lfilter,
                stop_filter=_should_stop,
                store=False
            ),
            daemon=True
        )
        self._thread.start()

    def stop(self):
        self._stop_event.set()
