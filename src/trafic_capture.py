# capture_features.py (Corrected)
import sys
import pyshark
import numpy as np
import socket
import csv
import time
from pathlib import Path
from collections import defaultdict
import psutil

# ========== CONFIGURATION ==========
OUTPUT_CSV = Path.home() / 'OneDrive' / 'Desktop' / 'botnet_attack'/ 'network_traffic.csv'
PCAP_OUTPUT = Path.home() / 'OneDrive' / 'Desktop'/ 'botnet_attack' / 'capture.pcap'
CAPTURE_FILTER = ''
FLOW_TIMEOUT = 30  # seconds

CSV_HEADER = [
    'source_ip', 'destination_ip', 'flow_duration', 'Header_Length', 'Protocol Type',
    'Duration', 'Rate', 'Srate', 'Drate', 'fin_flag_number', 'syn_flag_number',
    'rst_flag_number', 'psh_flag_number', 'ack_flag_number', 'ece_flag_number',
    'cwr_flag_number', 'ack_count', 'syn_count', 'fin_count', 'urg_count', 'rst_count',
    'HTTP', 'HTTPS', 'DNS', 'Telnet', 'SMTP', 'SSH', 'IRC', 'TCP', 'UDP', 'DHCP', 'ARP',
    'ICMP', 'IPv', 'LLC', 'Tot sum', 'Min', 'Max', 'AVG', 'Std', 'Tot size', 'IAT',
    'Number', 'Magnitue', 'Radius', 'Covariance', 'Variance', 'Weight'
]

class FlowTracker:
    def __init__(self, src, dst, sport, dport, proto):
        self.src = src
        self.dst = dst
        self.sport = sport
        self.dport = dport
        self.proto = proto.upper()
        self.start_time = None
        self.end_time = None
        self.packet_times = []
        self.packet_sizes = []
        self.total_bytes = 0
        self.packet_count = 0
        self.flags = defaultdict(int)
        self.forward_packets = 0
        self.forward_bytes = 0
        self.backward_packets = 0
        self.backward_bytes = 0
        self.protocols = defaultdict(int)

    def add_packet(self, packet):
        try:
            timestamp = packet.sniff_time.timestamp()
            size = int(getattr(packet, 'length', 0))
            
            # Initialize timestamps
            if self.start_time is None:
                self.start_time = timestamp
            self.end_time = timestamp
            
            # Store packet metrics
            self.packet_times.append(timestamp)
            self.packet_sizes.append(size)
            self.total_bytes += size
            self.packet_count += 1

            # Calculate direction
            if 'IP' in packet:
                if packet.ip.src == self.src:
                    self.forward_packets += 1
                    self.forward_bytes += size
                else:
                    self.backward_packets += 1
                    self.backward_bytes += size

            # Extract flags
            if 'TCP' in packet:
                flags = str(packet.tcp.flags).upper()
                for flag in ['SYN', 'ACK', 'FIN', 'RST', 'PSH', 'URG', 'ECE', 'CWR']:
                    if flag in flags:
                        self.flags[flag.lower()] += 1

            # Detect protocols
            self._detect_protocols(packet)

        except Exception as e:
            print(f"Packet processing error: {e}")

    def _detect_protocols(self, packet):
        # Layer-based protocol detection
        layers = [layer.layer_name for layer in packet.layers]
        
        if 'arp' in layers:
            self.protocols['ARP'] = 1
        if 'icmp' in layers:
            self.protocols['ICMP'] = 1
        if 'tcp' in layers:
            self.protocols['TCP'] = 1
            try:
                port = int(self.dport)
                if port == 80: self.protocols['HTTP'] = 1
                if port == 443: self.protocols['HTTPS'] = 1
                if port == 22: self.protocols['SSH'] = 1
                if port == 23: self.protocols['Telnet'] = 1
                if port in (25, 587): self.protocols['SMTP'] = 1
                if port == 6667: self.protocols['IRC'] = 1
            except: pass
        if 'udp' in layers:
            self.protocols['UDP'] = 1
            try:
                port = int(self.dport)
                if port == 53: self.protocols['DNS'] = 1
                if port in (67, 68): self.protocols['DHCP'] = 1
            except: pass
        self.protocols['IPv'] = 1

    def is_expired(self, current_time):
        return self.end_time and (current_time - self.end_time) > FLOW_TIMEOUT

    def get_features(self):
        try:
            # Calculate duration
            duration = self.end_time - self.start_time if self.start_time else 0.0
            
            # Convert sizes to numpy array
            sizes = np.array(self.packet_sizes) if self.packet_sizes else np.array([0.0])
            
            # Calculate covariance safely
            covariance = 0.0
            if len(sizes) > 1:
                cov_matrix = np.cov(sizes)
                covariance = float(cov_matrix[0][1]) if cov_matrix.size > 1 else 0.0

            # Calculate statistical features
            return [
                self.src, self.dst,
                duration,
                self.total_bytes,
                6.0 if self.proto == 'TCP' else 17.0 if self.proto == 'UDP' else 1.0,
                duration,
                self.packet_count / duration if duration > 0 else 0.0,
                self.forward_packets / duration if duration > 0 else 0.0,
                self.backward_packets / duration if duration > 0 else 0.0,
                self.flags['fin'], self.flags['syn'],
                self.flags['rst'], self.flags['psh'],
                self.flags['ack'], self.flags['ece'],
                self.flags['cwr'], self.flags['ack'],
                self.flags['syn'], self.flags['fin'],
                self.flags['urg'], self.flags['rst'],
                self.protocols.get('HTTP', 0), self.protocols.get('HTTPS', 0),
                self.protocols.get('DNS', 0), self.protocols.get('Telnet', 0),
                self.protocols.get('SMTP', 0), self.protocols.get('SSH', 0),
                self.protocols.get('IRC', 0), self.protocols.get('TCP', 0),
                self.protocols.get('UDP', 0), self.protocols.get('DHCP', 0),
                self.protocols.get('ARP', 0), self.protocols.get('ICMP', 0),
                1.0, self.protocols.get('LLC', 0),
                self.total_bytes,
                float(sizes.min()) if sizes.size > 0 else 0.0,
                float(sizes.max()) if sizes.size > 0 else 0.0,
                float(sizes.mean()) if sizes.size > 0 else 0.0,
                float(sizes.std()) if sizes.size > 0 else 0.0,
                self.total_bytes,
                np.diff(self.packet_times).mean() if len(self.packet_times) > 1 else 0.0,
                float(self.packet_count),
                np.sqrt((sizes**2).sum()),
                np.sqrt((sizes**2).mean()),
                covariance,
                sizes.var() if sizes.size > 0 else 0.0,
                np.log1p(self.total_bytes) * covariance / (np.sqrt((sizes**2).mean()) + 1e-6)
            ]
        except Exception as e:
            print(f"Feature calculation error: {e}")
            return [self.src, self.dst] + [0.0]*(len(CSV_HEADER)-2)

def get_network_interface():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address == local_ip:
                    return interface
    except Exception as e:
        print(f"Interface detection failed: {e}")
    return None

def initialize_output_files():
    try:
        with open(OUTPUT_CSV, 'w', newline='') as f:
            csv.writer(f).writerow(CSV_HEADER)
        open(PCAP_OUTPUT, 'wb').close()
        print("Output files initialized successfully")
    except Exception as e:
        print(f"File initialization error: {e}")
        sys.exit(1)

def main():
    interface = get_network_interface()
    if not interface:
        print("No active network interface found")
        sys.exit(1)

    initialize_output_files()
    
    active_flows = {}
    capture = pyshark.LiveCapture(
        interface=interface,
        display_filter=CAPTURE_FILTER,
        output_file=str(PCAP_OUTPUT)
    )
    
    try:
        for packet in capture.sniff_continuously():
            try:
                if 'IP' not in packet:
                    continue

                # Extract basic information
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                proto = 'IP'
                sport = ''
                dport = ''

                # Get transport protocol
                if 'TCP' in packet:
                    proto = 'TCP'
                    sport = packet.tcp.srcport
                    dport = packet.tcp.dstport
                elif 'UDP' in packet:
                    proto = 'UDP'
                    sport = packet.udp.srcport
                    dport = packet.udp.dstport

                # Create flow key (bidirectional)
                sorted_ips = sorted([src_ip, dst_ip])
                flow_key = tuple(sorted_ips + [sport, dport, proto])

                # Create new flow if needed
                if flow_key not in active_flows:
                    active_flows[flow_key] = FlowTracker(
                        src=src_ip,
                        dst=dst_ip,
                        sport=sport,
                        dport=dport,
                        proto=proto
                    )
                
                # Update flow with packet
                active_flows[flow_key].add_packet(packet)

                # Check for expired flows
                current_time = time.time()
                for key in list(active_flows.keys()):
                    flow = active_flows[key]
                    if flow.is_expired(current_time):
                        features = flow.get_features()
                        with open(OUTPUT_CSV, 'a', newline='') as f:
                            csv.writer(f).writerow(features)
                        print(f"Recorded flow: {key[0]} -> {key[1]} ({proto})")
                        del active_flows[key]

            except Exception as e:
                print(f"Packet handling error: {e}")

    except KeyboardInterrupt:
        print("\nFinalizing flows...")
        for flow in active_flows.values():
            features = flow.get_features()
            with open(OUTPUT_CSV, 'a', newline='') as f:
                csv.writer(f).writerow(features)
        print("Capture stopped successfully")

if __name__ == '__main__':
    main()