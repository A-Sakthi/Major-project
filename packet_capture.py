import threading
import time
from datetime import datetime
from typing import Dict, List, Optional, Callable
import uuid
import queue
import json

try:
    from scapy.all import sniff, get_if_list, conf
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether
    SCAPY_AVAILABLE = True
    print("✅ Scapy loaded - Real packet capture available")
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️  Scapy not available. Install with: pip install scapy")
    print("⚠️  Using mock packet capture for demonstration")

class RealTimePacketCapture:
    """
    Real-time network packet capture system using Python and Scapy.
    Captures live network traffic and processes packets in real-time.
    """
    
    def __init__(self):
        self.is_capturing = False
        self.capture_thread = None
        self.packet_queue = queue.Queue()
        self.stats = {
            'total_packets': 0,
            'packets_per_second': 0,
            'bytes_captured': 0,
            'start_time': None,
            'last_packet_time': None,
            'protocols': {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'OTHER': 0}
        }
        self.callbacks = []
        self.interfaces = self._get_interfaces()
        
        # Rate calculation
        self.packet_count_last_second = 0
        self.rate_thread = None
        self.stop_rate_calculation = False
        
        # Local network filtering
        self.local_only_mode = False
        self.local_ranges = [
            # Standard private IP ranges (RFC 1918)
            "192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
            "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
            # Loopback and localhost
            "127.", "localhost",
            # Common VM and container ranges
            "172.17.", "172.18.", "172.19.", "172.20.",  # Docker default ranges
            "192.168.122.", "192.168.99.", "192.168.56.", # VirtualBox/VMware common ranges
            "10.0.2.", "10.0.0.", "10.1.1.", # VirtualBox NAT
            "172.24.", "172.25.", "172.26.", # VMware ranges
            "169.254.", # Link-local addresses
            # Hyper-V common ranges
            "192.168.137.", "192.168.138.", "192.168.139.",
            # WSL2 ranges
            "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21."
        ]
        
    def set_local_only_mode(self, enabled: bool):
        """Enable or disable local network only mode"""
        self.local_only_mode = enabled
        mode_status = "ENABLED" if enabled else "DISABLED"
        print(f"🏠 Local network only mode: {mode_status}")
        
    def is_local_network_packet(self, src_ip: str, dst_ip: str) -> bool:
        """Check if packet is within local network ranges - STRICT mode: both src and dst must be local"""
        # Check if source is local
        src_local = any(src_ip.startswith(range_prefix) for range_prefix in self.local_ranges)
        # Check if destination is local  
        dst_local = any(dst_ip.startswith(range_prefix) for range_prefix in self.local_ranges)
        
        # In strict local mode, BOTH source AND destination must be local
        return src_local and dst_local
        
    def _get_interfaces(self) -> List[str]:
        """Get available network interfaces"""
        if SCAPY_AVAILABLE:
            try:
                return get_if_list()
            except:
                return ['eth0', 'wlan0', 'lo']
        else:
            # Mock interfaces for demonstration
            return ['mock_eth0', 'mock_wlan0', 'mock_loopback']
    
    def add_packet_callback(self, callback: Callable):
        """Add a callback function to be called for each captured packet"""
        self.callbacks.append(callback)
    
    def remove_packet_callback(self, callback: Callable):
        """Remove a packet callback"""
        if callback in self.callbacks:
            self.callbacks.remove(callback)
    
    def start_capture(self, interface: str = None, packet_filter: str = None):
        """
        Start real-time packet capture
        
        Args:
            interface: Network interface to capture from (e.g., 'eth0', 'wlan0')
            packet_filter: BPF filter string (e.g., 'tcp port 80', 'icmp')
        """
        if self.is_capturing:
            raise Exception("Packet capture is already running")
        
        self.is_capturing = True
        self.stats['start_time'] = datetime.now()
        self.stats['total_packets'] = 0
        self.stats['bytes_captured'] = 0
        
        print(f"🚀 Starting packet capture...")
        print(f"📡 Interface: {interface or 'default'}")
        print(f"🔍 Filter: {packet_filter or 'none (all packets)'}")
        print(f"💡 Try pinging this machine or browsing websites to see packets!")
        
        # Start rate calculation thread
        self.stop_rate_calculation = False
        self.rate_thread = threading.Thread(target=self._calculate_rate, daemon=True)
        self.rate_thread.start()
        
        # Start packet capture
        if SCAPY_AVAILABLE:
            self.capture_thread = threading.Thread(
                target=self._real_packet_capture,
                args=(interface, packet_filter),
                daemon=True
            )
        else:
            self.capture_thread = threading.Thread(
                target=self._mock_packet_capture,
                daemon=True
            )
        
        self.capture_thread.start()
        return True
    
    def stop_capture(self):
        """Stop packet capture"""
        if not self.is_capturing:
            return False
        
        print("🛑 Stopping packet capture...")
        self.is_capturing = False
        self.stop_rate_calculation = True
        
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
        if self.rate_thread:
            self.rate_thread.join(timeout=2)
            
        print("✅ Packet capture stopped")
        return True
    
    def _real_packet_capture(self, interface: str, packet_filter: str):
        """Real packet capture using Scapy"""
        try:
            print("🔥 Starting real-time packet sniffing...")
            sniff(
                iface=interface,
                filter=packet_filter,
                prn=self._process_packet,
                stop_filter=lambda x: not self.is_capturing,
                store=False  # Don't store packets in memory
            )
        except Exception as e:
            print(f"❌ Error in packet capture: {e}")
            self.is_capturing = False
    
    def _mock_packet_capture(self):
        """Mock packet capture for demonstration"""
        print("🎭 Starting mock packet capture (for demonstration)")
        print("💡 Install scapy for real packet capture: pip install scapy")
        
        import random
        protocols = ['TCP', 'UDP', 'ICMP']
        
        while self.is_capturing:
            # Generate mock packet data
            mock_packet_data = {
                'timestamp': datetime.now().isoformat(),
                'src_ip': f"192.168.1.{random.randint(1, 254)}",
                'dst_ip': f"192.168.1.{random.randint(1, 254)}",
                'src_port': random.randint(1024, 65535),
                'dst_port': random.choice([80, 443, 53, 22, 21, 25]),
                'protocol': random.choice(protocols),
                'length': random.randint(64, 1500),
                'flags': 'SYN' if random.random() > 0.5 else 'ACK',
            }
            
            self._process_mock_packet(mock_packet_data)
            time.sleep(random.uniform(0.1, 2.0))  # Simulate varying packet rates
    
    def _process_packet(self, packet):
        """Process a real captured packet"""
        try:
            packet_data = self._extract_packet_info(packet)
            if packet_data:
                # Skip packets with empty or invalid IPs first
                src_ip = packet_data.get('src_ip', '')
                dst_ip = packet_data.get('dst_ip', '')
                
                # Skip packets with empty, null, or invalid IP addresses
                if not src_ip or not dst_ip or src_ip in ['', '0.0.0.0', 'null', 'None'] or dst_ip in ['', '0.0.0.0', 'null', 'None']:
                    return  # Skip invalid packets early
                
                # Apply local network filter if enabled
                if self.local_only_mode:
                    if not self.is_local_network_packet(src_ip, dst_ip):
                        return  # Skip non-local-to-local packets
                
                self._update_stats(packet_data)
                self._notify_callbacks(packet_data)
        except Exception as e:
            print(f"Error processing packet: {e}")
    
    def _process_mock_packet(self, packet_data):
        """Process a mock packet"""
        packet_data['id'] = str(uuid.uuid4())
        packet_data['flow_id'] = self._generate_flow_id(packet_data)
        
        # Apply local network filter if enabled
        if self.local_only_mode:
            src_ip = packet_data.get('src_ip', '')
            dst_ip = packet_data.get('dst_ip', '')
            if not self.is_local_network_packet(src_ip, dst_ip):
                return  # Skip non-local packets
        
        self._update_stats(packet_data)
        self._notify_callbacks(packet_data)
    
    def _extract_packet_info(self, packet) -> Optional[Dict]:
        """Extract relevant information from a Scapy packet"""
        try:
            packet_info = {
                'id': str(uuid.uuid4()),
                'timestamp': datetime.now().isoformat(),
                'length': len(packet)
            }
            
            # Extract IP layer info
            if IP in packet:
                packet_info.update({
                    'src_ip': packet[IP].src,
                    'dst_ip': packet[IP].dst,
                    'protocol': packet[IP].proto,
                    'ttl': packet[IP].ttl,
                })
                
                # Extract TCP info
                if TCP in packet:
                    packet_info.update({
                        'src_port': packet[TCP].sport,
                        'dst_port': packet[TCP].dport,
                        'flags': str(packet[TCP].flags),
                        'protocol': 'TCP'
                    })
                
                # Extract UDP info
                elif UDP in packet:
                    packet_info.update({
                        'src_port': packet[UDP].sport,
                        'dst_port': packet[UDP].dport,
                        'protocol': 'UDP'
                    })
                
                # Extract ICMP info
                elif ICMP in packet:
                    packet_info.update({
                        'protocol': 'ICMP',
                        'icmp_type': packet[ICMP].type,
                        'icmp_code': packet[ICMP].code
                    })
            
            # Generate flow ID
            packet_info['flow_id'] = self._generate_flow_id(packet_info)
            
            return packet_info
            
        except Exception as e:
            print(f"Error extracting packet info: {e}")
            return None
    
    def _generate_flow_id(self, packet_data: Dict) -> str:
        """Generate a unique flow identifier"""
        try:
            src_ip = packet_data.get('src_ip', '')
            dst_ip = packet_data.get('dst_ip', '')
            src_port = packet_data.get('src_port', 0)
            dst_port = packet_data.get('dst_port', 0)
            protocol = packet_data.get('protocol', '')
            
            # Create bidirectional flow ID
            endpoints = sorted([f"{src_ip}:{src_port}", f"{dst_ip}:{dst_port}"])
            return f"{endpoints[0]}_{endpoints[1]}_{protocol}"
        except:
            return str(uuid.uuid4())
    
    def _update_stats(self, packet_data: Dict):
        """Update capture statistics"""
        self.stats['total_packets'] += 1
        self.packet_count_last_second += 1
        self.stats['bytes_captured'] += packet_data.get('length', 0)
        self.stats['last_packet_time'] = datetime.now()
        
        # Update protocol counts
        protocol = packet_data.get('protocol', 'OTHER')
        if protocol in self.stats['protocols']:
            self.stats['protocols'][protocol] += 1
        else:
            self.stats['protocols']['OTHER'] += 1
    
    def _notify_callbacks(self, packet_data: Dict):
        """Notify all registered callbacks about the new packet"""
        for callback in self.callbacks:
            try:
                callback(packet_data)
            except Exception as e:
                print(f"Error in packet callback: {e}")
    
    def _calculate_rate(self):
        """Calculate packets per second in a separate thread"""
        while not self.stop_rate_calculation:
            time.sleep(1)
            self.stats['packets_per_second'] = self.packet_count_last_second
            self.packet_count_last_second = 0
            
            # Print periodic stats
            if self.stats['packets_per_second'] > 0:
                print(f"📊 Rate: {self.stats['packets_per_second']} pps | "
                      f"Total: {self.stats['total_packets']} packets | "
                      f"Bytes: {self.stats['bytes_captured']:,}")
    
    def get_stats(self) -> Dict:
        """Get current capture statistics"""
        uptime = 0
        if self.stats['start_time']:
            uptime = (datetime.now() - self.stats['start_time']).total_seconds()
        
        return {
            **self.stats,
            'is_capturing': self.is_capturing,
            'uptime_seconds': uptime,
            'average_pps': self.stats['total_packets'] / max(uptime, 1),
            'scapy_available': SCAPY_AVAILABLE
        }
    
    def get_interfaces(self) -> List[str]:
        """Get available network interfaces"""
        return self.interfaces
    
    def reset_stats(self):
        """Reset capture statistics"""
        self.stats = {
            'total_packets': 0,
            'packets_per_second': 0,
            'bytes_captured': 0,
            'start_time': None,
            'last_packet_time': None,
            'protocols': {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'OTHER': 0}
        }
        print("📊 Statistics reset")


if __name__ == "__main__":
    # Example usage
    def packet_handler(packet_data):
        """Example packet handler"""
        print(f"📦 Packet: {packet_data['src_ip']}:{packet_data.get('src_port', '')} -> "
              f"{packet_data['dst_ip']}:{packet_data.get('dst_port', '')} "
              f"({packet_data['protocol']}) {packet_data['length']} bytes")
    
    # Create packet capture instance
    capture = RealTimePacketCapture()
    
    # Add packet handler
    capture.add_packet_callback(packet_handler)
    
    print("🌐 Network Traffic Analyzer")
    print(f"Available interfaces: {capture.get_interfaces()}")
    
    try:
        # Start capture (use None for default interface)
        capture.start_capture(interface=None, packet_filter=None)
        
        print("\n💡 Testing instructions:")
        print("1. Open another terminal/command prompt")
        print("2. Run: ping 8.8.8.8")
        print("3. Run: ping localhost") 
        print("4. Open a web browser and visit websites")
        print("5. Watch packets appear in real-time!")
        print("\nPress Ctrl+C to stop...\n")
        
        # Keep the main thread alive
        while capture.is_capturing:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n⏹️  Stopping capture...")
        capture.stop_capture()
        
        # Print final stats
        stats = capture.get_stats()
        print(f"\n📈 Final Statistics:")
        print(f"Total packets: {stats['total_packets']}")
        print(f"Total bytes: {stats['bytes_captured']:,}")
        print(f"Average rate: {stats['average_pps']:.2f} packets/second")
        print(f"Protocols: {stats['protocols']}")
        print(f"Uptime: {stats['uptime_seconds']:.2f} seconds")