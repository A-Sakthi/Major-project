import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any
from collections import defaultdict, deque
import statistics
import math

class NetworkFeatureExtractor:
    """
    Comprehensive feature extraction system for network traffic analysis.
    Extracts packet-level, flow-level, node-level, and edge-level features
    for machine learning and anomaly detection.
    """
    
    def __init__(self, flow_timeout: int = 60, feature_window: int = 300):
        self.flow_timeout = flow_timeout  # Seconds before flow expires
        self.feature_window = feature_window  # Seconds for temporal features
        
        # Data storage for feature extraction
        self.flows = {}  # Active flows
        self.packet_buffer = deque(maxlen=10000)  # Recent packets
        self.node_features = defaultdict(dict)  # Node-level features
        self.edge_features = defaultdict(dict)  # Edge-level features
        
        # Feature statistics
        self.feature_stats = {
            'packets_processed': 0,
            'flows_created': 0,
            'features_extracted': 0,
            'last_extraction': None
        }
    
    def extract_packet_features(self, packet_data: Dict) -> Dict:
        """
        Extract packet-level features from a single packet.
        
        Args:
            packet_data: Dictionary containing packet information
            
        Returns:
            Dictionary of packet-level features
        """
        try:
            # Store packet for temporal analysis
            packet_data['extraction_time'] = datetime.now()
            self.packet_buffer.append(packet_data)
            
            # Basic packet features
            features = {
                'packet_size': packet_data.get('length', 0),
                'protocol_type': self._encode_protocol(packet_data.get('protocol', 'OTHER')),
                'port_number': packet_data.get('dst_port', 0),
                'src_port': packet_data.get('src_port', 0),
                'is_tcp': 1 if packet_data.get('protocol') == 'TCP' else 0,
                'is_udp': 1 if packet_data.get('protocol') == 'UDP' else 0,
                'is_icmp': 1 if packet_data.get('protocol') == 'ICMP' else 0,
            }
            
            # TCP-specific features
            if packet_data.get('protocol') == 'TCP':
                features.update(self._extract_tcp_features(packet_data))
            
            # Time-based features
            features.update(self._extract_temporal_features(packet_data))
            
            # IP-based features
            features.update(self._extract_ip_features(packet_data))
            
            self.feature_stats['packets_processed'] += 1
            return features
            
        except Exception as e:
            print(f"Error extracting packet features: {e}")
            return {}
    
    def extract_flow_features(self, flow_id: str) -> Dict:
        """
        Extract flow-level features from accumulated packet data.
        
        Args:
            flow_id: Unique identifier for the flow
            
        Returns:
            Dictionary of flow-level features
        """
        try:
            if flow_id not in self.flows:
                return {}
            
            flow_data = self.flows[flow_id]
            packets = flow_data.get('packets', [])
            
            if not packets:
                return {}
            
            # Basic flow statistics
            features = {
                'flow_duration': self._calculate_flow_duration(packets),
                'total_packets': len(packets),
                'total_bytes': sum(p.get('length', 0) for p in packets),
                'avg_packet_size': statistics.mean([p.get('length', 0) for p in packets]),
                'std_packet_size': statistics.stdev([p.get('length', 0) for p in packets]) if len(packets) > 1 else 0,
                'min_packet_size': min(p.get('length', 0) for p in packets),
                'max_packet_size': max(p.get('length', 0) for p in packets),
            }
            
            # Packet rate features
            duration = features['flow_duration']
            if duration > 0:
                features.update({
                    'packets_per_second': features['total_packets'] / duration,
                    'bytes_per_second': features['total_bytes'] / duration,
                })
            else:
                features.update({
                    'packets_per_second': 0,
                    'bytes_per_second': 0,
                })
            
            # Inter-arrival time features
            features.update(self._extract_inter_arrival_features(packets))
            
            # Directional features
            features.update(self._extract_directional_features(packets))
            
            # Protocol distribution
            features.update(self._extract_protocol_distribution(packets))
            
            # Port analysis
            features.update(self._extract_port_features(packets))
            
            # Flag analysis (for TCP)
            features.update(self._extract_flag_features(packets))
            
            self.feature_stats['features_extracted'] += 1
            return features
            
        except Exception as e:
            print(f"Error extracting flow features: {e}")
            return {}
    
    def extract_node_features(self, node_id: str, graph_data: Dict) -> Dict:
        """
        Extract node-level features from graph topology.
        
        Args:
            node_id: IP address or node identifier
            graph_data: Graph structure data
            
        Returns:
            Dictionary of node-level features
        """
        try:
            nodes = graph_data.get('nodes', [])
            edges = graph_data.get('edges', [])
            
            # Find node data
            node_data = None
            for node in nodes:
                if node.get('id') == node_id:
                    node_data = node
                    break
            
            if not node_data:
                return {}
            
            # Basic node features
            features = {
                'degree': self._calculate_node_degree(node_id, edges),
                'in_degree': self._calculate_in_degree(node_id, edges),
                'out_degree': self._calculate_out_degree(node_id, edges),
                'total_packets': node_data.get('packet_count', 0),
                'bytes_sent': node_data.get('bytes_sent', 0),
                'bytes_received': node_data.get('bytes_received', 0),
                'unique_protocols': len(node_data.get('protocols', [])),
                'unique_ports': len(node_data.get('ports', [])),
            }
            
            # Centrality measures (simplified)
            features.update({
                'degree_centrality': features['degree'] / max(len(nodes) - 1, 1),
                'closeness_centrality': self._estimate_closeness_centrality(node_id, edges),
                'betweenness_centrality': self._estimate_betweenness_centrality(node_id, edges),
            })
            
            # Activity patterns
            features.update(self._extract_node_activity_patterns(node_data))
            
            # Communication patterns
            features.update(self._extract_communication_patterns(node_id, edges))
            
            return features
            
        except Exception as e:
            print(f"Error extracting node features: {e}")
            return {}
    
    def extract_edge_features(self, src_node: str, dst_node: str, graph_data: Dict) -> Dict:
        """
        Extract edge-level features from network connections.
        
        Args:
            src_node: Source node ID
            dst_node: Destination node ID  
            graph_data: Graph structure data
            
        Returns:
            Dictionary of edge-level features
        """
        try:
            edges = graph_data.get('edges', [])
            
            # Find edge data
            edge_data = None
            for edge in edges:
                if edge.get('source') == src_node and edge.get('target') == dst_node:
                    edge_data = edge
                    break
            
            if not edge_data:
                return {}
            
            # Basic edge features
            features = {
                'packet_count': edge_data.get('packet_count', 0),
                'total_bytes': edge_data.get('total_bytes', 0),
                'avg_packet_size': edge_data.get('total_bytes', 0) / max(edge_data.get('packet_count', 1), 1),
                'weight': edge_data.get('weight', 0),
                'unique_protocols': len(edge_data.get('protocols', [])),
                'unique_ports': len(edge_data.get('ports', [])),
                'unique_flows': len(edge_data.get('flows', [])),
            }
            
            # Temporal features
            features.update(self._extract_edge_temporal_features(edge_data))
            
            # Traffic pattern features
            features.update(self._extract_traffic_patterns(edge_data))
            
            return features
            
        except Exception as e:
            print(f"Error extracting edge features: {e}")
            return {}
    
    def add_packet_to_flow(self, packet_data: Dict):
        """Add packet to its corresponding flow for flow-level analysis"""
        try:
            flow_id = packet_data.get('flow_id')
            if not flow_id:
                return
            
            current_time = datetime.now()
            
            # Create flow if it doesn't exist
            if flow_id not in self.flows:
                self.flows[flow_id] = {
                    'packets': [],
                    'first_seen': current_time,
                    'last_seen': current_time,
                    'src_ip': packet_data.get('src_ip'),
                    'dst_ip': packet_data.get('dst_ip'),
                    'protocol': packet_data.get('protocol')
                }
                self.feature_stats['flows_created'] += 1
            
            # Add packet to flow
            self.flows[flow_id]['packets'].append(packet_data)
            self.flows[flow_id]['last_seen'] = current_time
            
            # Clean up old flows
            self._cleanup_expired_flows(current_time)
            
        except Exception as e:
            print(f"Error adding packet to flow: {e}")
    
    def _extract_tcp_features(self, packet_data: Dict) -> Dict:
        """Extract TCP-specific features"""
        features = {}
        
        flags = packet_data.get('flags', '')
        features.update({
            'tcp_flag_syn': 1 if 'S' in flags else 0,
            'tcp_flag_ack': 1 if 'A' in flags else 0,
            'tcp_flag_fin': 1 if 'F' in flags else 0,
            'tcp_flag_rst': 1 if 'R' in flags else 0,
            'tcp_flag_psh': 1 if 'P' in flags else 0,
            'tcp_flag_urg': 1 if 'U' in flags else 0,
        })
        
        return features
    
    def _extract_temporal_features(self, packet_data: Dict) -> Dict:
        """Extract time-based features"""
        features = {}
        
        current_time = datetime.now()
        
        # Hour of day (0-23)
        features['hour_of_day'] = current_time.hour
        
        # Day of week (0-6)
        features['day_of_week'] = current_time.weekday()
        
        # Time since last packet (if available)
        if len(self.packet_buffer) > 1:
            last_packet_time = self.packet_buffer[-2].get('extraction_time', current_time)
            time_delta = (current_time - last_packet_time).total_seconds()
            features['inter_arrival_time'] = time_delta
        else:
            features['inter_arrival_time'] = 0
        
        return features
    
    def _extract_ip_features(self, packet_data: Dict) -> Dict:
        """Extract IP-based features"""
        features = {}
        
        src_ip = packet_data.get('src_ip', '')
        dst_ip = packet_data.get('dst_ip', '')
        
        # Check if IPs are private
        features.update({
            'src_is_private': 1 if self._is_private_ip(src_ip) else 0,
            'dst_is_private': 1 if self._is_private_ip(dst_ip) else 0,
            'src_is_localhost': 1 if src_ip.startswith('127.') else 0,
            'dst_is_localhost': 1 if dst_ip.startswith('127.') else 0,
        })
        
        # TTL analysis
        ttl = packet_data.get('ttl', 64)
        features['ttl'] = ttl
        features['ttl_class'] = self._classify_ttl(ttl)
        
        return features
    
    def _extract_inter_arrival_features(self, packets: List[Dict]) -> Dict:
        """Extract inter-arrival time statistics"""
        if len(packets) < 2:
            return {
                'avg_inter_arrival': 0,
                'std_inter_arrival': 0,
                'min_inter_arrival': 0,
                'max_inter_arrival': 0
            }
        
        # Calculate inter-arrival times
        inter_arrivals = []
        for i in range(1, len(packets)):
            prev_time = packets[i-1].get('extraction_time', datetime.now())
            curr_time = packets[i].get('extraction_time', datetime.now())
            inter_arrival = (curr_time - prev_time).total_seconds()
            inter_arrivals.append(inter_arrival)
        
        return {
            'avg_inter_arrival': statistics.mean(inter_arrivals),
            'std_inter_arrival': statistics.stdev(inter_arrivals) if len(inter_arrivals) > 1 else 0,
            'min_inter_arrival': min(inter_arrivals),
            'max_inter_arrival': max(inter_arrivals)
        }
    
    def _extract_directional_features(self, packets: List[Dict]) -> Dict:
        """Extract directional flow features"""
        forward_packets = 0
        backward_packets = 0
        forward_bytes = 0
        backward_bytes = 0
        
        if not packets:
            return {
                'forward_packets': 0,
                'backward_packets': 0,
                'forward_bytes': 0,
                'backward_bytes': 0,
                'forward_backward_ratio': 0
            }
        
        # Use first packet to determine flow direction
        first_src = packets[0].get('src_ip')
        first_dst = packets[0].get('dst_ip')
        
        for packet in packets:
            packet_length = packet.get('length', 0)
            
            if packet.get('src_ip') == first_src and packet.get('dst_ip') == first_dst:
                forward_packets += 1
                forward_bytes += packet_length
            else:
                backward_packets += 1
                backward_bytes += packet_length
        
        ratio = forward_packets / max(backward_packets, 1)
        
        return {
            'forward_packets': forward_packets,
            'backward_packets': backward_packets,
            'forward_bytes': forward_bytes,
            'backward_bytes': backward_bytes,
            'forward_backward_ratio': ratio
        }
    
    def _extract_protocol_distribution(self, packets: List[Dict]) -> Dict:
        """Extract protocol distribution features"""
        protocol_counts = defaultdict(int)
        
        for packet in packets:
            protocol = packet.get('protocol', 'OTHER')
            protocol_counts[protocol] += 1
        
        total_packets = len(packets)
        
        return {
            'tcp_ratio': protocol_counts['TCP'] / max(total_packets, 1),
            'udp_ratio': protocol_counts['UDP'] / max(total_packets, 1),
            'icmp_ratio': protocol_counts['ICMP'] / max(total_packets, 1),
            'protocol_diversity': len(protocol_counts)
        }
    
    def _extract_port_features(self, packets: List[Dict]) -> Dict:
        """Extract port-based features"""
        src_ports = set()
        dst_ports = set()
        well_known_ports = 0
        
        for packet in packets:
            src_port = packet.get('src_port')
            dst_port = packet.get('dst_port')
            
            if src_port:
                src_ports.add(src_port)
            if dst_port:
                dst_ports.add(dst_port)
                # Well-known ports (0-1023)
                if dst_port <= 1023:
                    well_known_ports += 1
        
        return {
            'unique_src_ports': len(src_ports),
            'unique_dst_ports': len(dst_ports),
            'well_known_port_ratio': well_known_ports / max(len(packets), 1)
        }
    
    def _extract_flag_features(self, packets: List[Dict]) -> Dict:
        """Extract TCP flag distribution"""
        flag_counts = defaultdict(int)
        
        for packet in packets:
            flags = packet.get('flags', '')
            if 'S' in flags:
                flag_counts['SYN'] += 1
            if 'A' in flags:
                flag_counts['ACK'] += 1
            if 'F' in flags:
                flag_counts['FIN'] += 1
            if 'R' in flags:
                flag_counts['RST'] += 1
        
        total_tcp = sum(1 for p in packets if p.get('protocol') == 'TCP')
        
        return {
            'syn_ratio': flag_counts['SYN'] / max(total_tcp, 1),
            'ack_ratio': flag_counts['ACK'] / max(total_tcp, 1),
            'fin_ratio': flag_counts['FIN'] / max(total_tcp, 1),
            'rst_ratio': flag_counts['RST'] / max(total_tcp, 1)
        }
    
    def _calculate_flow_duration(self, packets: List[Dict]) -> float:
        """Calculate flow duration in seconds"""
        if len(packets) < 2:
            return 0
        
        try:
            first_time = packets[0].get('extraction_time', datetime.now())
            last_time = packets[-1].get('extraction_time', datetime.now())
            return (last_time - first_time).total_seconds()
        except:
            return 0
    
    def _calculate_node_degree(self, node_id: str, edges: List[Dict]) -> int:
        """Calculate total degree of a node"""
        degree = 0
        for edge in edges:
            if edge.get('source') == node_id or edge.get('target') == node_id:
                degree += 1
        return degree
    
    def _calculate_in_degree(self, node_id: str, edges: List[Dict]) -> int:
        """Calculate in-degree of a node"""
        return sum(1 for edge in edges if edge.get('target') == node_id)
    
    def _calculate_out_degree(self, node_id: str, edges: List[Dict]) -> int:
        """Calculate out-degree of a node"""
        return sum(1 for edge in edges if edge.get('source') == node_id)
    
    def _encode_protocol(self, protocol: str) -> int:
        """Encode protocol as numeric value"""
        protocol_map = {'TCP': 1, 'UDP': 2, 'ICMP': 3, 'OTHER': 0}
        return protocol_map.get(protocol.upper(), 0)
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP address is private"""
        if not ip:
            return False
        
        private_ranges = [
            '10.', '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
            '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
            '172.30.', '172.31.', '192.168.'
        ]
        
        return any(ip.startswith(prefix) for prefix in private_ranges)
    
    def _classify_ttl(self, ttl: int) -> int:
        """Classify TTL into categories"""
        if ttl <= 32:
            return 1  # Low TTL
        elif ttl <= 64:
            return 2  # Medium TTL
        elif ttl <= 128:
            return 3  # High TTL
        else:
            return 4  # Very high TTL
    
    def _cleanup_expired_flows(self, current_time: datetime):
        """Remove expired flows"""
        expired_flows = []
        cutoff_time = current_time - timedelta(seconds=self.flow_timeout)
        
        for flow_id, flow_data in self.flows.items():
            if flow_data['last_seen'] < cutoff_time:
                expired_flows.append(flow_id)
        
        for flow_id in expired_flows:
            del self.flows[flow_id]
    
    def _extract_node_activity_patterns(self, node_data: Dict) -> Dict:
        """Extract node activity patterns"""
        return {
            'activity_ratio': min(node_data.get('packet_count', 0) / 1000, 1),  # Normalized activity
            'bytes_per_packet': node_data.get('bytes_sent', 0) / max(node_data.get('packet_count', 1), 1)
        }
    
    def _extract_communication_patterns(self, node_id: str, edges: List[Dict]) -> Dict:
        """Extract communication patterns for a node"""
        connections = sum(1 for edge in edges 
                         if edge.get('source') == node_id or edge.get('target') == node_id)
        
        return {
            'connection_diversity': connections,
            'communication_intensity': connections / 10  # Normalized
        }
    
    def _estimate_closeness_centrality(self, node_id: str, edges: List[Dict]) -> float:
        """Estimate closeness centrality (simplified)"""
        # Simplified estimation based on direct connections
        direct_connections = self._calculate_node_degree(node_id, edges)
        return direct_connections / max(len(edges), 1)
    
    def _estimate_betweenness_centrality(self, node_id: str, edges: List[Dict]) -> float:
        """Estimate betweenness centrality (simplified)"""
        # Simplified estimation
        return self._calculate_node_degree(node_id, edges) / max(len(edges), 1)
    
    def _extract_edge_temporal_features(self, edge_data: Dict) -> Dict:
        """Extract temporal features for edges"""
        return {
            'edge_age': (datetime.now() - edge_data.get('first_seen', datetime.now())).total_seconds(),
            'last_activity': (datetime.now() - edge_data.get('last_seen', datetime.now())).total_seconds()
        }
    
    def _extract_traffic_patterns(self, edge_data: Dict) -> Dict:
        """Extract traffic pattern features"""
        return {
            'traffic_intensity': edge_data.get('packet_count', 0) / 100,  # Normalized
            'bandwidth_utilization': edge_data.get('total_bytes', 0) / 1000000  # Normalized to MB
        }
    
    def get_comprehensive_features(self, packet_data: Dict, flow_id: str, graph_data: Dict) -> Dict:
        """
        Extract comprehensive features combining all levels.
        
        Args:
            packet_data: Current packet data
            flow_id: Flow identifier
            graph_data: Current graph state
            
        Returns:
            Dictionary containing all extracted features
        """
        try:
            # Add packet to flow first
            self.add_packet_to_flow(packet_data)
            
            # Extract all feature levels
            features = {
                'packet_features': self.extract_packet_features(packet_data),
                'flow_features': self.extract_flow_features(flow_id),
                'node_features': {
                    'source': self.extract_node_features(packet_data.get('src_ip', ''), graph_data),
                    'destination': self.extract_node_features(packet_data.get('dst_ip', ''), graph_data)
                },
                'edge_features': self.extract_edge_features(
                    packet_data.get('src_ip', ''), 
                    packet_data.get('dst_ip', ''), 
                    graph_data
                ),
                'timestamp': datetime.now().isoformat(),
                'flow_id': flow_id
            }
            
            self.feature_stats['last_extraction'] = datetime.now()
            return features
            
        except Exception as e:
            print(f"Error extracting comprehensive features: {e}")
            return {}
    
    def get_stats(self) -> Dict:
        """Get feature extraction statistics"""
        return self.feature_stats.copy()
    
    def reset(self):
        """Reset all feature extraction data"""
        self.flows.clear()
        self.packet_buffer.clear()
        self.node_features.clear()
        self.edge_features.clear()
        
        self.feature_stats = {
            'packets_processed': 0,
            'flows_created': 0,
            'features_extracted': 0,
            'last_extraction': None
        }
        
        print("🔄 Feature extractor reset")


if __name__ == "__main__":
    # Example usage
    feature_extractor = NetworkFeatureExtractor()
    
    print("🔍 Network Feature Extractor Test")
    
    # Sample packet data
    packet = {
        'src_ip': '192.168.1.100',
        'dst_ip': '8.8.8.8',
        'src_port': 45678,
        'dst_port': 80,
        'protocol': 'TCP',
        'length': 1024,
        'flags': 'SA',
        'ttl': 64,
        'flow_id': 'test_flow_1'
    }
    
    # Sample graph data
    graph_data = {
        'nodes': [
            {'id': '192.168.1.100', 'packet_count': 50, 'bytes_sent': 5000, 
             'bytes_received': 3000, 'protocols': ['TCP', 'UDP'], 'ports': [80, 443, 22]}
        ],
        'edges': [
            {'source': '192.168.1.100', 'target': '8.8.8.8', 'packet_count': 25,
             'total_bytes': 2500, 'weight': 0.8, 'protocols': ['TCP'], 'ports': [80],
             'flows': ['test_flow_1'], 'first_seen': datetime.now(), 'last_seen': datetime.now()}
        ]
    }
    
    # Extract comprehensive features
    features = feature_extractor.get_comprehensive_features(packet, 'test_flow_1', graph_data)
    
    print(f"\n📊 Extracted Features:")
    print(f"  Packet features: {len(features.get('packet_features', {}))}")
    print(f"  Flow features: {len(features.get('flow_features', {}))}")
    print(f"  Node features: {len(features.get('node_features', {}).get('source', {}))}")
    print(f"  Edge features: {len(features.get('edge_features', {}))}")
    
    # Print some sample features
    packet_features = features.get('packet_features', {})
    print(f"\n🔍 Sample Packet Features:")
    for key, value in list(packet_features.items())[:5]:
        print(f"  {key}: {value}")
    
    # Print stats
    stats = feature_extractor.get_stats()
    print(f"\n📈 Feature Extractor Stats:")
    for key, value in stats.items():
        print(f"  {key}: {value}")