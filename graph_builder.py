import networkx as nx
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
import threading
import time
import math

class DynamicGraphBuilder:
    """
    Dynamic graph construction with time-decay weighting.
    Builds and maintains a network graph where nodes represent network entities
    and edges represent communication patterns with exponential time decay.
    """
    
    def __init__(self, decay_lambda: float = 0.001, cleanup_interval: int = 60):
        self.graph = nx.DiGraph()  # Directed graph for network flows
        self.decay_lambda = decay_lambda  # Time decay constant
        self.cleanup_interval = cleanup_interval  # Seconds between cleanup
        self.node_last_seen = {}  # Track when nodes were last active
        self.edge_last_seen = {}  # Track when edges were last active
        self.snapshots = []  # Store temporal snapshots
        self.max_snapshots = 100  # Maximum snapshots to keep
        
        # Threading for background cleanup
        self.cleanup_thread = None
        self.should_stop_cleanup = False
        
        # Statistics
        self.stats = {
            'total_nodes': 0,
            'total_edges': 0,
            'active_nodes': 0,
            'active_edges': 0,
            'snapshots_created': 0,
            'last_cleanup': None
        }
        
        self.start_background_cleanup()
    
    def clear(self):
        """Clear all graph data"""
        self.graph.clear()
        self.node_last_seen.clear()
        self.edge_last_seen.clear()
        self.snapshots.clear()
        
        # Reset statistics
        self.stats = {
            'total_nodes': 0,
            'total_edges': 0,
            'active_nodes': 0,
            'active_edges': 0,
            'snapshots_created': 0,
            'last_cleanup': None
        }
        print("🗑️ Graph data cleared")
    
    def start_background_cleanup(self):
        """Start background thread for periodic cleanup of expired nodes/edges"""
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()
    
    def stop_background_cleanup(self):
        """Stop background cleanup thread"""
        self.should_stop_cleanup = True
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=5)
    
    def add_packet(self, packet_data: Dict):
        """
        Add a packet to the dynamic graph, updating nodes and edges.
        
        Args:
            packet_data: Dictionary containing packet information
        """
        try:
            src_ip = packet_data.get('src_ip')
            dst_ip = packet_data.get('dst_ip')
            timestamp = packet_data.get('timestamp', datetime.now().isoformat())
            
            # Filter out unknown or invalid packets
            if not src_ip or not dst_ip or src_ip == 'unknown' or dst_ip == 'unknown':
                return
            
            # Filter out empty, null, or invalid IP addresses
            if src_ip in ['', '0.0.0.0', 'null', 'None'] or dst_ip in ['', '0.0.0.0', 'null', 'None']:
                return
            
            current_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00')) if isinstance(timestamp, str) else timestamp
            
            # Add or update source node
            self._add_or_update_node(src_ip, packet_data, current_time, node_type='source')
            
            # Add or update destination node  
            self._add_or_update_node(dst_ip, packet_data, current_time, node_type='destination')
            
            # Add or update edge between nodes
            self._add_or_update_edge(src_ip, dst_ip, packet_data, current_time)
            
            # Update statistics
            self._update_stats()
            
        except Exception as e:
            print(f"Error adding packet to graph: {e}")
    
    def _add_or_update_node(self, node_id: str, packet_data: Dict, timestamp: datetime, node_type: str):
        """Add or update a node in the graph"""
        if not self.graph.has_node(node_id):
            # Create new node with attributes
            self.graph.add_node(node_id,
                first_seen=timestamp,
                last_seen=timestamp,
                packet_count=0,
                bytes_sent=0,
                bytes_received=0,
                protocols=set(),
                ports=set(),
                node_type=node_type
            )
        
        # Update node attributes
        node_attrs = self.graph.nodes[node_id]
        node_attrs['last_seen'] = timestamp
        node_attrs['packet_count'] += 1
        
        # Update byte counts
        packet_length = packet_data.get('length', 0)
        if node_type == 'source':
            node_attrs['bytes_sent'] += packet_length
        else:
            node_attrs['bytes_received'] += packet_length
        
        # Update protocols and ports
        if 'protocol' in packet_data:
            node_attrs['protocols'].add(packet_data['protocol'])
        
        for port_key in ['src_port', 'dst_port']:
            if port_key in packet_data and packet_data[port_key]:
                node_attrs['ports'].add(packet_data[port_key])
        
        # Store last seen time for cleanup
        self.node_last_seen[node_id] = timestamp
    
    def _add_or_update_edge(self, src_node: str, dst_node: str, packet_data: Dict, timestamp: datetime):
        """Add or update an edge in the graph"""
        edge_key = (src_node, dst_node)
        
        if not self.graph.has_edge(src_node, dst_node):
            # Create new edge with attributes
            self.graph.add_edge(src_node, dst_node,
                first_seen=timestamp,
                last_seen=timestamp,
                packet_count=0,
                total_bytes=0,
                protocols=set(),
                ports=set(),
                weight=1.0,
                flows=set()
            )
        
        # Update edge attributes
        edge_attrs = self.graph.edges[edge_key]
        edge_attrs['last_seen'] = timestamp
        edge_attrs['packet_count'] += 1
        edge_attrs['total_bytes'] += packet_data.get('length', 0)
        
        # Update protocols and ports
        if 'protocol' in packet_data:
            edge_attrs['protocols'].add(packet_data['protocol'])
        
        if 'flow_id' in packet_data:
            edge_attrs['flows'].add(packet_data['flow_id'])
        
        for port_key in ['src_port', 'dst_port']:
            if port_key in packet_data and packet_data[port_key]:
                edge_attrs['ports'].add(packet_data[port_key])
        
        # Calculate time-decay weight
        edge_attrs['weight'] = self._calculate_decay_weight(timestamp)
        
        # Store last seen time for cleanup
        self.edge_last_seen[edge_key] = timestamp
    
    def _calculate_decay_weight(self, current_time: datetime) -> float:
        """
        Calculate exponential time-decay weight.
        
        Formula: w(t) = exp(-λ * (t - t_last))
        """
        try:
            # For new edges, weight is 1.0
            return 1.0
        except Exception as e:
            print(f"Error calculating decay weight: {e}")
            return 1.0
    
    def update_decay_weights(self, reference_time: datetime = None):
        """Update all edge weights based on time decay"""
        if reference_time is None:
            reference_time = datetime.now()
        
        edges_to_remove = []
        
        for edge in self.graph.edges():
            edge_attrs = self.graph.edges[edge]
            last_seen = edge_attrs.get('last_seen', reference_time)
            
            if isinstance(last_seen, str):
                last_seen = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
            
            # Calculate time difference in seconds
            time_diff = (reference_time - last_seen).total_seconds()
            
            # Apply exponential decay: w(t) = exp(-λ * Δt)
            new_weight = math.exp(-self.decay_lambda * time_diff)
            edge_attrs['weight'] = new_weight
            
            # Mark edges with very low weight for removal
            if new_weight < 0.001:  # Threshold for edge removal
                edges_to_remove.append(edge)
        
        # Remove expired edges
        for edge in edges_to_remove:
            self.graph.remove_edge(*edge)
            if edge in self.edge_last_seen:
                del self.edge_last_seen[edge]
    
    def create_snapshot(self) -> Dict:
        """Create a temporal snapshot of the current graph state"""
        snapshot = {
            'timestamp': datetime.now().isoformat(),
            'node_count': self.graph.number_of_nodes(),
            'edge_count': self.graph.number_of_edges(),
            'nodes': {},
            'edges': {},
            'graph_metrics': self._calculate_graph_metrics()
        }
        
        # Capture node states
        for node_id in self.graph.nodes():
            node_attrs = self.graph.nodes[node_id].copy()
            # Convert sets to lists for JSON serialization
            node_attrs['protocols'] = list(node_attrs['protocols'])
            node_attrs['ports'] = list(node_attrs['ports'])
            # Convert datetime to string
            if 'first_seen' in node_attrs:
                node_attrs['first_seen'] = node_attrs['first_seen'].isoformat()
            if 'last_seen' in node_attrs:
                node_attrs['last_seen'] = node_attrs['last_seen'].isoformat()
            
            snapshot['nodes'][node_id] = node_attrs
        
        # Capture edge states
        for edge in self.graph.edges():
            edge_attrs = self.graph.edges[edge].copy()
            # Convert sets to lists for JSON serialization
            edge_attrs['protocols'] = list(edge_attrs['protocols'])
            edge_attrs['ports'] = list(edge_attrs['ports'])
            edge_attrs['flows'] = list(edge_attrs['flows'])
            # Convert datetime to string
            if 'first_seen' in edge_attrs:
                edge_attrs['first_seen'] = edge_attrs['first_seen'].isoformat()
            if 'last_seen' in edge_attrs:
                edge_attrs['last_seen'] = edge_attrs['last_seen'].isoformat()
            
            edge_key = f"{edge[0]}->{edge[1]}"
            snapshot['edges'][edge_key] = edge_attrs
        
        # Store snapshot
        self.snapshots.append(snapshot)
        
        # Limit number of snapshots
        if len(self.snapshots) > self.max_snapshots:
            self.snapshots.pop(0)
        
        self.stats['snapshots_created'] += 1
        return snapshot
    
    def _calculate_graph_metrics(self) -> Dict:
        """Calculate various graph metrics"""
        if self.graph.number_of_nodes() == 0:
            return {'density': 0, 'avg_degree': 0, 'connected_components': 0}
        
        try:
            # Convert to undirected for some metrics
            undirected_graph = self.graph.to_undirected()
            
            metrics = {
                'density': nx.density(self.graph),
                'avg_degree': sum(dict(self.graph.degree()).values()) / self.graph.number_of_nodes(),
                'connected_components': nx.number_connected_components(undirected_graph),
                'avg_clustering': nx.average_clustering(undirected_graph),
                'diameter': 0  # Placeholder - expensive to calculate
            }
            
            # Calculate diameter for small graphs only
            if self.graph.number_of_nodes() < 100:
                try:
                    if nx.is_connected(undirected_graph):
                        metrics['diameter'] = nx.diameter(undirected_graph)
                except:
                    pass
            
            return metrics
            
        except Exception as e:
            print(f"Error calculating graph metrics: {e}")
            return {'density': 0, 'avg_degree': 0, 'connected_components': 0}
    
    def _cleanup_loop(self):
        """Background cleanup loop for expired nodes and edges"""
        while not self.should_stop_cleanup:
            try:
                time.sleep(self.cleanup_interval)
                self._cleanup_expired_elements()
            except Exception as e:
                print(f"Error in cleanup loop: {e}")
    
    def _cleanup_expired_elements(self, max_age_seconds: int = 300):
        """Remove nodes and edges that haven't been seen for a while"""
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(seconds=max_age_seconds)
        
        # Find expired nodes
        expired_nodes = []
        for node_id, last_seen in self.node_last_seen.items():
            if last_seen < cutoff_time:
                expired_nodes.append(node_id)
        
        # Remove expired nodes
        for node_id in expired_nodes:
            if self.graph.has_node(node_id):
                self.graph.remove_node(node_id)
            if node_id in self.node_last_seen:
                del self.node_last_seen[node_id]
        
        # Find expired edges
        expired_edges = []
        for edge_key, last_seen in self.edge_last_seen.items():
            if last_seen < cutoff_time:
                expired_edges.append(edge_key)
        
        # Remove expired edges
        for edge_key in expired_edges:
            if self.graph.has_edge(*edge_key):
                self.graph.remove_edge(*edge_key)
            if edge_key in self.edge_last_seen:
                del self.edge_last_seen[edge_key]
        
        if expired_nodes or expired_edges:
            print(f"🧹 Cleaned up {len(expired_nodes)} expired nodes and {len(expired_edges)} expired edges")
        
        self.stats['last_cleanup'] = current_time
        self._update_stats()
    
    def _update_stats(self):
        """Update graph statistics"""
        self.stats.update({
            'total_nodes': self.graph.number_of_nodes(),
            'total_edges': self.graph.number_of_edges(),
            'active_nodes': len([n for n, t in self.node_last_seen.items() 
                               if (datetime.now() - t).total_seconds() < 60]),
            'active_edges': len([e for e, t in self.edge_last_seen.items() 
                               if (datetime.now() - t).total_seconds() < 60])
        })
    
    def get_graph_data(self) -> Dict:
        """Get current graph data for visualization"""
        nodes = []
        for node_id in self.graph.nodes():
            node_attrs = self.graph.nodes[node_id].copy()
            
            # Convert sets to lists for JSON serialization
            if 'protocols' in node_attrs:
                node_attrs['protocols'] = list(node_attrs['protocols'])
            if 'ports' in node_attrs:
                node_attrs['ports'] = list(node_attrs['ports'])
            
            # Convert datetime objects to strings
            if 'first_seen' in node_attrs and hasattr(node_attrs['first_seen'], 'isoformat'):
                node_attrs['first_seen'] = node_attrs['first_seen'].isoformat()
            if 'last_seen' in node_attrs and hasattr(node_attrs['last_seen'], 'isoformat'):
                node_attrs['last_seen'] = node_attrs['last_seen'].isoformat()
                
            nodes.append({
                'id': node_id,
                'label': node_id,
                **node_attrs
            })
        
        edges = []
        for edge in self.graph.edges():
            edge_attrs = self.graph.edges[edge].copy()
            
            # Convert sets to lists for JSON serialization
            if 'protocols' in edge_attrs:
                edge_attrs['protocols'] = list(edge_attrs['protocols'])
            if 'ports' in edge_attrs:
                edge_attrs['ports'] = list(edge_attrs['ports'])
            if 'flows' in edge_attrs:
                edge_attrs['flows'] = list(edge_attrs['flows'])
                
            # Convert datetime objects to strings
            if 'first_seen' in edge_attrs and hasattr(edge_attrs['first_seen'], 'isoformat'):
                edge_attrs['first_seen'] = edge_attrs['first_seen'].isoformat()
            if 'last_seen' in edge_attrs and hasattr(edge_attrs['last_seen'], 'isoformat'):
                edge_attrs['last_seen'] = edge_attrs['last_seen'].isoformat()
                
            edges.append({
                'source': edge[0],
                'target': edge[1],
                **edge_attrs
            })
        
        return {
            'nodes': nodes,
            'edges': edges,
            'stats': self._serialize_stats()
        }
    
    def _serialize_stats(self) -> Dict:
        """Get stats with datetime objects converted to strings"""
        stats = self.stats.copy()
        
        # Convert datetime objects to ISO strings
        if 'last_cleanup' in stats and stats['last_cleanup']:
            if hasattr(stats['last_cleanup'], 'isoformat'):
                stats['last_cleanup'] = stats['last_cleanup'].isoformat()
        
        return stats

    def get_stats(self) -> Dict:
        """Get current graph statistics"""
        return self._serialize_stats()
    
    def get_snapshots(self, limit: int = 10) -> List[Dict]:
        """Get recent temporal snapshots"""
        return self.snapshots[-limit:] if limit else self.snapshots
    
    def reset(self):
        """Reset the graph and all data"""
        self.graph.clear()
        self.node_last_seen.clear()
        self.edge_last_seen.clear()
        self.snapshots.clear()
        self.stats = {
            'total_nodes': 0,
            'total_edges': 0,
            'active_nodes': 0,
            'active_edges': 0,
            'snapshots_created': 0,
            'last_cleanup': None
        }
        print("🔄 Graph reset completed")


if __name__ == "__main__":
    # Example usage
    graph_builder = DynamicGraphBuilder()
    
    # Simulate some network traffic
    import random
    
    print("🕸️  Dynamic Graph Builder Test")
    
    # Generate sample packets
    for i in range(50):
        packet = {
            'src_ip': f"192.168.1.{random.randint(1, 10)}",
            'dst_ip': f"192.168.1.{random.randint(1, 10)}",
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice([80, 443, 22, 53]),
            'protocol': random.choice(['TCP', 'UDP']),
            'length': random.randint(64, 1500),
            'timestamp': datetime.now(),
            'flow_id': f"flow_{random.randint(1, 20)}"
        }
        
        graph_builder.add_packet(packet)
        time.sleep(0.1)  # Small delay
    
    # Create snapshot
    snapshot = graph_builder.create_snapshot()
    
    # Print results
    print(f"\n📊 Graph Statistics:")
    stats = graph_builder.get_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    print(f"\n🕸️  Graph Structure:")
    graph_data = graph_builder.get_graph_data()
    print(f"  Nodes: {len(graph_data['nodes'])}")
    print(f"  Edges: {len(graph_data['edges'])}")
    
    print(f"\n📸 Created snapshot with {snapshot['node_count']} nodes and {snapshot['edge_count']} edges")
    
    # Cleanup
    graph_builder.stop_background_cleanup()