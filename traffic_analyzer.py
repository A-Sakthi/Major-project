"""
Network Traffic Analyzer - Main Orchestrator
Coordinates packet capture, graph construction, and feature extraction
for comprehensive real-time network traffic analysis.
"""

import threading
import time
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable, Any
from collections import deque, defaultdict
import queue
import signal
import sys
import os

# Import our components
try:
    from packet_capture import RealTimePacketCapture
    from graph_builder import DynamicGraphBuilder
    from feature_extractor import NetworkFeatureExtractor
except ImportError as e:
    print(f"⚠️  Warning: Could not import components: {e}")
    print("📍 Please ensure all required modules are in the same directory")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('traffic_analyzer.log')
    ]
)
logger = logging.getLogger(__name__)

class NetworkTrafficAnalyzer:
    """
    Main orchestrator for the network traffic analysis system.
    Coordinates all components and manages the data processing pipeline.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize the traffic analyzer with optional configuration.
        
        Args:
            config: Configuration dictionary with system settings
        """
        # Default configuration
        self.config = {
            'interface': 'auto',
            'packet_buffer_size': 10000,
            'graph_decay_lambda': 0.001,
            'feature_window': 300,
            'flow_timeout': 60,
            'update_interval': 1.0,
            'save_data': False,
            'data_directory': './data',
            'max_file_size': 100 * 1024 * 1024,  # 100MB
        }
        
        if config:
            self.config.update(config)
        
        # Initialize components
        self.packet_capture = None
        self.graph_builder = None
        self.feature_extractor = None
        
        # Data management
        self.packet_queue = queue.Queue(maxsize=1000)
        self.packet_buffer = deque(maxlen=self.config['packet_buffer_size'])
        self.processed_data = deque(maxlen=1000)
        
        # Statistics and monitoring
        self.stats = {
            'start_time': None,
            'total_packets': 0,
            'processed_packets': 0,
            'features_extracted': 0,
            'graph_updates': 0,
            'errors': 0,
            'last_update': None,
            'current_rate': 0.0,
            'peak_rate': 0.0
        }
        
        # Threading and control
        self.running = False
        self.threads = {}
        self.shutdown_event = threading.Event()
        
        # Callback functions
        self.callbacks = {
            'packet': [],
            'feature': [],
            'graph_update': [],
            'status_update': []
        }
        
        # Rate limiting and performance
        self.rate_limiter = {
            'last_check': time.time(),
            'packet_count': 0,
            'target_rate': 1000,  # packets per second
        }
        
        logger.info("🔧 Network Traffic Analyzer initialized")
    
    def initialize_components(self) -> bool:
        """
        Initialize all analysis components.
        
        Returns:
            True if all components initialized successfully
        """
        try:
            # Initialize packet capture
            logger.info("🎯 Initializing packet capture...")
            self.packet_capture = RealTimePacketCapture(
                interface=self.config['interface']
            )
            
            # Initialize graph builder
            logger.info("🕸️  Initializing graph builder...")
            self.graph_builder = DynamicGraphBuilder(
                decay_lambda=self.config['graph_decay_lambda']
            )
            
            # Initialize feature extractor
            logger.info("🔍 Initializing feature extractor...")
            self.feature_extractor = NetworkFeatureExtractor(
                flow_timeout=self.config['flow_timeout'],
                feature_window=self.config['feature_window']
            )
            
            # Create data directory if saving is enabled
            if self.config['save_data']:
                os.makedirs(self.config['data_directory'], exist_ok=True)
                logger.info(f"📁 Data directory: {self.config['data_directory']}")
            
            logger.info("✅ All components initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error initializing components: {e}")
            return False
    
    def add_callback(self, event_type: str, callback: Callable):
        """
        Add callback function for specific events.
        
        Args:
            event_type: Type of event ('packet', 'feature', 'graph_update', 'status_update')
            callback: Callback function to add
        """
        if event_type in self.callbacks:
            self.callbacks[event_type].append(callback)
            logger.info(f"📞 Added callback for {event_type} events")
        else:
            logger.warning(f"⚠️  Unknown callback type: {event_type}")
    
    def _packet_processor(self):
        """Background thread that processes captured packets"""
        logger.info("🔄 Packet processor thread started")
        
        while not self.shutdown_event.is_set():
            try:
                # Get packet from queue (with timeout)
                packet_data = self.packet_queue.get(timeout=1.0)
                
                # Rate limiting check
                current_time = time.time()
                self.rate_limiter['packet_count'] += 1
                
                if current_time - self.rate_limiter['last_check'] >= 1.0:
                    self.stats['current_rate'] = self.rate_limiter['packet_count']
                    if self.stats['current_rate'] > self.stats['peak_rate']:
                        self.stats['peak_rate'] = self.stats['current_rate']
                    
                    self.rate_limiter['last_check'] = current_time
                    self.rate_limiter['packet_count'] = 0
                
                # Check rate limiting
                if self.stats['current_rate'] > self.rate_limiter['target_rate']:
                    time.sleep(0.01)  # Brief pause to reduce rate
                
                # Add to packet buffer
                self.packet_buffer.append(packet_data)
                
                # Process through graph builder
                if self.graph_builder:
                    self.graph_builder.add_packet(packet_data)
                    self.stats['graph_updates'] += 1
                
                # Extract features
                if self.feature_extractor and self.graph_builder:
                    flow_id = self._generate_flow_id(packet_data)
                    graph_snapshot = self.graph_builder.create_snapshot()
                    
                    features = self.feature_extractor.get_comprehensive_features(
                        packet_data, flow_id, graph_snapshot
                    )
                    
                    if features:
                        self.stats['features_extracted'] += 1
                        
                        # Store processed data
                        processed_item = {
                            'packet': packet_data,
                            'features': features,
                            'timestamp': datetime.now().isoformat()
                        }
                        self.processed_data.append(processed_item)
                        
                        # Call feature callbacks
                        for callback in self.callbacks['feature']:
                            try:
                                callback(features, packet_data)
                            except Exception as e:
                                logger.error(f"❌ Error in feature callback: {e}")
                
                # Update statistics
                self.stats['processed_packets'] += 1
                self.stats['last_update'] = datetime.now()
                
                # Call packet callbacks
                for callback in self.callbacks['packet']:
                    try:
                        callback(packet_data)
                    except Exception as e:
                        logger.error(f"❌ Error in packet callback: {e}")
                
                # Save data if enabled
                if self.config['save_data']:
                    self._save_packet_data(packet_data)
                
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"❌ Error processing packet: {e}")
                self.stats['errors'] += 1
        
        logger.info("🛑 Packet processor thread stopped")
    
    def _status_updater(self):
        """Background thread that provides periodic status updates"""
        logger.info("📊 Status updater thread started")
        
        while not self.shutdown_event.is_set():
            try:
                # Wait for update interval
                if self.shutdown_event.wait(self.config['update_interval']):
                    break
                
                # Generate status update
                status = self.get_status()
                
                # Call status callbacks
                for callback in self.callbacks['status_update']:
                    try:
                        callback(status)
                    except Exception as e:
                        logger.error(f"❌ Error in status callback: {e}")
                
                # Log periodic status (every minute)
                if time.time() % 60 < self.config['update_interval']:
                    logger.info(
                        f"📈 Status: {self.stats['processed_packets']} packets, "
                        f"{self.stats['features_extracted']} features, "
                        f"{self.stats['current_rate']:.1f} pkt/s"
                    )
                
            except Exception as e:
                logger.error(f"❌ Error in status updater: {e}")
        
        logger.info("🛑 Status updater thread stopped")
    
    def _graph_updater(self):
        """Background thread that handles periodic graph updates"""
        logger.info("🕸️  Graph updater thread started")
        
        while not self.shutdown_event.is_set():
            try:
                # Wait for 5 seconds or shutdown signal
                if self.shutdown_event.wait(5.0):
                    break
                
                if self.graph_builder:
                    # Create graph snapshot
                    graph_snapshot = self.graph_builder.create_snapshot()
                    
                    # Call graph update callbacks
                    for callback in self.callbacks['graph_update']:
                        try:
                            callback(graph_snapshot)
                        except Exception as e:
                            logger.error(f"❌ Error in graph callback: {e}")
                
            except Exception as e:
                logger.error(f"❌ Error in graph updater: {e}")
        
        logger.info("🛑 Graph updater thread stopped")
    
    def _packet_capture_callback(self, packet_data: Dict):
        """
        Callback function called by packet capture for each packet.
        
        Args:
            packet_data: Dictionary containing packet information
        """
        try:
            # Add timestamp if not present
            if 'capture_timestamp' not in packet_data:
                packet_data['capture_timestamp'] = datetime.now().isoformat()
            
            # Update total packet count
            self.stats['total_packets'] += 1
            
            # Add to processing queue (non-blocking)
            try:
                self.packet_queue.put_nowait(packet_data)
            except queue.Full:
                # Drop packet if queue is full
                logger.warning("⚠️  Packet queue full, dropping packet")
                
        except Exception as e:
            logger.error(f"❌ Error in packet capture callback: {e}")
            self.stats['errors'] += 1
    
    def _generate_flow_id(self, packet_data: Dict) -> str:
        """
        Generate a flow ID from packet data.
        
        Args:
            packet_data: Packet information
            
        Returns:
            Flow identifier string
        """
        try:
            src_ip = packet_data.get('src_ip', 'unknown')
            dst_ip = packet_data.get('dst_ip', 'unknown')
            protocol = packet_data.get('protocol', 'unknown')
            src_port = packet_data.get('src_port', 0)
            dst_port = packet_data.get('dst_port', 0)
            
            return f"{src_ip}:{src_port}->{dst_ip}:{dst_port}_{protocol}"
        except:
            return f"unknown_flow_{time.time()}"
    
    def _save_packet_data(self, packet_data: Dict):
        """
        Save packet data to file (if enabled).
        
        Args:
            packet_data: Packet information to save
        """
        try:
            # Generate filename with timestamp
            date_str = datetime.now().strftime("%Y-%m-%d")
            filename = os.path.join(self.config['data_directory'], f"packets_{date_str}.jsonl")
            
            # Write packet data as JSON line
            with open(filename, 'a') as f:
                json.dump(packet_data, f)
                f.write('\n')
                
            # Check file size and rotate if necessary
            if os.path.getsize(filename) > self.config['max_file_size']:
                self._rotate_data_file(filename)
                
        except Exception as e:
            logger.error(f"❌ Error saving packet data: {e}")
    
    def _rotate_data_file(self, filename: str):
        """
        Rotate data file when it gets too large.
        
        Args:
            filename: Path to file to rotate
        """
        try:
            timestamp = datetime.now().strftime("%H-%M-%S")
            base_name, ext = os.path.splitext(filename)
            rotated_name = f"{base_name}_{timestamp}{ext}"
            
            os.rename(filename, rotated_name)
            logger.info(f"🔄 Rotated data file: {rotated_name}")
            
        except Exception as e:
            logger.error(f"❌ Error rotating data file: {e}")
    
    def start(self) -> bool:
        """
        Start the traffic analyzer system.
        
        Returns:
            True if started successfully
        """
        if self.running:
            logger.warning("⚠️  Traffic analyzer already running")
            return False
        
        logger.info("🚀 Starting Network Traffic Analyzer...")
        
        # Initialize components
        if not self.initialize_components():
            return False
        
        # Set up signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        try:
            # Start background threads
            self.threads['processor'] = threading.Thread(
                target=self._packet_processor, 
                name='PacketProcessor'
            )
            self.threads['status'] = threading.Thread(
                target=self._status_updater, 
                name='StatusUpdater'
            )
            self.threads['graph'] = threading.Thread(
                target=self._graph_updater, 
                name='GraphUpdater'
            )
            
            # Start threads
            for thread in self.threads.values():
                thread.daemon = True
                thread.start()
            
            # Start packet capture
            if self.packet_capture:
                self.packet_capture.start_capture(self._packet_capture_callback)
            
            # Update state
            self.running = True
            self.stats['start_time'] = datetime.now()
            
            logger.info("✅ Network Traffic Analyzer started successfully")
            logger.info("📍 Press Ctrl+C to stop")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Error starting traffic analyzer: {e}")
            self.stop()
            return False
    
    def stop(self):
        """Stop the traffic analyzer system"""
        if not self.running:
            return
        
        logger.info("🛑 Stopping Network Traffic Analyzer...")
        
        # Set running flag
        self.running = False
        self.shutdown_event.set()
        
        # Stop packet capture
        if self.packet_capture:
            try:
                self.packet_capture.stop_capture()
            except Exception as e:
                logger.error(f"❌ Error stopping packet capture: {e}")
        
        # Wait for threads to complete
        for name, thread in self.threads.items():
            if thread and thread.is_alive():
                logger.info(f"⏳ Waiting for {name} thread to stop...")
                thread.join(timeout=5.0)
                if thread.is_alive():
                    logger.warning(f"⚠️  {name} thread did not stop gracefully")
        
        logger.info("✅ Network Traffic Analyzer stopped")
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        logger.info(f"📡 Received signal {signum}, shutting down...")
        self.stop()
    
    def get_status(self) -> Dict:
        """
        Get current system status.
        
        Returns:
            Dictionary containing system status information
        """
        uptime = 0
        if self.stats['start_time']:
            uptime = (datetime.now() - self.stats['start_time']).total_seconds()
        
        status = {
            'running': self.running,
            'uptime': uptime,
            'statistics': self.stats.copy(),
            'component_stats': {
                'packet_capture': self.packet_capture.get_stats() if self.packet_capture else {},
                'graph_builder': self.graph_builder.get_stats() if self.graph_builder else {},
                'feature_extractor': self.feature_extractor.get_stats() if self.feature_extractor else {}
            },
            'buffers': {
                'packet_buffer': len(self.packet_buffer),
                'packet_queue': self.packet_queue.qsize(),
                'processed_data': len(self.processed_data)
            },
            'threads': {
                name: thread.is_alive() if thread else False 
                for name, thread in self.threads.items()
            },
            'timestamp': datetime.now().isoformat()
        }
        
        return status
    
    def get_recent_packets(self, count: int = 50) -> List[Dict]:
        """
        Get recent packet data.
        
        Args:
            count: Number of recent packets to return
            
        Returns:
            List of recent packet data
        """
        return list(self.packet_buffer)[-count:]
    
    def get_processed_data(self, count: int = 50) -> List[Dict]:
        """
        Get recent processed data (packets with features).
        
        Args:
            count: Number of recent processed items to return
            
        Returns:
            List of processed data items
        """
        return list(self.processed_data)[-count:]
    
    def get_current_graph(self) -> Dict:
        """
        Get current network graph snapshot.
        
        Returns:
            Graph data dictionary
        """
        if self.graph_builder:
            return self.graph_builder.create_snapshot()
        return {"nodes": [], "edges": [], "stats": {}}

def create_analyzer_from_config(config_file: str) -> NetworkTrafficAnalyzer:
    """
    Create analyzer instance from configuration file.
    
    Args:
        config_file: Path to JSON configuration file
        
    Returns:
        Configured NetworkTrafficAnalyzer instance
    """
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        return NetworkTrafficAnalyzer(config)
    except Exception as e:
        logger.error(f"❌ Error loading config from {config_file}: {e}")
        return NetworkTrafficAnalyzer()

def main():
    """Main entry point for the traffic analyzer"""
    print("🌐 Network Traffic Analyzer v1.0")
    print("📊 Real-time packet capture, graph analysis, and feature extraction")
    print()
    
    # Create analyzer with default configuration
    analyzer = NetworkTrafficAnalyzer({
        'interface': 'auto',
        'save_data': True,
        'data_directory': './analyzer_data'
    })
    
    # Add some example callbacks
    def packet_callback(packet_data):
        """Example packet callback"""
        if analyzer.stats['total_packets'] % 100 == 0:
            print(f"📦 Processed {analyzer.stats['total_packets']} packets")
    
    def status_callback(status):
        """Example status callback"""
        if status['statistics']['processed_packets'] % 500 == 0:
            print(f"📈 Status: {status['statistics']['processed_packets']} processed, "
                  f"{status['statistics']['current_rate']:.1f} pkt/s")
    
    # Register callbacks
    analyzer.add_callback('packet', packet_callback)
    analyzer.add_callback('status_update', status_callback)
    
    # Start the analyzer
    if analyzer.start():
        try:
            # Keep running until interrupted
            while analyzer.running:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            analyzer.stop()
    else:
        print("❌ Failed to start traffic analyzer")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())