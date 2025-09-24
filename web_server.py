from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, List, Optional, Any
import json
import asyncio
import uvicorn
from datetime import datetime, timedelta
import threading
import time
from collections import deque

# Import our custom modules (these would be our actual implementations)
try:
    from packet_capture import RealTimePacketCapture
    from graph_builder import DynamicGraphBuilder  
    from feature_extractor import NetworkFeatureExtractor
except ImportError:
    # Mock implementations for development
    print("⚠️  Warning: Using mock implementations for development")
    
    class RealTimePacketCapture:
        def __init__(self, interface="mock"):
            self.running = False
            
        def start_capture(self, callback):
            self.running = True
            print("🎯 Mock packet capture started")
            
        def stop_capture(self):
            self.running = False
            print("🛑 Mock packet capture stopped")
            
        def get_stats(self):
            return {"packets_captured": 42, "rate": 5.2, "interface": "mock"}
    
    class DynamicGraphBuilder:
        def __init__(self):
            self.nodes = []
            self.edges = []
            
        def add_packet(self, packet_data):
            pass
            
        def create_snapshot(self):
            return {"nodes": [], "edges": [], "stats": {"node_count": 0}}
            
        def get_stats(self):
            return {"nodes": 0, "edges": 0, "active_flows": 0}
    
    class NetworkFeatureExtractor:
        def __init__(self):
            pass
            
        def get_comprehensive_features(self, packet_data, flow_id, graph_data):
            return {"mock_features": True}
            
        def get_stats(self):
            return {"features_extracted": 0, "flows_created": 0}

# FastAPI app initialization
app = FastAPI(
    title="Network Traffic Analyzer API",
    description="Real-time network traffic analysis with graph visualization",
    version="1.0.0"
)

# Enable CORS for web interface
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic models for API
class SystemStatus(BaseModel):
    status: str
    uptime: float
    packet_capture: Dict[str, Any]
    graph_builder: Dict[str, Any]
    feature_extractor: Dict[str, Any]
    active_connections: int
    timestamp: str

class PacketData(BaseModel):
    src_ip: str
    dst_ip: str
    protocol: str
    length: int
    timestamp: str
    additional_info: Optional[Dict] = None

class GraphData(BaseModel):
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]
    stats: Dict[str, Any]
    timestamp: str

class FeatureData(BaseModel):
    packet_features: Dict[str, Any]
    flow_features: Dict[str, Any]
    node_features: Dict[str, Any]
    edge_features: Dict[str, Any]
    timestamp: str

# Global instances
packet_capture = None
graph_builder = None
feature_extractor = None
app_start_time = datetime.now()

# Data buffers and queues
packet_buffer = []
feature_buffer = []
graph_snapshots = []
packet_updates_queue = []  # Queue for packet updates to be sent via WebSocket

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.connection_stats = {
            "total_connections": 0,
            "active_connections": 0,
            "messages_sent": 0
        }

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        self.connection_stats["total_connections"] += 1
        self.connection_stats["active_connections"] = len(self.active_connections)
        print(f"🔌 WebSocket connected. Active connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        self.connection_stats["active_connections"] = len(self.active_connections)
        print(f"🔌 WebSocket disconnected. Active connections: {len(self.active_connections)}")

    async def send_personal_message(self, message: str, websocket: WebSocket):
        try:
            await websocket.send_text(message)
            self.connection_stats["messages_sent"] += 1
        except:
            self.disconnect(websocket)

    async def broadcast(self, data: Dict[str, Any]):
        if not self.active_connections:
            return
            
        message = json.dumps(data)
        disconnected = []
        
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
                self.connection_stats["messages_sent"] += 1
            except:
                disconnected.append(connection)
        
        # Remove disconnected websockets
        for connection in disconnected:
            self.disconnect(connection)

    def get_stats(self):
        return self.connection_stats.copy()

# Global connection manager
manager = ConnectionManager()

# Data buffers for real-time updates
packet_buffer = deque(maxlen=1000)  # Store last 1000 packets
graph_snapshots = deque(maxlen=100)  # Store last 100 graph snapshots
feature_buffer = deque(maxlen=500)   # Store last 500 feature extractions

# Background task for real-time data processing
async def process_network_data():
    """Background task that processes network data and sends updates to clients"""
    
    def packet_callback(packet_data):
        """Callback function called for each captured packet"""
        try:
            # Add to packet buffer
            packet_buffer.append(packet_data)
            
            # Process through graph builder
            if graph_builder:
                graph_builder.add_packet(packet_data)
            
            # Generate flow ID for feature extraction
            flow_id = f"{packet_data.get('src_ip', '')}_{packet_data.get('dst_ip', '')}_{packet_data.get('protocol', '')}"
            
            # Extract features (temporarily disabled to avoid errors)
            if False:  # Disable feature extraction temporarily
                if feature_extractor and graph_builder:
                    graph_snapshot = graph_builder.create_snapshot()
                    features = feature_extractor.get_comprehensive_features(
                        packet_data, flow_id, graph_snapshot
                    )
                    if features:
                        feature_buffer.append(features)
            
            # Store update for periodic broadcasting instead of real-time
            # This avoids threading issues with asyncio
            # Ensure all datetime objects are serialized to strings
            serialized_packet = packet_data.copy()
            
            # Convert any datetime objects to ISO format strings
            for key, value in serialized_packet.items():
                if hasattr(value, 'isoformat'):  # Check if it's a datetime object
                    serialized_packet[key] = value.isoformat()
            
            packet_updates_queue.append({
                "type": "packet_update", 
                "packet": serialized_packet,
                "timestamp": datetime.now().isoformat()
            })
            
        except Exception as e:
            print(f"❌ Error in packet callback: {e}")
    
    # Don't start packet capture automatically - wait for user to click Start Capture
    # Add callback for when capture is started
    if packet_capture and hasattr(packet_capture, 'add_packet_callback'):
        try:
            packet_capture.add_packet_callback(packet_callback)
            print("✅ Packet callback registered - ready for manual capture start")
        except Exception as e:
            print(f"❌ Error registering packet callback: {e}")
    
    # Periodic graph updates
    while True:
        try:
            await asyncio.sleep(1)  # Check more frequently for packet updates
            
            # Only send updates if capture is active
            capture_active = packet_capture and hasattr(packet_capture, 'is_capturing') and packet_capture.is_capturing
            
            # Send any queued packet updates
            if capture_active:
                while packet_updates_queue:
                    packet_update = packet_updates_queue.pop(0)
                    try:
                        await manager.broadcast(packet_update)
                        # Debug: Print every 10th packet update
                        if len(packet_buffer) % 10 == 0:
                            print(f"📡 Sent packet update #{len(packet_buffer)} via WebSocket")
                    except Exception as e:
                        print(f"❌ Error sending packet update via WebSocket: {e}")
            
            # Send graph updates only when capture is active
            if capture_active and len(packet_buffer) % 50 == 0:
                if graph_builder:
                    # Use get_graph_data() for WebSocket updates too
                    graph_data = graph_builder.get_graph_data()
                    
                    # Send graph update to clients
                    graph_update_data = {
                        "type": "graph_update",
                        "graph": graph_data,
                        "timestamp": datetime.now().isoformat()
                    }
                    
                    try:
                        await manager.broadcast(graph_update_data)
                    except Exception as e:
                        print(f"❌ Error sending graph update: {e}")
            
            # Clear packet update queue when capture stops
            elif not capture_active and packet_updates_queue:
                packet_updates_queue.clear()
                print("🧹 Cleared packet update queue - capture stopped")
                
        except Exception as e:
            print(f"❌ Error in periodic update: {e}")
            await asyncio.sleep(5)  # Wait longer on error

@app.on_event("startup")
async def startup_event():
    """Initialize components on startup"""
    global packet_capture, graph_builder, feature_extractor
    
    print("🚀 Starting Network Traffic Analyzer API...")
    
    # Initialize components
    try:
        packet_capture = RealTimePacketCapture()
        graph_builder = DynamicGraphBuilder()
        feature_extractor = NetworkFeatureExtractor()
        print("✅ All components initialized successfully")
    except Exception as e:
        print(f"⚠️  Error initializing components: {e}")
        print("📍 Using mock implementations for development")
    
    # Start background data processing
    asyncio.create_task(process_network_data())
    print("🔄 Background data processing started")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    print("🛑 Shutting down Network Traffic Analyzer API...")
    
    if packet_capture and hasattr(packet_capture, 'stop_capture'):
        try:
            packet_capture.stop_capture()
            print("✅ Packet capture stopped")
        except Exception as e:
            print(f"⚠️  Error stopping packet capture: {e}")

# API Endpoints

@app.get("/api/info")
async def get_api_info():
    """API information endpoint"""
    return {
        "name": "Network Traffic Analyzer API",
        "version": "1.0.0",
        "status": "running",
        "uptime": (datetime.now() - app_start_time).total_seconds(),
        "endpoints": {
            "status": "/api/status",
            "packets": "/api/packets",
            "graph": "/api/graph",
            "features": "/api/features",
            "websocket": "/ws/live"
        }
    }

@app.get("/api/status", response_model=SystemStatus)
async def get_system_status():
    """Get comprehensive system status"""
    try:
        # Collect stats from all components
        packet_stats = packet_capture.get_stats() if packet_capture else {}
        graph_stats = graph_builder.get_stats() if graph_builder else {}
        feature_stats = feature_extractor.get_stats() if feature_extractor else {}
        
        return SystemStatus(
            status="running",
            uptime=(datetime.now() - app_start_time).total_seconds(),
            packet_capture=packet_stats,
            graph_builder=graph_stats,
            feature_extractor=feature_stats,
            active_connections=len(manager.active_connections),
            timestamp=datetime.now().isoformat()
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting system status: {str(e)}")

@app.get("/api/packets")
async def get_recent_packets(limit: int = 50):
    """Get recent packet data"""
    try:
        # Get the most recent packets from buffer
        recent_packets = list(packet_buffer)[-limit:] if packet_buffer else []
        
        return {
            "packets": recent_packets,
            "count": len(recent_packets),
            "total_captured": len(packet_buffer),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting packets: {str(e)}")

@app.get("/api/graph", response_model=GraphData)
async def get_current_graph():
    """Get current network graph"""
    try:
        if graph_builder:
            # Use get_graph_data() which returns nodes and edges as lists
            graph_data = graph_builder.get_graph_data()
            return GraphData(
                nodes=graph_data.get("nodes", []),
                edges=graph_data.get("edges", []),
                stats=graph_data.get("stats", {}),
                timestamp=datetime.now().isoformat()
            )
        else:
            return GraphData(
                nodes=[],
                edges=[],
                stats={},
                timestamp=datetime.now().isoformat()
            )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting graph: {str(e)}")

@app.get("/api/features")
async def get_recent_features(limit: int = 20):
    """Get recent feature extractions"""
    try:
        recent_features = list(feature_buffer)[-limit:] if feature_buffer else []
        
        return {
            "features": recent_features,
            "count": len(recent_features),
            "total_extracted": len(feature_buffer),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting features: {str(e)}")

@app.get("/api/stats")
async def get_detailed_stats():
    """Get detailed system statistics"""
    try:
        return {
            "system": {
                "uptime": (datetime.now() - app_start_time).total_seconds(),
                "start_time": app_start_time.isoformat(),
                "status": "running"
            },
            "data_buffers": {
                "packets": len(packet_buffer),
                "graph_snapshots": len(graph_snapshots),
                "features": len(feature_buffer)
            },
            "websocket": manager.get_stats(),
            "components": {
                "packet_capture": packet_capture.get_stats() if packet_capture else {},
                "graph_builder": graph_builder.get_stats() if graph_builder else {},
                "feature_extractor": feature_extractor.get_stats() if feature_extractor else {}
            },
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting stats: {str(e)}")

# WebSocket endpoint for real-time updates
@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time data streaming"""
    await manager.connect(websocket)
    
    try:
        # Send initial data
        initial_data = {
            "type": "connection_established",
            "message": "Connected to real-time traffic analyzer",
            "timestamp": datetime.now().isoformat()
        }
        await websocket.send_text(json.dumps(initial_data))
        
        # Send current system status
        try:
            status_data = {
                "type": "system_status",
                "data": {
                    "uptime": (datetime.now() - app_start_time).total_seconds(),
                    "active_connections": len(manager.active_connections),
                    "packet_buffer_size": len(packet_buffer),
                    "graph_snapshots": len(graph_snapshots),
                    "feature_buffer_size": len(feature_buffer)
                },
                "timestamp": datetime.now().isoformat()
            }
            await websocket.send_text(json.dumps(status_data))
        except:
            pass
        
        # Keep connection alive and handle incoming messages
        while True:
            try:
                # Wait for client messages (ping/pong, requests, etc.)
                data = await websocket.receive_text()
                
                # Handle client requests
                try:
                    client_message = json.loads(data)
                    if client_message.get("type") == "ping":
                        response = {
                            "type": "pong",
                            "timestamp": datetime.now().isoformat()
                        }
                        await websocket.send_text(json.dumps(response))
                except:
                    # Handle non-JSON messages
                    pass
                    
            except WebSocketDisconnect:
                break
            except Exception as e:
                print(f"❌ WebSocket error: {e}")
                break
                
    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"❌ WebSocket connection error: {e}")
    finally:
        manager.disconnect(websocket)

@app.post("/api/capture/start")
async def start_capture():
    """Start packet capture"""
    try:
        if packet_capture and hasattr(packet_capture, 'start_capture'):
            if not packet_capture.is_capturing:
                packet_capture.start_capture()
                return {"status": "started", "message": "Packet capture started"}
            else:
                return {"status": "already_running", "message": "Packet capture already running"}
        else:
            return {"status": "error", "message": "Packet capture not available"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error starting capture: {str(e)}")

@app.post("/api/capture/stop")
async def stop_capture():
    """Stop packet capture"""
    try:
        if packet_capture and hasattr(packet_capture, 'stop_capture'):
            packet_capture.stop_capture()
            return {"status": "stopped", "message": "Packet capture stopped"}
        else:
            return {"status": "error", "message": "Packet capture not available"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error stopping capture: {str(e)}")

@app.get("/api/capture/status")
async def get_capture_status():
    """Get current capture status"""
    try:
        if packet_capture and hasattr(packet_capture, 'is_capturing'):
            is_active = packet_capture.is_capturing
            return {
                "status": "active" if is_active else "inactive",
                "is_capturing": is_active,
                "message": "Packet capture is running" if is_active else "Packet capture is stopped"
            }
        else:
            return {"status": "unavailable", "is_capturing": False, "message": "Packet capture not available"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting capture status: {str(e)}")

@app.post("/api/capture/local-mode/{enabled}")
async def toggle_local_mode(enabled: bool):
    """Toggle local network only mode"""
    try:
        if packet_capture and hasattr(packet_capture, 'set_local_only_mode'):
            packet_capture.set_local_only_mode(enabled)
            return {"status": "success", "local_mode": enabled, "message": f"Local mode {'enabled' if enabled else 'disabled'}"}
        else:
            return {"status": "error", "message": "Packet capture not available"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error toggling local mode: {str(e)}")

@app.post("/api/graph/clear")
async def clear_graph():
    """Clear graph data"""
    try:
        # Clear buffers
        packet_buffer.clear()
        graph_snapshots.clear()
        feature_buffer.clear()
        
        # Reset graph builder if available
        if graph_builder and hasattr(graph_builder, 'clear'):
            graph_builder.clear()
        
        return {"status": "success", "message": "Graph data cleared"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error clearing graph: {str(e)}")

# Health check endpoint
@app.get("/health")
async def health_check():
    """Simple health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "uptime": (datetime.now() - app_start_time).total_seconds()
    }

# Serve static files (for web interface)
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/", response_class=HTMLResponse)
async def serve_index():
    """Serve the main web interface"""
    try:
        # Try to serve the simplified dashboard first (no external dependencies)
        with open("static/dashboard-simple.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        try:
            # Fallback to full dashboard
            with open("static/dashboard.html", "r", encoding="utf-8") as f:
                return HTMLResponse(content=f.read())
        except FileNotFoundError:
            try:
                # Final fallback to old index.html
                with open("static/index.html", "r", encoding="utf-8") as f:
                    return HTMLResponse(content=f.read())
            except FileNotFoundError:
                return HTMLResponse(
                    content="<h1>Web interface not found</h1><p>Please ensure dashboard files exist in static/</p>",
                    status_code=404
                )

@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard():
    """Serve the full dashboard"""
    try:
        # Serve the simplified dashboard (works without external dependencies)
        with open("static/dashboard-simple.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        try:
            # Fallback to full dashboard with D3.js
            with open("static/dashboard.html", "r", encoding="utf-8") as f:
                return HTMLResponse(content=f.read())
        except FileNotFoundError:
            return HTMLResponse(
                content="<h1>Dashboard not found</h1><p>Please ensure static/dashboard-simple.html exists</p>",
                status_code=404
            )

@app.get("/simple", response_class=HTMLResponse)
async def serve_simple_dashboard():
    """Serve the simplified dashboard (no external dependencies)"""
    try:
        with open("static/dashboard-simple.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(
            content="<h1>Simple dashboard not found</h1><p>Please ensure static/dashboard-simple.html exists</p>",
            status_code=404
        )

@app.get("/test", response_class=HTMLResponse)
async def serve_test():
    """Serve the test page"""
    try:
        with open("static/test.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(
            content="<h1>Test page not found</h1>",
            status_code=404
        )

if __name__ == "__main__":
    print("🌐 Starting Network Traffic Analyzer Web Server")
    print("📍 Access API at: http://localhost:8000")
    print("📍 API Documentation: http://localhost:8000/docs")
    print("📍 WebSocket: ws://localhost:8000/ws/live")
    print("⚠️  Note: Run as Administrator/root for packet capture")
    
    # Run with uvicorn
    uvicorn.run(
        "web_server:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info",
        access_log=True
    )