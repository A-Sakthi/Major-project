# Network Traffic Analyzer

Real-time network traffic analysis with interactive web dashboard. Captures packets, builds dynamic graphs, and provides live visualization of network communications.

## Features

- **Real-time packet capture** using Scapy with Npcap
- **Interactive web dashboard** with live graph visualization
- **Local/External traffic filtering** - toggle between all traffic or local-only
- **Dynamic network graph** with automatic node cleanup
- **Protocol analysis** - TCP, UDP, ICMP support
- **Cross-platform** - Windows, Linux, macOS

## Quick Start

### Prerequisites

- Python 3.8+
- Administrator/root privileges (for packet capture)
- **Windows**: Install [Npcap](https://nmap.org/npcap/) driver

### Installation & Run

```bash
# Install dependencies
pip install -r requirements.txt

# Start the analyzer
python start.py

# Open browser to http://localhost:8000
```

## Usage

1. **Start capture**: Click "Start Capture" button
2. **Toggle modes**: Switch between "All Traffic" and "Local Only"
3. **Stop capture**: Click "Stop Capture" when done
4. **Clear graph**: Reset visualization with "Clear Graph"

### Controls

- **🚀 Start/Stop Capture**: Begin/end packet monitoring
- **🏠 Local Mode**: Filter to show only local network traffic (192.168.x.x ↔ 192.168.x.x)
- **🌐 All Traffic**: Show all captured network communications
- **🗑️ Clear Graph**: Reset the visualization

## Architecture

```
Network Interface → Packet Capture → Graph Builder → Web Server → Dashboard
```

### Files

- `start.py` - Main entry point
- `packet_capture.py` - Real-time packet capture with Scapy
- `graph_builder.py` - Dynamic network graph using NetworkX
- `web_server.py` - FastAPI server with WebSocket updates
- `static/dashboard-simple.html` - Interactive web interface

## API Endpoints

- `GET /` - Web dashboard
- `POST /api/capture/start` - Start packet capture
- `POST /api/capture/stop` - Stop packet capture
- `GET /api/capture/status` - Get capture status
- `POST /api/capture/local-mode/{enabled}` - Toggle local mode
- `GET /api/graph` - Get current network graph
- `POST /api/graph/clear` - Clear graph data
- `WebSocket /ws/live` - Real-time updates

## Troubleshooting

**No packets captured?**
- Run as Administrator (Windows) or sudo (Linux/macOS)
- Install Npcap driver on Windows
- Generate traffic by browsing websites or pinging

**Import errors?**
- Install requirements: `pip install -r requirements.txt`
- Use Python 3.8+ 

**Permission denied?**
- Network capture requires elevated privileges
- Windows: Run as Administrator
- Linux/macOS: Use sudo

## License

MIT License - see LICENSE file for details.

---

⚠️ **Security Note**: This tool monitors network traffic. Ensure compliance with local policies and privacy regulations.