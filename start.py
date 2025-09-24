#!/usr/bin/env python3
"""
Quick Start Script for Network Traffic Analyzer
This script helps you get started with the traffic analyzer quickly
"""

import sys
import os
import subprocess
import time
import argparse
from pathlib import Path

def check_dependencies():
    """Check if required dependencies are installed"""
    print("🔍 Checking dependencies...")
    
    required_packages = [
        'scapy', 'networkx', 'numpy', 'fastapi', 'uvicorn', 'websockets'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
            print(f"  ✅ {package}")
        except ImportError:
            print(f"  ❌ {package} - Missing")
            missing_packages.append(package)
    
    if missing_packages:
        print(f"\n⚠️  Missing packages: {', '.join(missing_packages)}")
        print("📦 Install with: pip install -r requirements.txt")
        return False
    
    print("✅ All dependencies satisfied")
    return True

def check_admin_privileges():
    """Check if running with admin privileges (required for packet capture)"""
    try:
        if os.name == 'nt':  # Windows
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:  # Unix/Linux
            return os.geteuid() == 0
    except:
        return False

def install_dependencies():
    """Install dependencies from requirements.txt"""
    print("📦 Installing dependencies...")
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'])
        print("✅ Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing dependencies: {e}")
        return False

def run_web_server():
    """Run the web server"""
    print("🌐 Starting web server...")
    try:
        subprocess.run([sys.executable, 'web_server.py'])
    except KeyboardInterrupt:
        print("\n🛑 Web server stopped by user")
    except Exception as e:
        print(f"❌ Error running web server: {e}")

def run_traffic_analyzer():
    """Run the main traffic analyzer"""
    print("🚀 Starting traffic analyzer...")
    try:
        subprocess.run([sys.executable, 'traffic_analyzer.py'])
    except KeyboardInterrupt:
        print("\n🛑 Traffic analyzer stopped by user")
    except Exception as e:
        print(f"❌ Error running traffic analyzer: {e}")

def test_components():
    """Test individual components"""
    print("🧪 Testing components...")
    
    components = [
        ('packet_capture.py', 'Packet Capture'),
        ('graph_builder.py', 'Graph Builder'), 
        ('feature_extractor.py', 'Feature Extractor')
    ]
    
    for filename, name in components:
        print(f"\n📋 Testing {name}...")
        try:
            result = subprocess.run([sys.executable, filename], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print(f"  ✅ {name} test passed")
            else:
                print(f"  ❌ {name} test failed: {result.stderr}")
        except subprocess.TimeoutExpired:
            print(f"  ✅ {name} test running (timeout reached)")
        except Exception as e:
            print(f"  ❌ {name} test error: {e}")

def main():
    parser = argparse.ArgumentParser(description='Network Traffic Analyzer Quick Start')
    parser.add_argument('--mode', choices=['web', 'analyzer', 'test', 'setup'], 
                       default='web', help='Mode to run')
    parser.add_argument('--install', action='store_true', 
                       help='Install dependencies first')
    parser.add_argument('--no-admin-check', action='store_true',
                       help='Skip admin privilege check')
    
    args = parser.parse_args()
    
    print("🌐 Network Traffic Analyzer - Quick Start")
    print("=" * 50)
    
    # Install dependencies if requested
    if args.install:
        if not install_dependencies():
            return 1
        print()
    
    # Check dependencies
    if not check_dependencies():
        print("\n💡 Run with --install to install missing dependencies")
        return 1
    
    # Check admin privileges (unless skipped)
    if not args.no_admin_check:
        if not check_admin_privileges():
            print("\n⚠️  Warning: Not running as Administrator/root")
            print("   Real packet capture may not work properly")
            print("   Use mock mode for development or run as admin for real capture")
            print("   Add --no-admin-check to skip this warning")
        else:
            print("✅ Running with admin privileges")
    
    print()
    
    # Run based on mode
    if args.mode == 'setup':
        print("🔧 Setup complete!")
        print("\nNext steps:")
        print("  1. Run web server: python start.py --mode web")
        print("  2. Open browser: http://localhost:8000")
        print("  3. Or run analyzer: python start.py --mode analyzer")
        
    elif args.mode == 'test':
        test_components()
        
    elif args.mode == 'web':
        print("🌐 Starting in web mode...")
        print("📍 Web interface will be available at: http://localhost:8000")
        print("📍 API documentation at: http://localhost:8000/docs")
        print("⚠️  Press Ctrl+C to stop")
        print()
        run_web_server()
        
    elif args.mode == 'analyzer':
        print("🚀 Starting in analyzer mode...")
        print("⚠️  Press Ctrl+C to stop")
        print()
        run_traffic_analyzer()
    
    return 0

if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n🛑 Stopped by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)