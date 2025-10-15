
#!/usr/bin/env python3
"""
IoT Device Log Forensic System
Main runner script for different modes
"""

import sys
import subprocess
import os

def print_banner():
    print("🔒" * 20)
    print("🔒 IoT Device Log Forensic System")
    print("🔒" * 20)
    print()

def show_menu():
    print("Available Modes:")
    print("1. 🖥️  CLI Dashboard (Interactive terminal interface)")
    print("2. 🌐 API Server (REST API with web interface)")
    print("3. 📡 API Client (Programmatic access)")
    print("4. 📊 Quick Analysis (Generate instant report)")
    print("5. 🔴 Real-time Monitor (Live monitoring)")
    print("6. ❓ Help")
    print("7. 🚪 Exit")
    print()

def run_cli_dashboard():
    """Run the CLI dashboard"""
    print("🖥️ Starting CLI Dashboard...")
    subprocess.run([sys.executable, "app.py", "--mode", "cli"])

def run_api_server():
    """Run the API server"""
    print("🌐 Starting API Server...")
    print("Access the API at: http://localhost:5000")
    print("Access the dashboard at: http://localhost:5000/dashboard")
    subprocess.run([sys.executable, "app.py", "--mode", "api"])

def run_api_client():
    """Run the API client"""
    print("📡 Starting API Client...")
    subprocess.run([sys.executable, "app.py", "--mode", "client"])

def quick_analysis():
    """Run quick analysis"""
    print("📊 Running Quick Analysis...")
    
    from database.db_manager import DatabaseManager
    from services.alert_system import AlertSystem
    from datetime import datetime
    
    db_manager = DatabaseManager()
    alert_system = AlertSystem(db_manager)
    
    print("\n📋 QUICK FORENSIC ANALYSIS")
    print("=" * 50)
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 50)
    
    # Get data
    devices = db_manager.get_devices()
    logs = db_manager.get_logs(limit=1000)
    alerts = db_manager.get_alerts()
    
    print(f"🖥️  Total Devices: {len(devices) if devices else 0}")
    print(f"📝 Total Logs: {len(logs) if logs else 0}")
    print(f"🚨 Active Alerts: {len([a for a in alerts if a['status'] == 'open']) if alerts else 0}")
    
    if logs:
        high_severity = len([l for l in logs if l.get('severity') == 'high'])
        medium_severity = len([l for l in logs if l.get('severity') == 'medium'])
        low_severity = len([l for l in logs if l.get('severity') == 'low'])
        
        print(f"\n📊 SEVERITY BREAKDOWN:")
        print(f"🔴 High: {high_severity}")
        print(f"🟡 Medium: {medium_severity}")
        print(f"🟢 Low: {low_severity}")
        
        # Attack analysis
        attack_logs = [l for l in logs if l.get('attack_type')]
        if attack_logs:
            attack_types = {}
            for log in attack_logs:
                attack_type = log.get('attack_type')
                attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
                
            print(f"\n🎯 ATTACK ANALYSIS:")
            print(f"Total Attack Attempts: {len(attack_logs)}")
            for attack, count in sorted(attack_types.items(), key=lambda x: x[1], reverse=True):
                print(f"  - {attack}: {count}")
        
        print(f"\n🔍 RECENT ACTIVITY (Last 10):")
        for log in logs[:10]:
            severity_icon = "🔴" if log.get('severity') == 'high' else "🟡" if log.get('severity') == 'medium' else "🟢"
            print(f"{severity_icon} {log.get('timestamp', 'N/A')} - {log.get('device_name', 'Unknown')} - {log.get('message', '')[:60]}...")
    
    print(f"\n💡 SECURITY RECOMMENDATIONS:")
    print("  - Monitor high-severity devices closely")
    print("  - Implement additional authentication for vulnerable devices")
    print("  - Review and update security policies regularly")
    print("  - Consider network segmentation for critical devices")
    
    input("\nPress Enter to continue...")

def real_time_monitor():
    """Start real-time monitoring"""
    print("🔴 Starting Real-time Monitor...")
    
    from api_client import IoTForensicAPIClient
    import time
    
    client = IoTForensicAPIClient()
    
    try:
        duration = input("Monitor duration in minutes (default 5): ")
        duration = int(duration) if duration else 5
        client.monitor_real_time(duration)
    except ValueError:
        print("Invalid duration, using 5 minutes")
        client.monitor_real_time(5)
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user")

def show_help():
    """Show help information"""
    print("📚 HELP & USAGE")
    print("=" * 50)
    print()
    print("🖥️  CLI Dashboard:")
    print("   Interactive terminal-based dashboard with menus")
    print("   Best for: Manual analysis and investigation")
    print()
    print("🌐 API Server:")
    print("   REST API server with optional web interface")
    print("   Best for: Integration with other systems")
    print("   Endpoints: /api/logs, /api/devices, /api/analytics")
    print()
    print("📡 API Client:")
    print("   Programmatic access to the API")
    print("   Best for: Automated scripts and reporting")
    print()
    print("📊 Quick Analysis:")
    print("   Instant forensic report generation")
    print("   Best for: Fast overview of current status")
    print()
    print("🔴 Real-time Monitor:")
    print("   Live monitoring of system events")
    print("   Best for: Active threat detection")
    print()
    print("Command line usage:")
    print("  python app.py --mode cli     # CLI dashboard")
    print("  python app.py --mode api     # API server")
    print("  python app.py --mode client  # API client")
    print()
    input("Press Enter to continue...")

def main():
    print_banner()
    
    while True:
        show_menu()
        choice = input("Select option (1-7): ").strip()
        
        if choice == "1":
            run_cli_dashboard()
        elif choice == "2":
            run_api_server()
        elif choice == "3":
            run_api_client()
        elif choice == "4":
            quick_analysis()
        elif choice == "5":
            real_time_monitor()
        elif choice == "6":
            show_help()
        elif choice == "7":
            print("👋 Goodbye!")
            break
        else:
            print("❌ Invalid option. Please try again.")
            input("Press Enter to continue...")

if __name__ == "__main__":
    main()
</new_str>
