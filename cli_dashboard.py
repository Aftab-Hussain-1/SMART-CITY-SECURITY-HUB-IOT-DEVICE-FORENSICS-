import os
import time
from datetime import datetime, timedelta
from services.log_processor import LogProcessor
from services.alert_system import AlertSystem
from services.ml_analyzer import MLAnalyzer
from database.db_manager import DatabaseManager
import json


class CLIDashboard:

    def __init__(self):
        self.db_manager = DatabaseManager()
        self.log_processor = LogProcessor(self.db_manager)
        self.alert_system = AlertSystem(self.db_manager)
        self.ml_analyzer = MLAnalyzer(self.db_manager)

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def print_header(self):
        print("=" * 80)
        print("🔒 IoT Device Log Forensic Analysis System")
        print("=" * 80)
        print(f"Current Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 80)

    def show_main_menu(self):
        print("\n📋 Main Menu:")
        print("1. View Dashboard Overview")
        print("2. Analyze Device Logs")
        print("3. View Active Alerts")
        print("4. Device Management")
        print("5. Security Analysis")
        print("6. Generate Reports")
        print("7. Real-time Monitoring")
        print("8. Exit")
        return input("\nSelect option (1-8): ")

    def show_dashboard_overview(self):
        self.clear_screen()
        self.print_header()

        print("📊 DASHBOARD OVERVIEW")
        print("-" * 50)

        # Get statistics
        devices = self.db_manager.get_devices()
        logs = self.db_manager.get_logs(limit=1000)
        alerts = self.db_manager.get_alerts()

        print(f"🖥️  Total Devices: {len(devices) if devices else 0}")
        print(f"📝 Total Logs: {len(logs) if logs else 0}")
        print(
            f"🚨 Active Alerts: {len([a for a in alerts if a['status'] == 'open']) if alerts else 0}"
        )

        if logs:
            high_severity = len(
                [l for l in logs if l.get('severity') == 'high'])
            print(f"⚠️  High Severity Events: {high_severity}")

        print("\n🔍 Recent Activity:")
        if logs:
            for log in logs[:5]:
                severity_icon = "🔴" if log.get(
                    'severity') == 'high' else "🟡" if log.get(
                        'severity') == 'medium' else "🟢"
                print(
                    f"{severity_icon} {log.get('timestamp', 'N/A')} - {log.get('device_name', 'Unknown')} - {log.get('message', '')[:50]}..."
                )
        else:
            print("No recent logs found")

        input("\nPress Enter to continue...")

    def analyze_device_logs(self):
        self.clear_screen()
        self.print_header()

        print("🔍 DEVICE LOG ANALYSIS")
        print("-" * 50)

        devices = self.db_manager.get_devices()
        if not devices:
            print("No devices found")
            input("Press Enter to continue...")
            return

        print("Available Devices:")
        for i, device in enumerate(devices):
            print(f"{i+1}. {device['device_name']} ({device['device_type']})")

        try:
            choice = int(input("\nSelect device (number): ")) - 1
            if 0 <= choice < len(devices):
                device = devices[choice]
                self.show_device_analysis(device)
            else:
                print("Invalid selection")
        except ValueError:
            print("Invalid input")

        input("Press Enter to continue...")

    def show_device_analysis(self, device):
        device_logs = self.db_manager.get_logs(device_id=device['id'],
                                               limit=50)

        print(f"\n📱 Analysis for: {device['device_name']}")
        print("-" * 40)

        if device_logs:
            severity_count = {'high': 0, 'medium': 0, 'low': 0}
            attack_types = {}

            for log in device_logs:
                severity = log.get('severity', 'low')
                severity_count[severity] = severity_count.get(severity, 0) + 1

                attack_type = log.get('attack_type')
                if attack_type:
                    attack_types[attack_type] = attack_types.get(
                        attack_type, 0) + 1

            print(f"Total Logs: {len(device_logs)}")
            print(f"🔴 High Severity: {severity_count['high']}")
            print(f"🟡 Medium Severity: {severity_count['medium']}")
            print(f"🟢 Low Severity: {severity_count['low']}")

            if attack_types:
                print("\nAttack Types Detected:")
                for attack, count in attack_types.items():
                    print(f"  - {attack}: {count}")

            print(
                f"\nRisk Score: {self.ml_analyzer.predict_risk_score(device['id']):.2f}/10"
            )

            print("\nRecent Logs:")
            for log in device_logs[:10]:
                severity_icon = "🔴" if log.get(
                    'severity') == 'high' else "🟡" if log.get(
                        'severity') == 'medium' else "🟢"
                print(
                    f"{severity_icon} {log.get('timestamp', 'N/A')} - {log.get('message', '')[:60]}..."
                )
        else:
            print("No logs found for this device")

    def view_active_alerts(self):
        self.clear_screen()
        self.print_header()

        print("🚨 ACTIVE ALERTS")
        print("-" * 50)

        alerts = self.alert_system.get_active_alerts()

        if alerts:
            for alert in alerts:
                severity_icon = "🔴" if alert[
                    'severity'] == 'high' else "🟡" if alert[
                        'severity'] == 'medium' else "🟢"
                print(f"{severity_icon} {alert['alert_type'].upper()}")
                print(f"   Device: {alert.get('device_name', 'Unknown')}")
                print(f"   Time: {alert['created_at']}")
                print(f"   Description: {alert['description']}")
                print("-" * 40)
        else:
            print("✅ No active alerts")

        input("\nPress Enter to continue...")

    def device_management(self):
        self.clear_screen()
        self.print_header()

        print("🖥️ DEVICE MANAGEMENT")
        print("-" * 50)

        devices = self.db_manager.get_devices()

        if devices:
            print("Registered Devices:")
            for device in devices:
                status_icon = "🟢" if device['status'] == 'active' else "🔴"
                print(
                    f"{status_icon} {device['device_name']} ({device['device_type']})"
                )
                print(f"   Location: {device.get('location', 'Unknown')}")
                print(f"   Status: {device['status']}")
                print("-" * 30)
        else:
            print("No devices registered")

        print("\nOptions:")
        print("1. Add new device")
        print("2. View device details")
        print("3. Back to main menu")

        choice = input("Select option: ")

        if choice == "1":
            self.add_new_device()
        elif choice == "2":
            self.view_device_details()

    def add_new_device(self):
        print("\n➕ ADD NEW DEVICE")
        name = input("Device name: ")
        device_type = input("Device type: ")
        location = input("Location (optional): ")

        device_id = self.db_manager.insert_device(name, device_type, location)
        if device_id:
            print(f"✅ Device '{name}' added successfully with ID: {device_id}")
        else:
            print("❌ Failed to add device")

    def security_analysis(self):
        self.clear_screen()
        self.print_header()

        print("🔐 SECURITY ANALYSIS")
        print("-" * 50)

        # Analyze attack patterns
        patterns = self.ml_analyzer.analyze_attack_patterns()

        print("📊 Attack Pattern Analysis:")
        if patterns['most_common_attacks']:
            print("\nMost Common Attacks:")
            for attack, count in patterns['most_common_attacks'].items():
                print(f"  - {attack}: {count} incidents")
        else:
            print("No attack patterns detected")

        if patterns['severity_distribution']:
            print("\nSeverity Distribution:")
            for severity, count in patterns['severity_distribution'].items():
                print(f"  - {severity}: {count}")

        # Check for anomalies
        print("\n🔍 Anomaly Detection:")
        devices = self.db_manager.get_devices()
        for device in devices[:5]:  # Check first 5 devices
            risk_score = self.ml_analyzer.predict_risk_score(device['id'])
            risk_level = "HIGH" if risk_score > 7 else "MEDIUM" if risk_score > 4 else "LOW"
            risk_icon = "🔴" if risk_level == "HIGH" else "🟡" if risk_level == "MEDIUM" else "🟢"
            print(
                f"{risk_icon} {device['device_name']}: Risk Level {risk_level} ({risk_score:.1f}/10)"
            )

        input("\nPress Enter to continue...")

    def generate_reports(self):
        self.clear_screen()
        self.print_header()

        print("📋 FORENSIC REPORT GENERATOR")
        print("-" * 50)

        print("Report Types:")
        print("1. Security Summary Report")
        print("2. Device Activity Report")
        print("3. Alert Analysis Report")
        print("4. Full Forensic Report")

        choice = input("Select report type (1-4): ")

        if choice == "1":
            self.generate_security_report()
        elif choice == "2":
            self.generate_device_report()
        elif choice == "3":
            self.generate_alert_report()
        elif choice == "4":
            self.generate_full_report()

    def generate_security_report(self):
        print("\n🔒 SECURITY SUMMARY REPORT")
        print("=" * 50)
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 50)

        logs = self.db_manager.get_logs(limit=1000)
        alerts = self.db_manager.get_alerts()

        if logs:
            high_severity = len(
                [l for l in logs if l.get('severity') == 'high'])
            attack_logs = [l for l in logs if l.get('attack_type')]

            print(f"📊 STATISTICS:")
            print(f"Total Security Events: {len(logs)}")
            print(f"High Severity Events: {high_severity}")
            print(f"Attack Attempts: {len(attack_logs)}")
            print(
                f"Active Alerts: {len([a for a in alerts if a['status'] == 'open']) if alerts else 0}"
            )

            if attack_logs:
                attack_types = {}
                for log in attack_logs:
                    attack_type = log.get('attack_type')
                    attack_types[attack_type] = attack_types.get(
                        attack_type, 0) + 1

                print(f"\n🎯 ATTACK BREAKDOWN:")
                for attack, count in sorted(attack_types.items(),
                                            key=lambda x: x[1],
                                            reverse=True):
                    print(f"  - {attack}: {count} attempts")

        print(f"\n💡 RECOMMENDATIONS:")
        print("  - Monitor high-risk devices more closely")
        print(
            "  - Implement additional security measures for vulnerable devices"
        )
        print("  - Review and update security policies")

        input("\nPress Enter to continue...")

    def real_time_monitoring(self):
        self.clear_screen()
        print("🔴 REAL-TIME MONITORING MODE")
        print("Press Ctrl+C to exit monitoring mode")
        print("-" * 50)

        try:
            while True:
                # Get recent logs (last 5 minutes)
                recent_time = datetime.now() - timedelta(minutes=5)
                logs = self.db_manager.get_logs(limit=20)

                if logs:
                    recent_logs = [
                        l for l in logs
                        if datetime.fromisoformat(l['timestamp'].replace(
                            'Z', '+00:00')) > recent_time
                    ]

                    if recent_logs:
                        print(
                            f"\n[{datetime.now().strftime('%H:%M:%S')}] Recent Activity:"
                        )
                        for log in recent_logs[:5]:
                            severity_icon = "🔴" if log.get(
                                'severity') == 'high' else "🟡" if log.get(
                                    'severity') == 'medium' else "🟢"
                            print(
                                f"{severity_icon} {log.get('device_name', 'Unknown')} - {log.get('message', '')[:60]}..."
                            )
                    else:
                        print(
                            f"[{datetime.now().strftime('%H:%M:%S')}] No recent activity"
                        )

                # Check for new alerts
                alerts = self.alert_system.check_alerts()
                if alerts:
                    for alert in alerts:
                        print(f"🚨 ALERT: {alert['message']}")

                time.sleep(10)  # Update every 10 seconds

        except KeyboardInterrupt:
            print("\n\nMonitoring stopped.")
            input("Press Enter to continue...")

    def run(self):
        while True:
            self.clear_screen()
            self.print_header()

            choice = self.show_main_menu()

            if choice == "1":
                self.show_dashboard_overview()
            elif choice == "2":
                self.analyze_device_logs()
            elif choice == "3":
                self.view_active_alerts()
            elif choice == "4":
                self.device_management()
            elif choice == "5":
                self.security_analysis()
            elif choice == "6":
                self.generate_reports()
            elif choice == "7":
                self.real_time_monitoring()
            elif choice == "8":
                print("👋 Goodbye!")
                break
            else:
                print("Invalid option. Please try again.")
                time.sleep(1)


if __name__ == "__main__":
    dashboard = CLIDashboard()
    dashboard.run()
