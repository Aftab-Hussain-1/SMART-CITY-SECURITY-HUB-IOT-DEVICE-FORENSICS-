
import random
import json
from datetime import datetime, timedelta
from database.db_manager import DatabaseManager

class SampleDataGenerator:
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.iot_devices = [
            "Smart Traffic Light 001",
            "Environmental Sensor 002", 
            "Security Camera 003",
            "Smart Streetlight 004",
            "Parking Meter 005"
        ]
        
        self.attack_types = [
            "DDoS", "Brute Force", "Data Exfiltration", 
            "Port Scan", "Malware", "Man-in-the-Middle"
        ]
        
        self.protocols = ["HTTP", "HTTPS", "MQTT", "CoAP", "TCP", "UDP"]
        
        self.sample_messages = {
            "normal": [
                "Device status: operational",
                "Sensor reading: temperature 22.5°C",
                "Traffic flow: 150 vehicles/hour",
                "Camera recording started",
                "Lighting level adjusted to 75%",
                "Payment processed successfully",
                "Environmental data synchronized",
                "System health check completed"
            ],
            "suspicious": [
                "Multiple failed login attempts detected",
                "Unusual network traffic pattern",
                "Unauthorized access attempt blocked",
                "Suspicious data transfer detected",
                "Port scanning activity identified",
                "Malicious payload intercepted",
                "Anomalous behavior in sensor readings",
                "Potential DDoS attack in progress"
            ],
            "attack": [
                "DDoS attack detected: 50000 requests/sec",
                "Brute force attack: 100 failed logins in 5 minutes",
                "Data exfiltration attempt: 10GB transfer detected",
                "Port scan from 192.168.1.100: ports 22,23,80,443",
                "Malware signature detected in traffic",
                "Man-in-the-middle attack intercepted"
            ]
        }
        
    def generate_sample_logs(self, count=500):
        """Generate sample IoT logs for testing"""
        logs_generated = 0
        
        try:
            # Get device IDs
            devices = self.db_manager.get_devices()
            if not devices:
                print("No devices found. Please initialize database first.")
                return 0
                
            device_ids = [device['id'] for device in devices]
            
            # Generate logs over the past 7 days
            end_time = datetime.now()
            start_time = end_time - timedelta(days=7)
            
            for i in range(count):
                # Random timestamp within the last 7 days
                random_time = start_time + timedelta(
                    seconds=random.randint(0, int((end_time - start_time).total_seconds()))
                )
                
                # Random device
                device_id = random.choice(device_ids)
                
                # Determine log type and severity
                log_type = random.choices(
                    ["normal", "suspicious", "attack"],
                    weights=[70, 20, 10]  # 70% normal, 20% suspicious, 10% attack
                )[0]
                
                if log_type == "normal":
                    severity = "low"
                    attack_type = None
                    message = random.choice(self.sample_messages["normal"])
                elif log_type == "suspicious":
                    severity = random.choice(["medium", "high"])
                    attack_type = random.choice(self.attack_types) if random.random() > 0.5 else None
                    message = random.choice(self.sample_messages["suspicious"])
                else:  # attack
                    severity = "high"
                    attack_type = random.choice(self.attack_types)
                    message = random.choice(self.sample_messages["attack"])
                
                # Random protocol and source IP
                protocol = random.choice(self.protocols)
                source_ip = f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
                
                # Insert log
                log_id = self.db_manager.insert_log(
                    device_id=device_id,
                    timestamp=random_time,
                    log_level="INFO" if severity == "low" else "WARNING" if severity == "medium" else "ERROR",
                    message=message,
                    severity=severity,
                    attack_type=attack_type,
                    protocol=protocol,
                    source_ip=source_ip
                )
                
                if log_id:
                    logs_generated += 1
                    
                    # Occasionally mark some logs as anomalies
                    if random.random() < 0.05:  # 5% chance
                        self.db_manager.execute_query(
                            "UPDATE logs SET is_anomaly = TRUE WHERE id = ?",
                            (log_id,)
                        )
                
            print(f"Generated {logs_generated} sample logs")
            return logs_generated
            
        except Exception as e:
            print(f"Error generating sample logs: {e}")
            return logs_generated
            
    def generate_sample_alerts(self, count=50):
        """Generate sample alerts based on logs"""
        try:
            # Get recent high severity logs
            high_severity_logs = self.db_manager.execute_query(
                """
                SELECT l.*, d.device_name 
                FROM logs l 
                LEFT JOIN devices d ON l.device_id = d.id 
                WHERE l.severity = 'high' 
                ORDER BY l.timestamp DESC 
                LIMIT ?
                """,
                (count,),
                fetch=True
            )
            
            alerts_generated = 0
            
            for log in high_severity_logs:
                alert_types = [
                    "security_breach_detected",
                    "anomaly_detected", 
                    "attack_in_progress",
                    "system_compromise_suspected",
                    "data_integrity_violation"
                ]
                
                alert_type = random.choice(alert_types)
                severity = random.choice(["high", "critical"])
                
                description = f"Alert triggered by {log['device_name']}: {log['message'][:100]}"
                
                # Insert alert
                alert_query = """
                    INSERT INTO alerts (log_id, alert_type, severity, title, description, device_id)
                    VALUES (?, ?, ?, ?, ?, ?)
                """
                
                result = self.db_manager.execute_query(
                    alert_query,
                    (
                        log['id'],
                        alert_type,
                        severity,
                        f"{alert_type.replace('_', ' ').title()}",
                        description,
                        log['device_id']
                    )
                )
                
                if result:
                    alerts_generated += 1
            
            print(f"Generated {alerts_generated} sample alerts")
            return alerts_generated
            
        except Exception as e:
            print(f"Error generating sample alerts: {e}")
            return 0
            
    def populate_test_environment(self):
        """Populate the test environment with comprehensive sample data"""
        print("🔄 Populating test environment with sample data...")
        
        # Generate logs
        logs_count = self.generate_sample_logs(1000)
        
        # Generate alerts
        alerts_count = self.generate_sample_alerts(100)
        
        print(f"✅ Test environment populated:")
        print(f"   📝 {logs_count} sample logs generated")
        print(f"   🚨 {alerts_count} sample alerts generated")
        
        return {
            'logs_generated': logs_count,
            'alerts_generated': alerts_count
        }

if __name__ == "__main__":
    # Initialize database and generate sample data
    db_manager = DatabaseManager()
    db_manager.init_database()
    
    generator = SampleDataGenerator(db_manager)
    result = generator.populate_test_environment()
    
    print("\n🎯 Sample data generation completed!")
    print("You can now test the IoT forensic system with realistic data.")
