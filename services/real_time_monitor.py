
import threading
import time
import json
from datetime import datetime, timedelta
import logging
from queue import Queue
import asyncio
import websocket
from .ml_analyzer import MLAnalyzer
from .alert_system import AlertSystem

class RealTimeMonitor:
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.ml_analyzer = MLAnalyzer(db_manager)
        self.alert_system = AlertSystem(db_manager)
        self.is_monitoring = False
        self.monitor_thread = None
        self.log_queue = Queue()
        self.websocket_clients = set()
        
    def start_monitoring(self):
        """Start real-time monitoring"""
        if not self.is_monitoring:
            self.is_monitoring = True
            self.monitor_thread = threading.Thread(target=self._monitoring_loop)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()
            logging.info("Real-time monitoring started")
            
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join()
        logging.info("Real-time monitoring stopped")
        
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.is_monitoring:
            try:
                # Check for new logs every 5 seconds
                recent_logs = self.db_manager.execute_query(
                    """
                    SELECT * FROM logs 
                    WHERE created_at >= ? AND processed = FALSE
                    ORDER BY timestamp DESC
                    """,
                    (datetime.now() - timedelta(seconds=30),),
                    fetch=True
                )
                
                if recent_logs:
                    # Process new logs
                    for log in recent_logs:
                        self._process_real_time_log(log)
                        
                    # Mark logs as processed
                    log_ids = [log['id'] for log in recent_logs]
                    placeholders = ','.join(['?' for _ in log_ids])
                    self.db_manager.execute_query(
                        f"UPDATE logs SET processed = TRUE WHERE id IN ({placeholders})",
                        log_ids
                    )
                
                # Check for security patterns
                self._check_security_patterns()
                
                # Send real-time updates to connected clients
                self._broadcast_updates()
                
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                logging.error(f"Real-time monitoring error: {e}")
                time.sleep(10)
                
    def _process_real_time_log(self, log):
        """Process a single log in real-time"""
        try:
            # Run anomaly detection
            anomalies = self.ml_analyzer.detect_anomalies([log])
            if anomalies:
                # Mark as anomaly in database
                self.db_manager.execute_query(
                    "UPDATE logs SET is_anomaly = TRUE WHERE id = ?",
                    (log['id'],)
                )
                
                # Create alert
                self.alert_system.create_alert(
                    log['id'],
                    'anomaly_detected',
                    'medium',
                    f"Real-time anomaly detected: {anomalies[0]['confidence']:.2f} confidence"
                )
            
            # Check for attack patterns
            if log.get('attack_type'):
                self.alert_system.create_alert(
                    log['id'],
                    'attack_detected',
                    'high',
                    f"Attack detected: {log['attack_type']}"
                )
                
            # Check for critical severity
            if log.get('severity') == 'high':
                self.alert_system.create_alert(
                    log['id'],
                    'critical_event',
                    'critical',
                    f"Critical security event: {log.get('message', '')[:100]}"
                )
                
        except Exception as e:
            logging.error(f"Real-time log processing error: {e}")
            
    def _check_security_patterns(self):
        """Check for security breach patterns"""
        # Check for DDoS patterns
        self._check_ddos_pattern()
        
        # Check for brute force patterns
        self._check_brute_force_pattern()
        
        # Check for data exfiltration patterns
        self._check_data_exfiltration_pattern()
        
    def _check_ddos_pattern(self):
        """Check for DDoS attack patterns"""
        recent_time = datetime.now() - timedelta(minutes=5)
        
        # Count requests per device in last 5 minutes
        ddos_logs = self.db_manager.execute_query(
            """
            SELECT device_id, COUNT(*) as request_count
            FROM logs 
            WHERE timestamp >= ? 
            GROUP BY device_id
            HAVING request_count > 100
            """,
            (recent_time,),
            fetch=True
        )
        
        for log in ddos_logs:
            self.alert_system.create_alert(
                None,
                'ddos_detected',
                'critical',
                f"Potential DDoS attack: {log['request_count']} requests from device {log['device_id']}"
            )
            
    def _check_brute_force_pattern(self):
        """Check for brute force attack patterns"""
        recent_time = datetime.now() - timedelta(minutes=10)
        
        failed_logins = self.db_manager.execute_query(
            """
            SELECT device_id, COUNT(*) as failed_count
            FROM logs 
            WHERE timestamp >= ? AND message LIKE '%failed%login%'
            GROUP BY device_id
            HAVING failed_count > 5
            """,
            (recent_time,),
            fetch=True
        )
        
        for log in failed_logins:
            self.alert_system.create_alert(
                None,
                'brute_force_detected',
                'high',
                f"Brute force attack detected: {log['failed_count']} failed login attempts"
            )
            
    def _check_data_exfiltration_pattern(self):
        """Check for data exfiltration patterns"""
        recent_time = datetime.now() - timedelta(hours=1)
        
        suspicious_transfers = self.db_manager.execute_query(
            """
            SELECT device_id, COUNT(*) as transfer_count
            FROM logs 
            WHERE timestamp >= ? AND (
                message LIKE '%data%transfer%' OR 
                message LIKE '%upload%' OR 
                message LIKE '%download%'
            )
            GROUP BY device_id
            HAVING transfer_count > 20
            """,
            (recent_time,),
            fetch=True
        )
        
        for log in suspicious_transfers:
            self.alert_system.create_alert(
                None,
                'data_exfiltration_suspected',
                'high',
                f"Suspicious data transfer activity: {log['transfer_count']} transfers detected"
            )
            
    def _broadcast_updates(self):
        """Broadcast real-time updates to connected clients"""
        try:
            # Get latest alerts
            recent_alerts = self.db_manager.execute_query(
                """
                SELECT * FROM alerts 
                WHERE created_at >= ? 
                ORDER BY created_at DESC LIMIT 10
                """,
                (datetime.now() - timedelta(minutes=1),),
                fetch=True
            )
            
            if recent_alerts:
                update_data = {
                    'type': 'alerts',
                    'data': recent_alerts,
                    'timestamp': datetime.now().isoformat()
                }
                
                # In a real implementation, this would send to WebSocket clients
                logging.info(f"Broadcasting {len(recent_alerts)} new alerts")
                
        except Exception as e:
            logging.error(f"Broadcast error: {e}")
            
    def get_monitoring_status(self):
        """Get current monitoring status"""
        return {
            'is_monitoring': self.is_monitoring,
            'queue_size': self.log_queue.qsize(),
            'connected_clients': len(self.websocket_clients),
            'last_check': datetime.now().isoformat()
        }
        
    def add_log_to_queue(self, log_data):
        """Add log to processing queue"""
        self.log_queue.put(log_data)
        
    def get_real_time_stats(self):
        """Get real-time statistics"""
        current_time = datetime.now()
        last_hour = current_time - timedelta(hours=1)
        
        stats = {
            'logs_last_hour': 0,
            'alerts_last_hour': 0,
            'anomalies_detected': 0,
            'high_severity_events': 0,
            'active_devices': 0
        }
        
        try:
            # Logs in last hour
            logs_count = self.db_manager.execute_query(
                "SELECT COUNT(*) as count FROM logs WHERE timestamp >= ?",
                (last_hour,),
                fetch=True
            )
            stats['logs_last_hour'] = logs_count[0]['count'] if logs_count else 0
            
            # Alerts in last hour
            alerts_count = self.db_manager.execute_query(
                "SELECT COUNT(*) as count FROM alerts WHERE created_at >= ?",
                (last_hour,),
                fetch=True
            )
            stats['alerts_last_hour'] = alerts_count[0]['count'] if alerts_count else 0
            
            # Anomalies detected
            anomalies_count = self.db_manager.execute_query(
                "SELECT COUNT(*) as count FROM logs WHERE is_anomaly = TRUE AND timestamp >= ?",
                (last_hour,),
                fetch=True
            )
            stats['anomalies_detected'] = anomalies_count[0]['count'] if anomalies_count else 0
            
            # High severity events
            high_severity_count = self.db_manager.execute_query(
                "SELECT COUNT(*) as count FROM logs WHERE severity = 'high' AND timestamp >= ?",
                (last_hour,),
                fetch=True
            )
            stats['high_severity_events'] = high_severity_count[0]['count'] if high_severity_count else 0
            
            # Active devices
            active_devices_count = self.db_manager.execute_query(
                "SELECT COUNT(DISTINCT device_id) as count FROM logs WHERE timestamp >= ?",
                (last_hour,),
                fetch=True
            )
            stats['active_devices'] = active_devices_count[0]['count'] if active_devices_count else 0
            
        except Exception as e:
            logging.error(f"Error getting real-time stats: {e}")
            
        return stats
