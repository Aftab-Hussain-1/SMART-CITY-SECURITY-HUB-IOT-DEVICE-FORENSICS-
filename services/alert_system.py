from datetime import datetime, timedelta
import json
import logging
from enum import Enum

class AlertSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AlertStatus(Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"

class AlertSystem:
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.alert_rules = {
            'multiple_failed_logins': {
                'threshold': 5,
                'time_window': 300,  # 5 minutes
                'severity': AlertSeverity.HIGH.value
            },
            'high_severity_logs': {
                'threshold': 3,
                'time_window': 600,  # 10 minutes
                'severity': AlertSeverity.HIGH.value
            },
            'anomaly_detection': {
                'threshold': 1,
                'time_window': 60,  # 1 minute
                'severity': AlertSeverity.MEDIUM.value
            },
            'attack_pattern': {
                'threshold': 1,
                'time_window': 0,  # Immediate
                'severity': AlertSeverity.HIGH.value
            }
        }
        self.alert_thresholds = {
            'high_severity_count': 5,
            'failed_login_attempts': 10,
            'unusual_traffic': 100
        }
    
    def create_alert(self, log_id, alert_type, severity, description):
        """Create a new alert"""
        try:
            query = """
                INSERT INTO alerts (log_id, alert_type, severity, description, status)
                VALUES (?, ?, ?, ?, ?)
            """
            result = self.db_manager.execute_query(
                query, 
                (log_id, alert_type, severity, description, AlertStatus.OPEN.value)
            )
            
            if result:
                logging.info(f"Alert created: {alert_type} - {severity}")
                return True
            return False
            
        except Exception as e:
            logging.error(f"Alert creation error: {e}")
            return False
    
    def check_alert_conditions(self, log_data):
        """Check if log data triggers any alert conditions"""
        alerts_triggered = []
        
        # Check for attack patterns
        if log_data.get('attack_type'):
            alert = self.create_alert(
                log_data['id'],
                'attack_detected',
                AlertSeverity.HIGH.value,
                f"Attack detected: {log_data['attack_type']} on device {log_data.get('device_name', 'Unknown')}"
            )
            if alert:
                alerts_triggered.append('attack_detected')
        
        # Check for high severity logs
        if log_data.get('severity') == 'high':
            alert = self.create_alert(
                log_data['id'],
                'high_severity_event',
                AlertSeverity.HIGH.value,
                f"High severity event on device {log_data.get('device_name', 'Unknown')}: {log_data.get('message', '')[:100]}"
            )
            if alert:
                alerts_triggered.append('high_severity_event')
        
        # Check for anomalies
        if log_data.get('is_anomaly'):
            alert = self.create_alert(
                log_data['id'],
                'anomaly_detected',
                AlertSeverity.MEDIUM.value,
                f"Anomaly detected on device {log_data.get('device_name', 'Unknown')}"
            )
            if alert:
                alerts_triggered.append('anomaly_detected')
        
        # Check for multiple failed login attempts
        if 'failed' in log_data.get('message', '').lower() and 'login' in log_data.get('message', '').lower():
            recent_failures = self.check_repeated_events(
                log_data.get('device_id'),
                'failed.*login',
                self.alert_rules['multiple_failed_logins']['time_window']
            )
            
            if recent_failures >= self.alert_rules['multiple_failed_logins']['threshold']:
                alert = self.create_alert(
                    log_data['id'],
                    'multiple_failed_logins',
                    AlertSeverity.HIGH.value,
                    f"Multiple failed login attempts detected on device {log_data.get('device_name', 'Unknown')}"
                )
                if alert:
                    alerts_triggered.append('multiple_failed_logins')
        
        return alerts_triggered
    
    def check_repeated_events(self, device_id, pattern, time_window):
        """Check for repeated events matching a pattern within a time window"""
        start_time = datetime.now() - timedelta(seconds=time_window)
        
        query = """
            SELECT COUNT(*) as count FROM logs 
            WHERE device_id = ? AND timestamp >= ? AND message LIKE ?
        """
        
        result = self.db_manager.execute_query(
            query, 
            (device_id, start_time, f"%{pattern}%"), 
            fetch=True
        )
        
        return result[0]['count'] if result else 0
    
    def get_active_alerts(self, severity=None, limit=50):
        """Get active alerts"""
        query = """
            SELECT a.*, l.message, l.timestamp as log_timestamp, d.device_name 
            FROM alerts a 
            JOIN logs l ON a.log_id = l.id 
            JOIN devices d ON l.device_id = d.id 
            WHERE a.status = ?
        """
        params = [AlertStatus.OPEN.value]
        
        if severity:
            query += " AND a.severity = ?"
            params.append(severity)
        
        query += " ORDER BY a.created_at DESC LIMIT ?"
        params.append(limit)
        
        return self.db_manager.execute_query(query, params, fetch=True)
    
    def update_alert_status(self, alert_id, new_status, resolution_notes=None):
        """Update alert status"""
        try:
            query = "UPDATE alerts SET status = %s"
            params = [new_status]
            
            if new_status == AlertStatus.RESOLVED.value:
                query += ", resolved_at = %s"
                params.append(datetime.now())
            
            if resolution_notes:
                query += ", description = description || ' | Resolution: ' || %s"
                params.append(resolution_notes)
            
            query += " WHERE id = %s"
            params.append(alert_id)
            
            return self.db_manager.execute_query(query, params)
            
        except Exception as e:
            logging.error(f"Alert update error: {e}")
            return False
    
    def get_alert_statistics(self, time_period='24h'):
        """Get alert statistics for a time period"""
        if time_period == '24h':
            time_delta = timedelta(hours=24)
        elif time_period == '7d':
            time_delta = timedelta(days=7)
        elif time_period == '30d':
            time_delta = timedelta(days=30)
        else:
            time_delta = timedelta(hours=24)
        
        start_time = datetime.now() - time_delta
        
        # Get alert counts by severity
        severity_query = """
            SELECT severity, COUNT(*) as count 
            FROM alerts 
            WHERE created_at >= ? 
            GROUP BY severity
        """
        severity_stats = self.db_manager.execute_query(severity_query, (start_time,), fetch=True)
        
        # Get alert counts by type
        type_query = """
            SELECT alert_type, COUNT(*) as count 
            FROM alerts 
            WHERE created_at >= ? 
            GROUP BY alert_type
        """
        type_stats = self.db_manager.execute_query(type_query, (start_time,), fetch=True)
        
        # Get resolution statistics
        resolution_query = """
            SELECT status, COUNT(*) as count 
            FROM alerts 
            WHERE created_at >= ? 
            GROUP BY status
        """
        resolution_stats = self.db_manager.execute_query(resolution_query, (start_time,), fetch=True)
        
        return {
            'severity_distribution': {row['severity']: row['count'] for row in severity_stats} if severity_stats else {},
            'alert_types': {row['alert_type']: row['count'] for row in type_stats} if type_stats else {},
            'resolution_status': {row['status']: row['count'] for row in resolution_stats} if resolution_stats else {},
            'time_period': time_period
        }
    
    def escalate_alert(self, alert_id, new_severity, escalation_reason):
        """Escalate an alert to higher severity"""
        try:
            query = """
                UPDATE alerts 
                SET severity = %s, description = description || ' | Escalated: ' || %s 
                WHERE id = %s
            """
            return self.db_manager.execute_query(
                query, 
                (new_severity, escalation_reason, alert_id)
            )
            
        except Exception as e:
            logging.error(f"Alert escalation error: {e}")
            return False
    
    def send_notification(self, alert_data):
        """Send notification for critical alerts (placeholder for integration)"""
        # This would integrate with external notification systems
        # like email, Slack, SMS, etc.
        logging.info(f"Notification would be sent for alert: {alert_data}")
        
        # For now, just log the notification
        if alert_data.get('severity') in [AlertSeverity.HIGH.value, AlertSeverity.CRITICAL.value]:
            print(f"🚨 CRITICAL ALERT: {alert_data.get('description')}")
        
        return True

    def check_alerts(self):
        """Check for alert conditions"""
        alerts = []

        # Check for high severity events
        high_severity_logs = self.get_recent_high_severity_logs()
        if len(high_severity_logs) >= self.alert_thresholds['high_severity_count']:
            alerts.append({
                'type': 'high_severity_spike',
                'message': f'High number of severe events detected: {len(high_severity_logs)}',
                'timestamp': datetime.now(),
                'severity': 'critical'
            })

        return alerts

    def get_recent_high_severity_logs(self):
        """Get recent high severity logs"""
        # This would query the database for recent high severity logs
        # For now, return sample data
        return [
            {'id': 1, 'severity': 'high', 'timestamp': datetime.now()},
            {'id': 2, 'severity': 'high', 'timestamp': datetime.now()}
        ]

    def send_alert(self, alert):
        """Send alert notification"""
        logging.warning(f"ALERT: {alert['message']}")
        # In production, this would send emails, SMS, or push notifications
        return True