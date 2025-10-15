import json
import re
from datetime import datetime
import logging

class LogProcessor:
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.attack_patterns = {
            'ddos': r'(flood|ddos|dos attack)',
            'bruteforce': r'(failed login|authentication failed|brute force)',
            'malware': r'(virus|malware|trojan)',
            'data_exfiltration': r'(data transfer|exfiltration|unauthorized access)',
            'port_scan': r'(port scan|scanning|reconnaissance)'
        }

    def process_log_entry(self, raw_log):
        """Process a single log entry"""
        try:
            parsed_log = self.parse_log(raw_log)
            severity = self.determine_severity(parsed_log)
            attack_type = self.detect_attack_type(parsed_log['message'])

            processed_log = {
                'timestamp': parsed_log.get('timestamp', datetime.now()),
                'device': parsed_log.get('device', 'Unknown'),
                'message': parsed_log.get('message', ''),
                'severity': severity,
                'attack_type': attack_type,
                'protocol': parsed_log.get('protocol', 'Unknown')
            }

            return processed_log
        except Exception as e:
            logging.error(f"Error processing log: {e}")
            return None

    def parse_log(self, raw_log):
        """Parse raw log data"""
        if isinstance(raw_log, dict):
            return raw_log

        # Basic log parsing
        return {
            'timestamp': datetime.now(),
            'device': 'Unknown Device',
            'message': str(raw_log),
            'protocol': 'Unknown'
        }

    def determine_severity(self, log_data):
        """Determine log severity based on content"""
        message = log_data.get('message', '').lower()

        if any(keyword in message for keyword in ['critical', 'attack', 'breach', 'unauthorized']):
            return 'high'
        elif any(keyword in message for keyword in ['warning', 'unusual', 'suspicious']):
            return 'medium'
        else:
            return 'low'

    def detect_attack_type(self, message):
        """Detect attack type from log message"""
        message_lower = message.lower()

        for attack_type, pattern in self.attack_patterns.items():
            if re.search(pattern, message_lower):
                return attack_type.replace('_', ' ').title()

        return 'Unknown'