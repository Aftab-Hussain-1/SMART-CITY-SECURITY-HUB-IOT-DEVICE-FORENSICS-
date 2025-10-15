
import re
import ipaddress
import json
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import logging

class NetworkAnalyzer:
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.suspicious_ports = [22, 23, 135, 139, 445, 1433, 3389, 5432, 5900]
        self.known_attack_signatures = {
            'port_scan': r'(?:nmap|masscan|zmap)',
            'sql_injection': r'(?:union|select|insert|drop|delete|update).*(?:from|into|where)',
            'xss': r'<script|javascript:|onload=|onerror=',
            'directory_traversal': r'\.\.\/|\.\.\\',
            'command_injection': r'(?:;|\||\&)\s*(?:cat|ls|dir|type|echo)',
        }
        self.iot_protocols = ['MQTT', 'CoAP', 'AMQP', 'DDS', 'HTTP', 'HTTPS', 'TCP', 'UDP']
        
    def analyze_network_traffic(self, time_period='24h'):
        """Analyze network traffic patterns from logs"""
        try:
            if time_period == '24h':
                time_delta = timedelta(hours=24)
            elif time_period == '7d':
                time_delta = timedelta(days=7)
            else:
                time_delta = timedelta(hours=24)
                
            start_time = datetime.now() - time_delta
            
            # Get logs with network information
            network_logs = self.db_manager.execute_query(
                """
                SELECT l.*, d.device_name, d.device_type, d.location
                FROM logs l
                LEFT JOIN devices d ON l.device_id = d.id
                WHERE l.timestamp >= ? AND (
                    l.source_ip IS NOT NULL OR 
                    l.protocol IS NOT NULL OR
                    l.message LIKE '%ip%' OR
                    l.message LIKE '%port%' OR
                    l.message LIKE '%connection%'
                )
                ORDER BY l.timestamp DESC
                """,
                (start_time,),
                fetch=True
            )
            
            if not network_logs:
                return self._empty_network_analysis()
                
            analysis = {
                'traffic_summary': self._analyze_traffic_summary(network_logs),
                'protocol_distribution': self._analyze_protocol_distribution(network_logs),
                'ip_analysis': self._analyze_ip_patterns(network_logs),
                'port_analysis': self._analyze_port_activity(network_logs),
                'connection_patterns': self._analyze_connection_patterns(network_logs),
                'suspicious_activities': self._detect_suspicious_network_activities(network_logs),
                'iot_protocol_analysis': self._analyze_iot_protocols(network_logs),
                'bandwidth_analysis': self._analyze_bandwidth_patterns(network_logs),
                'geographic_analysis': self._analyze_geographic_patterns(network_logs)
            }
            
            return analysis
            
        except Exception as e:
            logging.error(f"Error analyzing network traffic: {e}")
            return self._empty_network_analysis()
            
    def _analyze_traffic_summary(self, logs):
        """Analyze overall traffic summary"""
        summary = {
            'total_connections': len(logs),
            'unique_source_ips': set(),
            'unique_protocols': set(),
            'total_devices': set(),
            'time_span': None,
            'peak_traffic_hour': None,
            'average_connections_per_hour': 0
        }
        
        hourly_traffic = defaultdict(int)
        
        for log in logs:
            if log.get('source_ip'):
                summary['unique_source_ips'].add(log['source_ip'])
            if log.get('protocol'):
                summary['unique_protocols'].add(log['protocol'])
            if log.get('device_name'):
                summary['total_devices'].add(log['device_name'])
                
            # Analyze hourly traffic
            timestamp = datetime.fromisoformat(log['timestamp'].replace('Z', '+00:00'))
            hour_key = timestamp.strftime('%Y-%m-%d %H:00:00')
            hourly_traffic[hour_key] += 1
        
        # Convert sets to counts
        summary['unique_source_ips'] = len(summary['unique_source_ips'])
        summary['unique_protocols'] = len(summary['unique_protocols'])
        summary['total_devices'] = len(summary['total_devices'])
        
        # Find peak traffic hour
        if hourly_traffic:
            peak_hour = max(hourly_traffic, key=hourly_traffic.get)
            summary['peak_traffic_hour'] = {
                'hour': peak_hour,
                'connections': hourly_traffic[peak_hour]
            }
            summary['average_connections_per_hour'] = sum(hourly_traffic.values()) / len(hourly_traffic)
        
        return summary
        
    def _analyze_protocol_distribution(self, logs):
        """Analyze protocol usage distribution"""
        protocol_stats = defaultdict(int)
        protocol_by_device = defaultdict(lambda: defaultdict(int))
        
        for log in logs:
            protocol = log.get('protocol', 'Unknown')
            device_name = log.get('device_name', 'Unknown')
            
            protocol_stats[protocol] += 1
            protocol_by_device[device_name][protocol] += 1
        
        # Find most used protocols
        sorted_protocols = sorted(protocol_stats.items(), key=lambda x: x[1], reverse=True)
        
        return {
            'protocol_counts': dict(protocol_stats),
            'top_protocols': sorted_protocols[:10],
            'protocol_by_device': dict(protocol_by_device),
            'protocol_diversity': len(protocol_stats)
        }
        
    def _analyze_ip_patterns(self, logs):
        """Analyze IP address patterns and detect anomalies"""
        ip_stats = {
            'source_ips': defaultdict(int),
            'suspicious_ips': [],
            'internal_ips': [],
            'external_ips': [],
            'private_ranges': defaultdict(int),
            'ip_reputation': {}
        }
        
        for log in logs:
            source_ip = log.get('source_ip')
            if not source_ip:
                continue
                
            ip_stats['source_ips'][source_ip] += 1
            
            try:
                ip_obj = ipaddress.ip_address(source_ip)
                
                if ip_obj.is_private:
                    ip_stats['internal_ips'].append(source_ip)
                    # Categorize private ranges
                    if str(ip_obj).startswith('192.168.'):
                        ip_stats['private_ranges']['192.168.x.x'] += 1
                    elif str(ip_obj).startswith('10.'):
                        ip_stats['private_ranges']['10.x.x.x'] += 1
                    elif str(ip_obj).startswith('172.'):
                        ip_stats['private_ranges']['172.16-31.x.x'] += 1
                else:
                    ip_stats['external_ips'].append(source_ip)
                    
            except ValueError:
                # Invalid IP address
                ip_stats['suspicious_ips'].append({
                    'ip': source_ip,
                    'reason': 'Invalid IP format',
                    'occurrences': ip_stats['source_ips'][source_ip]
                })
        
        # Identify suspicious IPs (high frequency connections)
        for ip, count in ip_stats['source_ips'].items():
            if count > 100:  # Threshold for suspicious activity
                ip_stats['suspicious_ips'].append({
                    'ip': ip,
                    'reason': 'High frequency connections',
                    'occurrences': count
                })
        
        # Remove duplicates and convert to unique lists
        ip_stats['internal_ips'] = list(set(ip_stats['internal_ips']))
        ip_stats['external_ips'] = list(set(ip_stats['external_ips']))
        
        return ip_stats
        
    def _analyze_port_activity(self, logs):
        """Analyze port usage and detect suspicious port activity"""
        port_stats = {
            'port_usage': defaultdict(int),
            'suspicious_ports': [],
            'common_ports': [],
            'uncommon_ports': [],
            'port_scans': []
        }
        
        for log in logs:
            # Extract port information from log messages
            message = log.get('message', '')
            port_matches = re.findall(r':(\d+)', message)
            
            for port_str in port_matches:
                try:
                    port = int(port_str)
                    if 1 <= port <= 65535:  # Valid port range
                        port_stats['port_usage'][port] += 1
                        
                        # Check if it's a suspicious port
                        if port in self.suspicious_ports:
                            port_stats['suspicious_ports'].append({
                                'port': port,
                                'device': log.get('device_name', 'Unknown'),
                                'timestamp': log.get('timestamp'),
                                'message': message[:100]
                            })
                except ValueError:
                    continue
        
        # Categorize ports
        for port, count in port_stats['port_usage'].items():
            if port <= 1024:  # Well-known ports
                port_stats['common_ports'].append({'port': port, 'count': count})
            else:
                port_stats['uncommon_ports'].append({'port': port, 'count': count})
        
        # Sort by usage
        port_stats['common_ports'].sort(key=lambda x: x['count'], reverse=True)
        port_stats['uncommon_ports'].sort(key=lambda x: x['count'], reverse=True)
        
        # Detect potential port scans (many different ports from same source)
        ip_port_map = defaultdict(set)
        for log in logs:
            source_ip = log.get('source_ip')
            message = log.get('message', '')
            ports = re.findall(r':(\d+)', message)
            
            if source_ip and ports:
                for port in ports:
                    try:
                        ip_port_map[source_ip].add(int(port))
                    except ValueError:
                        continue
        
        for ip, ports in ip_port_map.items():
            if len(ports) > 10:  # Accessing many different ports
                port_stats['port_scans'].append({
                    'source_ip': ip,
                    'ports_accessed': list(ports)[:20],  # Limit for display
                    'total_ports': len(ports)
                })
        
        return port_stats
        
    def _analyze_connection_patterns(self, logs):
        """Analyze connection patterns and behaviors"""
        patterns = {
            'connection_types': defaultdict(int),
            'failed_connections': [],
            'long_connections': [],
            'connection_timeline': defaultdict(int),
            'device_connections': defaultdict(int)
        }
        
        for log in logs:
            message = log.get('message', '').lower()
            device_name = log.get('device_name', 'Unknown')
            timestamp = log.get('timestamp')
            
            # Categorize connection types
            if 'connect' in message:
                patterns['connection_types']['connection_attempts'] += 1
            if 'disconnect' in message:
                patterns['connection_types']['disconnections'] += 1
            if 'timeout' in message:
                patterns['connection_types']['timeouts'] += 1
            if 'refused' in message:
                patterns['connection_types']['refused'] += 1
            if 'established' in message:
                patterns['connection_types']['established'] += 1
                
            # Track failed connections
            if any(keyword in message for keyword in ['failed', 'error', 'refused', 'timeout']):
                patterns['failed_connections'].append({
                    'device': device_name,
                    'timestamp': timestamp,
                    'message': log.get('message', '')[:100]
                })
            
            # Track connections by device
            patterns['device_connections'][device_name] += 1
            
            # Timeline analysis
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                hour_key = dt.strftime('%H:00')
                patterns['connection_timeline'][hour_key] += 1
            except:
                pass
        
        return patterns
        
    def _detect_suspicious_network_activities(self, logs):
        """Detect suspicious network activities using signature matching"""
        suspicious_activities = []
        
        for log in logs:
            message = log.get('message', '').lower()
            device_name = log.get('device_name', 'Unknown')
            timestamp = log.get('timestamp')
            
            # Check against known attack signatures
            for attack_type, pattern in self.known_attack_signatures.items():
                if re.search(pattern, message, re.IGNORECASE):
                    suspicious_activities.append({
                        'attack_type': attack_type,
                        'device': device_name,
                        'timestamp': timestamp,
                        'message': log.get('message', '')[:150],
                        'severity': 'high',
                        'signature_matched': pattern
                    })
            
            # Additional suspicious patterns
            if re.search(r'(\d+\.\d+\.\d+\.\d+).*(\d+\.\d+\.\d+\.\d+)', message):
                # Multiple IP addresses in one message (potential lateral movement)
                suspicious_activities.append({
                    'attack_type': 'potential_lateral_movement',
                    'device': device_name,
                    'timestamp': timestamp,
                    'message': log.get('message', '')[:150],
                    'severity': 'medium',
                    'signature_matched': 'multiple_ips'
                })
        
        return suspicious_activities
        
    def _analyze_iot_protocols(self, logs):
        """Analyze IoT-specific protocol usage"""
        iot_analysis = {
            'protocol_usage': defaultdict(int),
            'mqtt_analysis': {'topics': [], 'qos_levels': [], 'retained_messages': 0},
            'coap_analysis': {'methods': [], 'response_codes': []},
            'http_analysis': {'methods': [], 'status_codes': [], 'user_agents': []},
            'security_concerns': []
        }
        
        for log in logs:
            protocol = log.get('protocol', '').upper()
            message = log.get('message', '')
            
            if protocol in self.iot_protocols:
                iot_analysis['protocol_usage'][protocol] += 1
                
                # MQTT specific analysis
                if protocol == 'MQTT':
                    if 'topic:' in message.lower():
                        topic_match = re.search(r'topic:\s*([^\s]+)', message, re.IGNORECASE)
                        if topic_match:
                            iot_analysis['mqtt_analysis']['topics'].append(topic_match.group(1))
                    
                    if 'retain' in message.lower():
                        iot_analysis['mqtt_analysis']['retained_messages'] += 1
                        
                # CoAP specific analysis
                elif protocol == 'COAP':
                    coap_methods = ['GET', 'POST', 'PUT', 'DELETE']
                    for method in coap_methods:
                        if method in message.upper():
                            iot_analysis['coap_analysis']['methods'].append(method)
                
                # HTTP specific analysis
                elif protocol in ['HTTP', 'HTTPS']:
                    http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
                    for method in http_methods:
                        if method in message.upper():
                            iot_analysis['http_analysis']['methods'].append(method)
                    
                    # Extract status codes
                    status_matches = re.findall(r'\b[1-5]\d{2}\b', message)
                    iot_analysis['http_analysis']['status_codes'].extend(status_matches)
                    
                    # Extract User-Agent if present
                    ua_match = re.search(r'user-agent:\s*([^\r\n]+)', message, re.IGNORECASE)
                    if ua_match:
                        iot_analysis['http_analysis']['user_agents'].append(ua_match.group(1))
            
            # Check for security concerns
            if any(concern in message.lower() for concern in ['plaintext', 'unencrypted', 'no auth']):
                iot_analysis['security_concerns'].append({
                    'device': log.get('device_name', 'Unknown'),
                    'concern': 'unencrypted_communication',
                    'message': message[:100]
                })
        
        return iot_analysis
        
    def _analyze_bandwidth_patterns(self, logs):
        """Analyze bandwidth usage patterns"""
        bandwidth_analysis = {
            'data_transfer_events': 0,
            'upload_events': 0,
            'download_events': 0,
            'large_transfers': [],
            'peak_usage_times': defaultdict(int)
        }
        
        for log in logs:
            message = log.get('message', '').lower()
            timestamp = log.get('timestamp')
            
            # Look for data transfer indicators
            if any(keyword in message for keyword in ['bytes', 'kb', 'mb', 'gb', 'transfer']):
                bandwidth_analysis['data_transfer_events'] += 1
                
                # Extract data sizes
                size_matches = re.findall(r'(\d+(?:\.\d+)?)\s*(bytes|kb|mb|gb)', message)
                for size, unit in size_matches:
                    try:
                        size_value = float(size)
                        if unit == 'mb' and size_value > 100:  # Large transfers > 100MB
                            bandwidth_analysis['large_transfers'].append({
                                'device': log.get('device_name', 'Unknown'),
                                'size': f"{size} {unit}",
                                'timestamp': timestamp
                            })
                    except ValueError:
                        continue
            
            if 'upload' in message:
                bandwidth_analysis['upload_events'] += 1
            if 'download' in message:
                bandwidth_analysis['download_events'] += 1
                
            # Track usage by hour
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                hour_key = dt.strftime('%H:00')
                bandwidth_analysis['peak_usage_times'][hour_key] += 1
            except:
                pass
        
        return bandwidth_analysis
        
    def _analyze_geographic_patterns(self, logs):
        """Analyze geographic patterns from device locations"""
        geo_analysis = {
            'locations': defaultdict(int),
            'device_distribution': {},
            'high_activity_locations': []
        }
        
        location_activity = defaultdict(int)
        
        for log in logs:
            location = log.get('location')
            device_name = log.get('device_name', 'Unknown')
            
            if location:
                geo_analysis['locations'][location] += 1
                location_activity[location] += 1
                
                if location not in geo_analysis['device_distribution']:
                    geo_analysis['device_distribution'][location] = set()
                geo_analysis['device_distribution'][location].add(device_name)
        
        # Convert device sets to counts
        for location, devices in geo_analysis['device_distribution'].items():
            geo_analysis['device_distribution'][location] = len(devices)
        
        # Find high activity locations
        sorted_locations = sorted(location_activity.items(), key=lambda x: x[1], reverse=True)
        geo_analysis['high_activity_locations'] = sorted_locations[:5]
        
        return geo_analysis
        
    def _empty_network_analysis(self):
        """Return empty network analysis structure"""
        return {
            'traffic_summary': {},
            'protocol_distribution': {},
            'ip_analysis': {},
            'port_analysis': {},
            'connection_patterns': {},
            'suspicious_activities': [],
            'iot_protocol_analysis': {},
            'bandwidth_analysis': {},
            'geographic_analysis': {}
        }
        
    def generate_network_security_report(self, time_period='24h'):
        """Generate comprehensive network security report"""
        analysis = self.analyze_network_traffic(time_period)
        
        report = {
            'report_id': f"NET_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'generated_at': datetime.now().isoformat(),
            'time_period': time_period,
            'network_analysis': analysis,
            'security_recommendations': self._generate_network_recommendations(analysis),
            'threat_assessment': self._assess_network_threats(analysis)
        }
        
        return report
        
    def _generate_network_recommendations(self, analysis):
        """Generate network security recommendations"""
        recommendations = []
        
        # Check for suspicious activities
        if analysis['suspicious_activities']:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Network Security',
                'recommendation': 'Investigate suspicious network activities',
                'details': f"Detected {len(analysis['suspicious_activities'])} suspicious network activities"
            })
        
        # Check for unencrypted communications
        if analysis['iot_protocol_analysis']['security_concerns']:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Protocol Security',
                'recommendation': 'Implement encryption for IoT communications',
                'details': 'Unencrypted communications detected in IoT devices'
            })
        
        # Check for port scanning
        if analysis['port_analysis']['port_scans']:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Network Security',
                'recommendation': 'Implement port scan detection and blocking',
                'details': f"Detected {len(analysis['port_analysis']['port_scans'])} potential port scans"
            })
        
        return recommendations
        
    def _assess_network_threats(self, analysis):
        """Assess network-based threats"""
        threat_level = 'LOW'
        threats = []
        
        # Assess based on suspicious activities
        if len(analysis['suspicious_activities']) > 10:
            threat_level = 'HIGH'
            threats.append('Multiple suspicious network activities detected')
        elif len(analysis['suspicious_activities']) > 5:
            threat_level = 'MEDIUM'
            threats.append('Some suspicious network activities detected')
        
        # Assess based on port scans
        if analysis['port_analysis']['port_scans']:
            if threat_level == 'LOW':
                threat_level = 'MEDIUM'
            threats.append('Port scanning activities detected')
        
        # Assess based on failed connections
        failed_connections = len(analysis['connection_patterns']['failed_connections'])
        if failed_connections > 50:
            if threat_level != 'HIGH':
                threat_level = 'MEDIUM'
            threats.append(f'High number of failed connections: {failed_connections}')
        
        return {
            'threat_level': threat_level,
            'identified_threats': threats,
            'risk_score': self._calculate_network_risk_score(analysis)
        }
        
    def _calculate_network_risk_score(self, analysis):
        """Calculate network risk score (0-100)"""
        score = 0
        
        # Suspicious activities weight: 40%
        suspicious_count = len(analysis['suspicious_activities'])
        score += min(suspicious_count * 2, 40)
        
        # Port scan weight: 25%
        port_scan_count = len(analysis['port_analysis']['port_scans'])
        score += min(port_scan_count * 5, 25)
        
        # Failed connections weight: 20%
        failed_count = len(analysis['connection_patterns']['failed_connections'])
        score += min(failed_count / 10, 20)
        
        # Security concerns weight: 15%
        security_concerns = len(analysis['iot_protocol_analysis']['security_concerns'])
        score += min(security_concerns * 3, 15)
        
        return min(score, 100)
