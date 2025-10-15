
import json
import os
from datetime import datetime, timedelta
from jinja2 import Template
import logging
from .ml_analyzer import MLAnalyzer
from .visualization_service import VisualizationService

class ForensicReporter:
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.ml_analyzer = MLAnalyzer(db_manager)
        self.visualization_service = VisualizationService(db_manager)
        
    def generate_comprehensive_report(self, time_period='7d', output_format='html'):
        """Generate comprehensive forensic report"""
        try:
            report_data = self._collect_report_data(time_period)
            
            if output_format == 'html':
                return self._generate_html_report(report_data)
            elif output_format == 'json':
                return self._generate_json_report(report_data)
            elif output_format == 'txt':
                return self._generate_text_report(report_data)
            else:
                return self._generate_html_report(report_data)
                
        except Exception as e:
            logging.error(f"Error generating forensic report: {e}")
            return None
            
    def _collect_report_data(self, time_period):
        """Collect all data needed for the report"""
        if time_period == '24h':
            time_delta = timedelta(hours=24)
        elif time_period == '7d':
            time_delta = timedelta(days=7)
        elif time_period == '30d':
            time_delta = timedelta(days=30)
        else:
            time_delta = timedelta(days=7)
            
        start_time = datetime.now() - time_delta
        end_time = datetime.now()
        
        # Collect basic statistics
        total_logs = self.db_manager.execute_query(
            "SELECT COUNT(*) as count FROM logs WHERE timestamp >= ?",
            (start_time,),
            fetch=True
        )
        
        total_devices = self.db_manager.execute_query(
            "SELECT COUNT(*) as count FROM devices WHERE status = 'active'",
            fetch=True
        )
        
        total_alerts = self.db_manager.execute_query(
            "SELECT COUNT(*) as count FROM alerts WHERE created_at >= ?",
            (start_time,),
            fetch=True
        )
        
        # Get detailed logs
        logs = self.db_manager.execute_query(
            """
            SELECT l.*, d.device_name, d.device_type, d.location
            FROM logs l
            LEFT JOIN devices d ON l.device_id = d.id
            WHERE l.timestamp >= ?
            ORDER BY l.timestamp DESC
            """,
            (start_time,),
            fetch=True
        )
        
        # Get alerts
        alerts = self.db_manager.execute_query(
            """
            SELECT a.*, d.device_name
            FROM alerts a
            LEFT JOIN devices d ON a.device_id = d.id
            WHERE a.created_at >= ?
            ORDER BY a.created_at DESC
            """,
            (start_time,),
            fetch=True
        )
        
        # Get devices
        devices = self.db_manager.get_devices()
        
        # Analyze patterns
        attack_patterns = self.ml_analyzer.analyze_attack_patterns()
        
        # Generate insights
        insights = self.ml_analyzer.generate_insights()
        
        # Security analysis
        security_analysis = self._perform_security_analysis(logs, alerts)
        
        # Device risk assessment
        device_risks = self._assess_device_risks(devices)
        
        # Temporal analysis
        temporal_analysis = self._perform_temporal_analysis(logs)
        
        # Generate visualizations
        charts = self.visualization_service.generate_forensic_report_charts(time_period)
        
        return {
            'report_metadata': {
                'generated_at': end_time.isoformat(),
                'time_period': time_period,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'report_id': f"FR_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            },
            'executive_summary': {
                'total_logs': total_logs[0]['count'] if total_logs else 0,
                'total_devices': total_devices[0]['count'] if total_devices else 0,
                'total_alerts': total_alerts[0]['count'] if total_alerts else 0,
                'high_severity_events': len([l for l in logs if l.get('severity') == 'high']),
                'anomalies_detected': len([l for l in logs if l.get('is_anomaly')]),
                'attack_events': len([l for l in logs if l.get('attack_type')])
            },
            'security_analysis': security_analysis,
            'attack_patterns': attack_patterns,
            'device_analysis': {
                'devices': devices,
                'risk_assessment': device_risks
            },
            'temporal_analysis': temporal_analysis,
            'alerts_analysis': {
                'alerts': alerts[:50],  # Top 50 alerts
                'alert_statistics': self._analyze_alerts(alerts)
            },
            'ml_insights': insights,
            'recommendations': self._generate_recommendations(security_analysis, insights),
            'detailed_logs': logs[:100],  # Top 100 logs
            'charts': charts
        }
        
    def _perform_security_analysis(self, logs, alerts):
        """Perform detailed security analysis"""
        analysis = {
            'severity_breakdown': {'high': 0, 'medium': 0, 'low': 0},
            'attack_type_distribution': {},
            'affected_devices': set(),
            'geographic_analysis': {},
            'protocol_analysis': {},
            'source_ip_analysis': {},
            'security_score': 0
        }
        
        for log in logs:
            # Severity analysis
            severity = log.get('severity', 'low')
            analysis['severity_breakdown'][severity] += 1
            
            # Attack type analysis
            attack_type = log.get('attack_type')
            if attack_type:
                analysis['attack_type_distribution'][attack_type] = \
                    analysis['attack_type_distribution'].get(attack_type, 0) + 1
                analysis['affected_devices'].add(log.get('device_name', 'Unknown'))
            
            # Geographic analysis
            location = log.get('location')
            if location:
                analysis['geographic_analysis'][location] = \
                    analysis['geographic_analysis'].get(location, 0) + 1
            
            # Protocol analysis
            protocol = log.get('protocol')
            if protocol:
                analysis['protocol_analysis'][protocol] = \
                    analysis['protocol_analysis'].get(protocol, 0) + 1
            
            # Source IP analysis
            source_ip = log.get('source_ip')
            if source_ip:
                analysis['source_ip_analysis'][source_ip] = \
                    analysis['source_ip_analysis'].get(source_ip, 0) + 1
        
        # Convert set to list for JSON serialization
        analysis['affected_devices'] = list(analysis['affected_devices'])
        
        # Calculate security score (0-100)
        total_logs = len(logs)
        if total_logs > 0:
            high_severity_ratio = analysis['severity_breakdown']['high'] / total_logs
            attack_ratio = len([l for l in logs if l.get('attack_type')]) / total_logs
            anomaly_ratio = len([l for l in logs if l.get('is_anomaly')]) / total_logs
            
            # Lower score means worse security posture
            analysis['security_score'] = max(0, 100 - (
                high_severity_ratio * 40 + 
                attack_ratio * 35 + 
                anomaly_ratio * 25
            ) * 100)
        
        return analysis
        
    def _assess_device_risks(self, devices):
        """Assess risk levels for all devices"""
        risk_assessment = []
        
        for device in devices:
            risk_score = self.ml_analyzer.predict_risk_score(device['id'])
            
            risk_level = 'LOW'
            if risk_score > 7:
                risk_level = 'HIGH' 
            elif risk_score > 4:
                risk_level = 'MEDIUM'
            
            risk_assessment.append({
                'device_id': device['id'],
                'device_name': device['device_name'],
                'device_type': device['device_type'],
                'location': device.get('location', 'Unknown'),
                'risk_score': risk_score,
                'risk_level': risk_level,
                'recommendations': self._get_device_recommendations(device, risk_score)
            })
        
        return sorted(risk_assessment, key=lambda x: x['risk_score'], reverse=True)
        
    def _get_device_recommendations(self, device, risk_score):
        """Get security recommendations for a device"""
        recommendations = []
        
        if risk_score > 7:
            recommendations.extend([
                "Immediate security review required",
                "Consider temporarily isolating device",
                "Update security patches immediately",
                "Review access logs and permissions"
            ])
        elif risk_score > 4:
            recommendations.extend([
                "Schedule security review within 24 hours",
                "Monitor device activity closely",
                "Check for available security updates"
            ])
        else:
            recommendations.extend([
                "Continue regular monitoring",
                "Maintain update schedule"
            ])
        
        # Device type specific recommendations
        device_type = device.get('device_type', '').lower()
        if 'camera' in device_type:
            recommendations.append("Review camera access logs for unauthorized viewing")
        elif 'sensor' in device_type:
            recommendations.append("Validate sensor data integrity")
        elif 'traffic' in device_type:
            recommendations.append("Monitor for traffic manipulation attempts")
            
        return recommendations
        
    def _perform_temporal_analysis(self, logs):
        """Perform temporal analysis of security events"""
        analysis = {
            'hourly_distribution': [0] * 24,
            'daily_distribution': [0] * 7,
            'peak_hours': [],
            'quiet_periods': [],
            'anomaly_periods': []
        }
        
        for log in logs:
            timestamp = datetime.fromisoformat(log['timestamp'].replace('Z', '+00:00'))
            hour = timestamp.hour
            day_of_week = timestamp.weekday()
            
            analysis['hourly_distribution'][hour] += 1
            analysis['daily_distribution'][day_of_week] += 1
        
        # Find peak hours (top 3)
        hour_counts = list(enumerate(analysis['hourly_distribution']))
        peak_hours = sorted(hour_counts, key=lambda x: x[1], reverse=True)[:3]
        analysis['peak_hours'] = [{'hour': h, 'count': c} for h, c in peak_hours]
        
        # Find quiet periods (bottom 3)
        quiet_hours = sorted(hour_counts, key=lambda x: x[1])[:3]
        analysis['quiet_periods'] = [{'hour': h, 'count': c} for h, c in quiet_hours]
        
        return analysis
        
    def _analyze_alerts(self, alerts):
        """Analyze alert patterns"""
        stats = {
            'by_severity': {},
            'by_type': {},
            'by_status': {},
            'resolution_times': [],
            'escalation_rate': 0
        }
        
        for alert in alerts:
            # Severity distribution
            severity = alert['severity']
            stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1
            
            # Type distribution
            alert_type = alert['alert_type']
            stats['by_type'][alert_type] = stats['by_type'].get(alert_type, 0) + 1
            
            # Status distribution
            status = alert['status']
            stats['by_status'][status] = stats['by_status'].get(status, 0) + 1
        
        return stats
        
    def _generate_recommendations(self, security_analysis, insights):
        """Generate security recommendations"""
        recommendations = []
        
        # Based on security score
        security_score = security_analysis.get('security_score', 0)
        if security_score < 50:
            recommendations.append({
                'priority': 'CRITICAL',
                'category': 'Overall Security',
                'recommendation': 'Immediate comprehensive security review required',
                'details': 'Security score is critically low. Consider emergency response procedures.'
            })
        elif security_score < 70:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Overall Security', 
                'recommendation': 'Enhanced monitoring and security measures needed',
                'details': 'Security score indicates elevated risk. Implement additional controls.'
            })
        
        # Based on attack patterns
        attack_types = security_analysis.get('attack_type_distribution', {})
        if 'DDoS' in attack_types:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Network Security',
                'recommendation': 'Implement DDoS protection measures',
                'details': 'DDoS attacks detected. Consider rate limiting and traffic filtering.'
            })
        
        if 'Brute Force' in attack_types:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Access Control',
                'recommendation': 'Strengthen authentication mechanisms',
                'details': 'Brute force attacks detected. Implement account lockout and MFA.'
            })
        
        # Based on insights
        for insight in insights:
            if insight['type'] == 'high_risk_device':
                recommendations.append({
                    'priority': 'HIGH',
                    'category': 'Device Security',
                    'recommendation': 'Review high-risk devices immediately',
                    'details': insight['details']
                })
        
        return recommendations
        
    def _generate_html_report(self, data):
        """Generate HTML forensic report"""
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>IoT Forensic Analysis Report - {{ data.report_metadata.report_id }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .critical { background-color: #ffebee; border-left: 5px solid #f44336; }
        .high { background-color: #fff3e0; border-left: 5px solid #ff9800; }
        .medium { background-color: #f3e5f5; border-left: 5px solid #9c27b0; }
        .low { background-color: #e8f5e8; border-left: 5px solid #4caf50; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .chart { text-align: center; margin: 20px 0; }
        .recommendations { background-color: #e3f2fd; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 IoT Device Log Forensic Analysis Report</h1>
        <p>Report ID: {{ data.report_metadata.report_id }}</p>
        <p>Generated: {{ data.report_metadata.generated_at }}</p>
        <p>Period: {{ data.report_metadata.start_time }} to {{ data.report_metadata.end_time }}</p>
    </div>
    
    <div class="section">
        <h2>📊 Executive Summary</h2>
        <table>
            <tr><td><strong>Total Logs Analyzed</strong></td><td>{{ data.executive_summary.total_logs }}</td></tr>
            <tr><td><strong>Active Devices</strong></td><td>{{ data.executive_summary.total_devices }}</td></tr>
            <tr><td><strong>Security Alerts</strong></td><td>{{ data.executive_summary.total_alerts }}</td></tr>
            <tr><td><strong>High Severity Events</strong></td><td>{{ data.executive_summary.high_severity_events }}</td></tr>
            <tr><td><strong>Anomalies Detected</strong></td><td>{{ data.executive_summary.anomalies_detected }}</td></tr>
            <tr><td><strong>Attack Events</strong></td><td>{{ data.executive_summary.attack_events }}</td></tr>
        </table>
    </div>
    
    <div class="section">
        <h2>🛡️ Security Analysis</h2>
        <p><strong>Overall Security Score:</strong> {{ "%.1f"|format(data.security_analysis.security_score) }}/100</p>
        
        <h3>Severity Breakdown</h3>
        <table>
            <tr><th>Severity</th><th>Count</th><th>Percentage</th></tr>
            {% for severity, count in data.security_analysis.severity_breakdown.items() %}
            <tr class="{{ severity }}">
                <td>{{ severity.title() }}</td>
                <td>{{ count }}</td>
                <td>{{ "%.1f"|format((count / data.executive_summary.total_logs * 100) if data.executive_summary.total_logs > 0 else 0) }}%</td>
            </tr>
            {% endfor %}
        </table>
        
        {% if data.security_analysis.attack_type_distribution %}
        <h3>Attack Type Distribution</h3>
        <table>
            <tr><th>Attack Type</th><th>Count</th></tr>
            {% for attack_type, count in data.security_analysis.attack_type_distribution.items() %}
            <tr><td>{{ attack_type }}</td><td>{{ count }}</td></tr>
            {% endfor %}
        </table>
        {% endif %}
    </div>
    
    <div class="section">
        <h2>🖥️ Device Risk Assessment</h2>
        <table>
            <tr><th>Device Name</th><th>Type</th><th>Risk Score</th><th>Risk Level</th></tr>
            {% for device in data.device_analysis.risk_assessment[:10] %}
            <tr class="{{ device.risk_level.lower() }}">
                <td>{{ device.device_name }}</td>
                <td>{{ device.device_type }}</td>
                <td>{{ "%.1f"|format(device.risk_score) }}</td>
                <td>{{ device.risk_level }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
    
    <div class="section recommendations">
        <h2>💡 Security Recommendations</h2>
        {% for rec in data.recommendations %}
        <div class="section {{ rec.priority.lower() }}">
            <h3>{{ rec.category }} - {{ rec.priority }} Priority</h3>
            <p><strong>Recommendation:</strong> {{ rec.recommendation }}</p>
            <p><strong>Details:</strong> {{ rec.details }}</p>
        </div>
        {% endfor %}
    </div>
    
    <div class="section">
        <h2>🔍 ML Insights</h2>
        {% for insight in data.ml_insights %}
        <div class="section {{ insight.severity }}">
            <h3>{{ insight.type.replace('_', ' ').title() }}</h3>
            <p>{{ insight.message }}</p>
            <p><em>{{ insight.details }}</em></p>
        </div>
        {% endfor %}
    </div>
    
    <div class="section">
        <h2>📈 Recent Critical Alerts</h2>
        <table>
            <tr><th>Time</th><th>Type</th><th>Severity</th><th>Description</th><th>Device</th></tr>
            {% for alert in data.alerts_analysis.alerts[:20] %}
            <tr class="{{ alert.severity }}">
                <td>{{ alert.created_at }}</td>
                <td>{{ alert.alert_type }}</td>
                <td>{{ alert.severity }}</td>
                <td>{{ alert.description[:100] }}...</td>
                <td>{{ alert.device_name or 'Unknown' }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
    
    <div class="section">
        <h2>📋 Investigation Summary</h2>
        <p>This forensic analysis has examined {{ data.executive_summary.total_logs }} log entries from {{ data.executive_summary.total_devices }} IoT devices over the period {{ data.report_metadata.time_period }}.</p>
        
        {% if data.executive_summary.attack_events > 0 %}
        <p><strong>Security Incidents:</strong> {{ data.executive_summary.attack_events }} potential attack events were identified, requiring immediate attention.</p>
        {% endif %}
        
        {% if data.executive_summary.anomalies_detected > 0 %}
        <p><strong>Anomalies:</strong> {{ data.executive_summary.anomalies_detected }} anomalous behaviors were detected using machine learning analysis.</p>
        {% endif %}
        
        <p><strong>Overall Assessment:</strong> 
        {% if data.security_analysis.security_score >= 80 %}
        The smart city infrastructure shows good security posture with minimal threats detected.
        {% elif data.security_analysis.security_score >= 60 %}
        The infrastructure shows moderate security concerns that should be addressed promptly.
        {% else %}
        The infrastructure shows significant security vulnerabilities requiring immediate remediation.
        {% endif %}
        </p>
    </div>
    
    <div class="section">
        <p><em>Report generated by IoT Device Log Forensic System on {{ data.report_metadata.generated_at }}</em></p>
    </div>
</body>
</html>
        """
        
        template = Template(html_template)
        return template.render(data=data)
        
    def _generate_json_report(self, data):
        """Generate JSON forensic report"""
        return json.dumps(data, indent=2, default=str)
        
    def _generate_text_report(self, data):
        """Generate text forensic report"""
        report = f"""
IoT DEVICE LOG FORENSIC ANALYSIS REPORT
{'='*50}

Report ID: {data['report_metadata']['report_id']}
Generated: {data['report_metadata']['generated_at']}
Time Period: {data['report_metadata']['time_period']}

EXECUTIVE SUMMARY
{'-'*20}
Total Logs Analyzed: {data['executive_summary']['total_logs']}
Active Devices: {data['executive_summary']['total_devices']}
Security Alerts: {data['executive_summary']['total_alerts']}
High Severity Events: {data['executive_summary']['high_severity_events']}
Anomalies Detected: {data['executive_summary']['anomalies_detected']}
Attack Events: {data['executive_summary']['attack_events']}

SECURITY ANALYSIS
{'-'*20}
Overall Security Score: {data['security_analysis']['security_score']:.1f}/100

Severity Breakdown:
"""
        
        for severity, count in data['security_analysis']['severity_breakdown'].items():
            percentage = (count / data['executive_summary']['total_logs'] * 100) if data['executive_summary']['total_logs'] > 0 else 0
            report += f"  {severity.title()}: {count} ({percentage:.1f}%)\n"
        
        if data['security_analysis']['attack_type_distribution']:
            report += "\nAttack Types Detected:\n"
            for attack_type, count in data['security_analysis']['attack_type_distribution'].items():
                report += f"  {attack_type}: {count}\n"
        
        report += f"\nRECOMMENDATIONS\n{'-'*20}\n"
        for rec in data['recommendations']:
            report += f"{rec['priority']} - {rec['category']}: {rec['recommendation']}\n"
            report += f"  Details: {rec['details']}\n\n"
        
        return report
        
    def save_report(self, report_content, filename, format_type='html'):
        """Save report to file"""
        try:
            # Create reports directory if it doesn't exist
            os.makedirs('reports', exist_ok=True)
            
            filepath = os.path.join('reports', f"{filename}.{format_type}")
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(report_content)
                
            logging.info(f"Report saved to {filepath}")
            return filepath
            
        except Exception as e:
            logging.error(f"Error saving report: {e}")
            return None
