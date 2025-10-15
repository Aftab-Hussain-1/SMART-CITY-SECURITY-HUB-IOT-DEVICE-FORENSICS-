
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import json
import base64
from io import BytesIO
import logging

class VisualizationService:
    def __init__(self, db_manager):
        self.db_manager = db_manager
        plt.style.use('seaborn-v0_8')
        sns.set_palette("husl")
        
    def generate_security_dashboard_data(self):
        """Generate data for security dashboard visualizations"""
        try:
            # Get data for the last 24 hours
            last_24h = datetime.now() - timedelta(hours=24)
            
            logs = self.db_manager.execute_query(
                """
                SELECT l.*, d.device_name, d.device_type 
                FROM logs l 
                LEFT JOIN devices d ON l.device_id = d.id 
                WHERE l.timestamp >= ?
                ORDER BY l.timestamp DESC
                """,
                (last_24h,),
                fetch=True
            )
            
            if not logs:
                return self._empty_dashboard_data()
                
            df = pd.DataFrame(logs)
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            
            dashboard_data = {
                'severity_distribution': self._get_severity_distribution(df),
                'attack_types_timeline': self._get_attack_timeline(df),
                'device_activity_heatmap': self._get_device_activity_heatmap(df),
                'anomaly_detection_chart': self._get_anomaly_chart(df),
                'security_trends': self._get_security_trends(df),
                'top_affected_devices': self._get_top_affected_devices(df),
                'hourly_log_distribution': self._get_hourly_distribution(df),
                'severity_by_device_type': self._get_severity_by_device_type(df)
            }
            
            return dashboard_data
            
        except Exception as e:
            logging.error(f"Error generating dashboard data: {e}")
            return self._empty_dashboard_data()
            
    def _get_severity_distribution(self, df):
        """Get severity distribution data"""
        severity_counts = df['severity'].value_counts().to_dict()
        
        return {
            'labels': list(severity_counts.keys()),
            'data': list(severity_counts.values()),
            'colors': ['#ff4444', '#ffaa00', '#44ff44'],
            'chart_type': 'pie'
        }
        
    def _get_attack_timeline(self, df):
        """Get attack types timeline"""
        attack_logs = df[df['attack_type'].notna()].copy()
        
        if attack_logs.empty:
            return {'labels': [], 'datasets': []}
            
        # Group by hour and attack type
        attack_logs['hour'] = attack_logs['timestamp'].dt.floor('H')
        timeline_data = attack_logs.groupby(['hour', 'attack_type']).size().unstack(fill_value=0)
        
        datasets = []
        colors = ['#ff6384', '#36a2eb', '#cc65fe', '#ffce56', '#4bc0c0']
        
        for i, attack_type in enumerate(timeline_data.columns):
            datasets.append({
                'label': attack_type,
                'data': timeline_data[attack_type].tolist(),
                'borderColor': colors[i % len(colors)],
                'backgroundColor': colors[i % len(colors)] + '20',
                'fill': False
            })
            
        return {
            'labels': [dt.strftime('%H:%M') for dt in timeline_data.index],
            'datasets': datasets,
            'chart_type': 'line'
        }
        
    def _get_device_activity_heatmap(self, df):
        """Generate device activity heatmap data"""
        # Create hour vs device matrix
        df['hour'] = df['timestamp'].dt.hour
        activity_matrix = df.groupby(['device_name', 'hour']).size().unstack(fill_value=0)
        
        return {
            'data': activity_matrix.values.tolist(),
            'labels': {
                'x': list(range(24)),  # Hours 0-23
                'y': activity_matrix.index.tolist()  # Device names
            },
            'chart_type': 'heatmap'
        }
        
    def _get_anomaly_chart(self, df):
        """Get anomaly detection chart data"""
        df['hour'] = df['timestamp'].dt.floor('H')
        
        hourly_stats = df.groupby('hour').agg({
            'id': 'count',
            'is_anomaly': 'sum'
        }).rename(columns={'id': 'total_logs', 'is_anomaly': 'anomalies'})
        
        return {
            'labels': [dt.strftime('%H:%M') for dt in hourly_stats.index],
            'datasets': [
                {
                    'label': 'Total Logs',
                    'data': hourly_stats['total_logs'].tolist(),
                    'backgroundColor': '#36a2eb',
                    'yAxisID': 'y'
                },
                {
                    'label': 'Anomalies',
                    'data': hourly_stats['anomalies'].tolist(),
                    'backgroundColor': '#ff6384',
                    'type': 'line',
                    'yAxisID': 'y1'
                }
            ],
            'chart_type': 'mixed'
        }
        
    def _get_security_trends(self, df):
        """Get security trends over time"""
        df['date'] = df['timestamp'].dt.date
        
        daily_trends = df.groupby('date').agg({
            'severity': lambda x: (x == 'high').sum(),
            'attack_type': lambda x: x.notna().sum(),
            'is_anomaly': 'sum'
        }).rename(columns={
            'severity': 'high_severity_events',
            'attack_type': 'attack_events',
            'is_anomaly': 'anomalies'
        })
        
        return {
            'labels': [d.strftime('%Y-%m-%d') for d in daily_trends.index],
            'datasets': [
                {
                    'label': 'High Severity Events',
                    'data': daily_trends['high_severity_events'].tolist(),
                    'borderColor': '#ff4444',
                    'backgroundColor': '#ff444420'
                },
                {
                    'label': 'Attack Events',
                    'data': daily_trends['attack_events'].tolist(),
                    'borderColor': '#ff8800',
                    'backgroundColor': '#ff880020'
                },
                {
                    'label': 'Anomalies',
                    'data': daily_trends['anomalies'].tolist(),
                    'borderColor': '#8844ff',
                    'backgroundColor': '#8844ff20'
                }
            ],
            'chart_type': 'line'
        }
        
    def _get_top_affected_devices(self, df):
        """Get top affected devices"""
        device_incidents = df[df['severity'] == 'high'].groupby('device_name').size().sort_values(ascending=False).head(10)
        
        return {
            'labels': device_incidents.index.tolist(),
            'data': device_incidents.values.tolist(),
            'backgroundColor': ['#ff6384', '#36a2eb', '#cc65fe', '#ffce56', '#4bc0c0'] * 2,
            'chart_type': 'bar'
        }
        
    def _get_hourly_distribution(self, df):
        """Get hourly log distribution"""
        hourly_dist = df.groupby(df['timestamp'].dt.hour).size()
        
        return {
            'labels': [f"{h:02d}:00" for h in range(24)],
            'data': [hourly_dist.get(h, 0) for h in range(24)],
            'backgroundColor': '#36a2eb',
            'chart_type': 'bar'
        }
        
    def _get_severity_by_device_type(self, df):
        """Get severity distribution by device type"""
        severity_by_type = df.groupby(['device_type', 'severity']).size().unstack(fill_value=0)
        
        datasets = []
        colors = {'high': '#ff4444', 'medium': '#ffaa00', 'low': '#44ff44'}
        
        for severity in ['high', 'medium', 'low']:
            if severity in severity_by_type.columns:
                datasets.append({
                    'label': severity.title(),
                    'data': severity_by_type[severity].tolist(),
                    'backgroundColor': colors[severity]
                })
                
        return {
            'labels': severity_by_type.index.tolist(),
            'datasets': datasets,
            'chart_type': 'stacked_bar'
        }
        
    def _empty_dashboard_data(self):
        """Return empty dashboard data structure"""
        return {
            'severity_distribution': {'labels': [], 'data': [], 'colors': []},
            'attack_types_timeline': {'labels': [], 'datasets': []},
            'device_activity_heatmap': {'data': [], 'labels': {'x': [], 'y': []}},
            'anomaly_detection_chart': {'labels': [], 'datasets': []},
            'security_trends': {'labels': [], 'datasets': []},
            'top_affected_devices': {'labels': [], 'data': []},
            'hourly_log_distribution': {'labels': [], 'data': []},
            'severity_by_device_type': {'labels': [], 'datasets': []}
        }
        
    def generate_forensic_report_charts(self, time_period='7d'):
        """Generate charts for forensic reports"""
        try:
            if time_period == '24h':
                time_delta = timedelta(hours=24)
            elif time_period == '7d':
                time_delta = timedelta(days=7)
            elif time_period == '30d':
                time_delta = timedelta(days=30)
            else:
                time_delta = timedelta(days=7)
                
            start_time = datetime.now() - time_delta
            
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
            
            charts = {}
            
            if logs:
                df = pd.DataFrame(logs)
                df['timestamp'] = pd.to_datetime(df['timestamp'])
                
                # Generate various charts
                charts['security_overview'] = self._create_security_overview_chart(df)
                charts['attack_analysis'] = self._create_attack_analysis_chart(df)
                charts['device_risk_assessment'] = self._create_device_risk_chart(df)
                charts['temporal_analysis'] = self._create_temporal_analysis_chart(df)
                
            return charts
            
        except Exception as e:
            logging.error(f"Error generating forensic report charts: {e}")
            return {}
            
    def _create_security_overview_chart(self, df):
        """Create security overview chart"""
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 10))
        
        # Severity distribution
        severity_counts = df['severity'].value_counts()
        ax1.pie(severity_counts.values, labels=severity_counts.index, autopct='%1.1f%%')
        ax1.set_title('Security Event Severity Distribution')
        
        # Attack types
        if 'attack_type' in df.columns:
            attack_counts = df[df['attack_type'].notna()]['attack_type'].value_counts().head(5)
            ax2.bar(attack_counts.index, attack_counts.values)   
            ax2.set_title('Top 5 Attack Types')
            ax2.tick_params(axis='x', rotation=45)
        
        # Timeline
        df['date'] = df['timestamp'].dt.date
        daily_counts = df.groupby('date').size()
        ax3.plot(daily_counts.index, daily_counts.values)
        ax3.set_title('Daily Security Events')
        ax3.tick_params(axis='x', rotation=45)
        
        # Anomalies
        anomaly_counts = df.groupby('date')['is_anomaly'].sum()
        ax4.bar(anomaly_counts.index, anomaly_counts.values, color='red', alpha=0.7)
        ax4.set_title('Daily Anomalies Detected')
        ax4.tick_params(axis='x', rotation=45)
        
        plt.tight_layout()
        return self._fig_to_base64(fig)
        
    def _create_attack_analysis_chart(self, df):
        """Create attack analysis chart"""
        attack_logs = df[df['attack_type'].notna()]
        
        if attack_logs.empty:
            return None
            
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        
        # Attack types by severity
        attack_severity = attack_logs.groupby(['attack_type', 'severity']).size().unstack(fill_value=0)
        attack_severity.plot(kind='bar', stacked=True, ax=ax1)
        ax1.set_title('Attack Types by Severity')
        ax1.tick_params(axis='x', rotation=45)
        
        # Attack timeline
        attack_logs['hour'] = attack_logs['timestamp'].dt.hour
        hourly_attacks = attack_logs.groupby('hour').size()
        ax2.plot(hourly_attacks.index, hourly_attacks.values, marker='o')
        ax2.set_title('Attack Distribution by Hour')
        ax2.set_xlabel('Hour of Day')
        ax2.set_ylabel('Number of Attacks')
        
        plt.tight_layout()
        return self._fig_to_base64(fig)
        
    def _create_device_risk_chart(self, df):
        """Create device risk assessment chart"""
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        
        # Device activity
        device_counts = df['device_name'].value_counts().head(10)
        ax1.barh(device_counts.index, device_counts.values)
        ax1.set_title('Top 10 Most Active Devices')
        
        # High severity events by device
        high_severity = df[df['severity'] == 'high']
        if not high_severity.empty:
            device_severity = high_severity['device_name'].value_counts().head(10)
            ax2.barh(device_severity.index, device_severity.values, color='red', alpha=0.7)
            ax2.set_title('Devices with Most High Severity Events')
        
        plt.tight_layout()
        return self._fig_to_base64(fig)
        
    def _create_temporal_analysis_chart(self, df):
        """Create temporal analysis chart"""
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 10))
        
        # Hourly distribution
        hourly_dist = df.groupby(df['timestamp'].dt.hour).size()
        ax1.bar(hourly_dist.index, hourly_dist.values)
        ax1.set_title('Hourly Event Distribution')
        ax1.set_xlabel('Hour of Day')
        
        # Daily distribution
        daily_dist = df.groupby(df['timestamp'].dt.dayofweek).size()
        days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
        ax2.bar([days[i] for i in daily_dist.index], daily_dist.values)
        ax2.set_title('Daily Event Distribution')
        
        # Severity over time
        df['date'] = df['timestamp'].dt.date
        severity_timeline = df.groupby(['date', 'severity']).size().unstack(fill_value=0)
        severity_timeline.plot(ax=ax3)
        ax3.set_title('Severity Timeline')
        ax3.tick_params(axis='x', rotation=45)
        
        # Anomaly rate over time
        daily_logs = df.groupby('date').size()
        daily_anomalies = df.groupby('date')['is_anomaly'].sum()
        anomaly_rate = (daily_anomalies / daily_logs * 100).fillna(0)
        ax4.plot(anomaly_rate.index, anomaly_rate.values, color='red', marker='o')
        ax4.set_title('Daily Anomaly Rate (%)')
        ax4.tick_params(axis='x', rotation=45)
        
        plt.tight_layout()
        return self._fig_to_base64(fig)
        
    def _fig_to_base64(self, fig):
        """Convert matplotlib figure to base64 string"""
        buffer = BytesIO()
        fig.savefig(buffer, format='png', dpi=150, bbox_inches='tight')
        buffer.seek(0)
        image_base64 = base64.b64encode(buffer.getvalue()).decode()
        plt.close(fig)
        return f"data:image/png;base64,{image_base64}"
        
    def export_chart_data(self, chart_data, filename):
        """Export chart data to JSON file"""
        try:
            with open(filename, 'w') as f:
                json.dump(chart_data, f, indent=2, default=str)
            return True
        except Exception as e:
            logging.error(f"Error exporting chart data: {e}")
            return False
