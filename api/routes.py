from flask import Blueprint, jsonify, request
from datetime import datetime
import json

api_bp = Blueprint('api', __name__)

@api_bp.route('/logs', methods=['GET'])
def get_logs():
    """Get device logs with optional filtering"""
    device = request.args.get('device')
    severity = request.args.get('severity')

    # Sample logs data
    sample_logs = [
        {
            "id": 1,
            "timestamp": "2025-01-26T18:00:00Z",
            "device": "Traffic Camera",
            "severity": "high",
            "message": "Unauthorized access attempt detected",
            "attack_type": "Brute Force"
        },
        {
            "id": 2,
            "timestamp": "2025-01-26T17:30:00Z",
            "device": "Environmental Sensor",
            "severity": "medium",
            "message": "Unusual data pattern detected",
            "attack_type": "Data Exfiltration"
        },
        {
            "id": 3,
            "timestamp": "2025-01-26T17:00:00Z",
            "device": "Smart Streetlight",
            "severity": "high",
            "message": "DDoS attack detected",
            "attack_type": "DDoS"
        }
    ]

    return jsonify(sample_logs)

@api_bp.route('/devices', methods=['GET'])
def get_devices():
    """Get list of monitored devices"""
    devices = [
        {"id": 1, "name": "Traffic Camera", "status": "online"},
        {"id": 2, "name": "Environmental Sensor", "status": "online"},
        {"id": 3, "name": "Smart Streetlight", "status": "offline"},
        {"id": 4, "name": "Surveillance Camera", "status": "online"},
        {"id": 5, "name": "Traffic Signal", "status": "online"}
    ]
    return jsonify(devices)

@api_bp.route('/analytics', methods=['GET'])
def get_analytics():
    """Get analytics data"""
    analytics = {
        "total_logs": 156,
        "anomalies": 23,
        "devices_monitored": 5,
        "high_severity_events": 8
    }
    return jsonify(analytics)
from flask import Blueprint, jsonify, request
from datetime import datetime
import json

api_bp = Blueprint('api', __name__)

@api_bp.route('/logs', methods=['GET'])
def get_logs():
    """Get device logs with optional filtering - Real authentication events only"""
    from app import db_manager
    
    device = request.args.get('device')
    severity = request.args.get('severity')
    limit = int(request.args.get('limit', 100))
    auth_only = request.args.get('auth_only', 'true').lower() == 'true'
    
    try:
        # Get logs, filtering for authentication events if requested
        if auth_only:
            query = """
                SELECT l.*, d.device_name, d.device_type, d.location
                FROM logs l
                LEFT JOIN devices d ON l.device_id = d.id
                WHERE l.protocol = 'AUTH' OR l.message LIKE '%login%' OR l.message LIKE '%logout%' OR l.message LIKE '%authentication%'
            """
        else:
            query = """
                SELECT l.*, d.device_name, d.device_type, d.location
                FROM logs l
                LEFT JOIN devices d ON l.device_id = d.id
            """
        
        conditions = []
        params = []
        
        if device:
            conditions.append("d.device_name = ?")
            params.append(device)
            
        if severity:
            conditions.append("l.severity = ?")
            params.append(severity)
        
        if conditions:
            if auth_only:
                query += " AND " + " AND ".join(conditions)
            else:
                query += " WHERE " + " AND ".join(conditions)
        
        query += " ORDER BY l.timestamp DESC LIMIT ?"
        params.append(limit)
        
        logs = db_manager.execute_query(query, params, fetch=True)
        
        return jsonify({
            'status': 'success',
            'data': logs if logs else [],
            'count': len(logs) if logs else 0,
            'filter_applied': 'authentication_events_only' if auth_only else 'all_logs'
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api_bp.route('/devices', methods=['GET'])
def get_devices():
    """Get list of monitored devices"""
    from app import db_manager
    
    try:
        devices = db_manager.get_devices()
        return jsonify({
            'status': 'success',
            'data': devices,
            'count': len(devices) if devices else 0
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api_bp.route('/analytics', methods=['GET'])
def get_analytics():
    """Get analytics data"""
    from app import db_manager, ml_analyzer
    
    try:
        # Get basic counts
        logs = db_manager.get_logs(limit=1000)
        devices = db_manager.get_devices()
        alerts = db_manager.get_alerts()
        
        # Generate ML insights
        insights = ml_analyzer.generate_insights()
        
        # Calculate analytics
        analytics = {
            "total_logs": len(logs) if logs else 0,
            "total_devices": len(devices) if devices else 0,
            "total_alerts": len(alerts) if alerts else 0,
            "active_alerts": len([a for a in alerts if a['status'] == 'open']) if alerts else 0,
            "high_severity_events": len([l for l in logs if l.get('severity') == 'high']) if logs else 0,
            "anomalies_detected": len([l for l in logs if l.get('is_anomaly')]) if logs else 0,
            "attack_events": len([l for l in logs if l.get('attack_type')]) if logs else 0,
            "ml_insights": insights
        }
        
        return jsonify({
            'status': 'success',
            'data': analytics
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api_bp.route('/alerts', methods=['GET'])
def get_alerts():
    """Get security alerts"""
    from app import db_manager
    
    status = request.args.get('status')
    severity = request.args.get('severity')
    
    try:
        alerts = db_manager.get_alerts(status=status)
        
        if severity:
            alerts = [alert for alert in alerts if alert.get('severity') == severity]
        
        return jsonify({
            'status': 'success',
            'data': alerts,
            'count': len(alerts) if alerts else 0
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api_bp.route('/real-time/monitor', methods=['GET'])
def get_real_time_monitoring():
    """Get real-time monitoring data"""
    from app import db_manager
    from services.real_time_monitor import RealTimeMonitor
    
    try:
        monitor = RealTimeMonitor(db_manager)
        stats = monitor.get_real_time_stats()
        status = monitor.get_monitoring_status()
        
        return jsonify({
            'status': 'success',
            'data': {
                'monitoring_status': status,
                'real_time_stats': stats
            }
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api_bp.route('/real-time/start', methods=['POST'])
def start_real_time_monitoring():
    """Start real-time monitoring"""
    from app import db_manager
    from services.real_time_monitor import RealTimeMonitor
    
    try:
        monitor = RealTimeMonitor(db_manager)
        monitor.start_monitoring()
        
        return jsonify({
            'status': 'success',
            'message': 'Real-time monitoring started'
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api_bp.route('/real-time/stop', methods=['POST'])
def stop_real_time_monitoring():
    """Stop real-time monitoring"""
    from app import db_manager
    from services.real_time_monitor import RealTimeMonitor
    
    try:
        monitor = RealTimeMonitor(db_manager)
        monitor.stop_monitoring()
        
        return jsonify({
            'status': 'success',
            'message': 'Real-time monitoring stopped'
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api_bp.route('/visualization/dashboard', methods=['GET'])
def get_dashboard_visualization():
    """Get dashboard visualization data"""
    from app import db_manager
    from services.visualization_service import VisualizationService
    
    try:
        viz_service = VisualizationService(db_manager)
        dashboard_data = viz_service.generate_security_dashboard_data()
        
        return jsonify({
            'status': 'success',
            'data': dashboard_data
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api_bp.route('/network/analysis', methods=['GET'])
def get_network_analysis():
    """Get network traffic analysis"""
    from app import db_manager
    from services.network_analyzer import NetworkAnalyzer
    
    time_period = request.args.get('time_period', '24h')
    
    try:
        network_analyzer = NetworkAnalyzer(db_manager)
        analysis = network_analyzer.analyze_network_traffic(time_period)
        
        return jsonify({
            'status': 'success',
            'data': analysis
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api_bp.route('/reports/forensic', methods=['POST'])
def generate_forensic_report():
    """Generate comprehensive forensic report"""
    from app import db_manager
    from services.forensic_reporter import ForensicReporter
    
    data = request.get_json()
    time_period = data.get('time_period', '7d')
    output_format = data.get('format', 'html')
    
    try:
        reporter = ForensicReporter(db_manager)
        report = reporter.generate_comprehensive_report(time_period, output_format)
        
        if report:
            # Save report
            report_id = f"FR_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            filename = reporter.save_report(report, report_id, output_format)
            
            return jsonify({
                'status': 'success',
                'data': {
                    'report_id': report_id,
                    'filename': filename,
                    'format': output_format,
                    'generated_at': datetime.now().isoformat()
                }
            })
        else:
            return jsonify({'status': 'error', 'message': 'Failed to generate report'}), 500
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api_bp.route('/anomalies/detect', methods=['POST'])
def detect_anomalies():
    """Detect anomalies in recent logs"""
    from app import db_manager, ml_analyzer
    
    data = request.get_json()
    limit = data.get('limit', 100)
    
    try:
        logs = db_manager.get_logs(limit=limit)
        anomalies = ml_analyzer.detect_anomalies(logs)
        
        return jsonify({
            'status': 'success',
            'data': {
                'anomalies': anomalies,
                'total_logs_analyzed': len(logs),
                'anomalies_count': len(anomalies)
            }
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api_bp.route('/ml/train', methods=['POST'])
def train_ml_model():
    """Train the ML anomaly detection model"""
    from app import db_manager, ml_analyzer
    
    try:
        success = ml_analyzer.train_anomaly_detector()
        
        if success:
            return jsonify({
                'status': 'success',
                'message': 'ML model trained successfully'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to train ML model'
            }), 500
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api_bp.route('/security/score/<int:device_id>', methods=['GET'])
def get_device_security_score():
    """Get security risk score for a specific device"""
    from app import db_manager, ml_analyzer
    
    try:
        risk_score = ml_analyzer.predict_risk_score(device_id)
        
        # Get device details
        device = db_manager.execute_query(
            "SELECT * FROM devices WHERE id = ?",
            (device_id,),
            fetch=True
        )
        
        if device:
            device_info = device[0]
            risk_level = 'LOW'
            if risk_score > 7:
                risk_level = 'HIGH'
            elif risk_score > 4:
                risk_level = 'MEDIUM'
            
            return jsonify({
                'status': 'success',
                'data': {
                    'device_id': device_id,
                    'device_name': device_info['device_name'],
                    'risk_score': risk_score,
                    'risk_level': risk_level,
                    'max_score': 10.0
                }
            })
        else:
            return jsonify({'status': 'error', 'message': 'Device not found'}), 404
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api_bp.route('/logs/correlation', methods=['GET'])
def get_log_correlation():
    """Get correlated logs for forensic analysis"""
    from app import db_manager
    
    time_window = int(request.args.get('time_window', 300))  # 5 minutes
    event_type = request.args.get('event_type')
    
    try:
        # Get logs within time window
        logs = db_manager.execute_query(
            """
            SELECT l.*, d.device_name, d.device_type
            FROM logs l
            LEFT JOIN devices d ON l.device_id = d.id
            WHERE l.timestamp >= datetime('now', '-{} seconds')
            ORDER BY l.timestamp DESC
            """.format(time_window),
            fetch=True
        )
        
        # Perform correlation analysis
        correlations = []
        if logs:
            # Group by device and time proximity
            device_groups = {}
            for log in logs:
                device_id = log['device_id']
                if device_id not in device_groups:
                    device_groups[device_id] = []
                device_groups[device_id].append(log)
            
            # Find correlations
            for device_id, device_logs in device_groups.items():
                if len(device_logs) > 1:
                    correlations.append({
                        'device_id': device_id,
                        'device_name': device_logs[0]['device_name'],
                        'correlated_events': len(device_logs),
                        'time_span': f"{time_window} seconds",
                        'events': device_logs[:10]  # Limit for response size
                    })
        
        return jsonify({
            'status': 'success',
            'data': {
                'correlations': correlations,
                'total_logs_analyzed': len(logs),
                'time_window_seconds': time_window
            }
        })
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api_bp.route('/health', methods=['GET'])
def health_check():
    """Enhanced health check endpoint"""
    from app import db_manager
    
    try:
        # Check database connection
        db_status = db_manager.check_connection()
        
        # Check recent activity
        recent_logs = db_manager.execute_query(
            "SELECT COUNT(*) as count FROM logs WHERE timestamp >= datetime('now', '-1 hour')",
            fetch=True
        )
        
        recent_log_count = recent_logs[0]['count'] if recent_logs else 0
        
        status = {
            'status': 'healthy',
            'database': db_status,
            'recent_activity': {
                'logs_last_hour': recent_log_count
            },
            'timestamp': datetime.now().isoformat(),
            'version': '1.0.0',
            'features': [
                'real_time_monitoring',
                'ml_anomaly_detection',
                'network_analysis',
                'forensic_reporting',
                'visualization'
            ]
        }
        
        return jsonify(status)
        
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500
