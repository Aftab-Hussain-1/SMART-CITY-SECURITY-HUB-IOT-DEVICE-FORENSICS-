
from flask import Flask, jsonify, request, render_template_string, send_from_directory
from flask_cors import CORS
from database.db_manager import DatabaseManager
from services.log_processor import LogProcessor
from services.ml_analyzer import MLAnalyzer
from services.alert_system import AlertSystem
from services.real_time_monitor import RealTimeMonitor
from services.visualization_service import VisualizationService
from services.forensic_reporter import ForensicReporter
from services.network_analyzer import NetworkAnalyzer
from services.camera_service import CameraService
from services.device_auth import DeviceAuthService
from api.routes import api_bp
import os
import sys
import argparse
import logging

app = Flask(__name__)
CORS(app)

# Initialize services
db_manager = DatabaseManager()
log_processor = LogProcessor(db_manager)
ml_analyzer = MLAnalyzer(db_manager)
alert_system = AlertSystem(db_manager)
real_time_monitor = RealTimeMonitor(db_manager)
visualization_service = VisualizationService(db_manager)
forensic_reporter = ForensicReporter(db_manager)
network_analyzer = NetworkAnalyzer(db_manager)
camera_service = CameraService(db_manager)
device_auth = DeviceAuthService(db_manager)

# Register blueprints
app.register_blueprint(api_bp, url_prefix='/api')
from api.camera_routes import camera_bp
app.register_blueprint(camera_bp, url_prefix='/api')
from api.auth_routes import auth_bp
app.register_blueprint(auth_bp, url_prefix='/api/auth')

@app.route('/')
def index():
    return jsonify({"message": "IoT Device Log Forensic API", "status": "running", "modes": ["api", "cli"]})

@app.route('/dashboard')
def dashboard():
    """Serve the IoT forensic dashboard"""
    try:
        with open('project.html', 'r', encoding='utf-8') as f:
            html_content = f.read()
        return html_content
    except FileNotFoundError:
        return jsonify({"error": "Dashboard not found"}), 404

@app.route('/static/<path:filename>')
def static_files(filename):
    """Serve static files"""
    return send_from_directory('static', filename)

@app.route('/logs.html')
def logs_page():
    """Serve the detailed logs page"""
    try:
        with open('logs.html', 'r', encoding='utf-8') as f:
            html_content = f.read()
        return html_content
    except FileNotFoundError:
        return jsonify({"error": "Logs page not found"}), 404

@app.route('/health')
def health_check():
    return jsonify({
        "status": "healthy", 
        "database": db_manager.check_connection(),
        "services": {
            "real_time_monitor": real_time_monitor.get_monitoring_status(),
            "ml_analyzer": ml_analyzer.is_trained,
            "features": [
                "log_processing",
                "ml_anomaly_detection", 
                "real_time_monitoring",
                "network_analysis",
                "forensic_reporting",
                "data_visualization"
            ]
        }
    })

@app.route('/api/features')
def get_features():
    """Get list of available features matching FYP proposal"""
    features = {
        "core_features": [
            "IoT Device Log Collection",
            "Real-time Log Analysis", 
            "Machine Learning Anomaly Detection",
            "Security Breach Investigation",
            "Smart City Infrastructure Monitoring"
        ],
        "forensic_capabilities": [
            "Log Correlation and Time Synchronization",
            "Attack Pattern Recognition",
            "Network Traffic Analysis",
            "Device Risk Assessment",
            "Comprehensive Forensic Reporting"
        ],
        "visualization_tools": [
            "Security Dashboard",
            "Attack Timeline Visualization",
            "Device Activity Heatmaps",
            "Network Traffic Analysis Charts",
            "Risk Assessment Graphs"
        ],
        "ml_features": [
            "Isolation Forest Anomaly Detection",
            "Pattern Recognition",
            "Predictive Risk Scoring",
            "Automated Threat Classification"
        ],
        "smart_city_specific": [
            "Traffic Management System Monitoring",
            "Environmental Sensor Analysis",
            "Surveillance Camera Log Analysis",
            "Smart Lighting Infrastructure",
            "IoT Protocol Analysis (MQTT, CoAP, HTTP)"
        ]
    }
    return jsonify(features)

@app.route('/api/system/status')
def get_system_status():
    """Get comprehensive system status"""
    try:
        # Get real-time statistics
        real_time_stats = real_time_monitor.get_real_time_stats()
        
        # Get ML insights
        ml_insights = ml_analyzer.generate_insights()
        
        # Get recent alerts
        recent_alerts = alert_system.get_active_alerts(limit=5)
        
        status = {
            "timestamp": datetime.now().isoformat(),
            "system_health": "operational",
            "real_time_stats": real_time_stats,
            "ml_insights": ml_insights[:3],  # Top 3 insights
            "recent_alerts": len(recent_alerts) if recent_alerts else 0,
            "features_status": {
                "log_processing": "active",
                "anomaly_detection": "active" if ml_analyzer.is_trained else "training_required",
                "real_time_monitoring": "active" if real_time_monitor.is_monitoring else "inactive",
                "forensic_analysis": "available",
                "network_analysis": "available"
            }
        }
        
        return jsonify(status)
        
    except Exception as e:
        return jsonify({
            "timestamp": datetime.now().isoformat(),
            "system_health": "error",
            "error": str(e)
        }), 500

def run_cli_mode():
    """Run the CLI dashboard"""
    from cli_dashboard import CLIDashboard
    dashboard = CLIDashboard()
    dashboard.run()

def run_api_client():
    """Run the API client"""
    from api_client import IoTForensicAPIClient
    client = IoTForensicAPIClient()
    
    print("🔒 IoT Forensic API Client")
    print("=" * 40)
    
    while True:
        print("\nAPI Client Options:")
        print("1. View devices")
        print("2. View logs")
        print("3. Get analytics")
        print("4. Generate report")
        print("5. Monitor real-time")
        print("6. Exit")
        
        choice = input("Select option (1-6): ")
        
        if choice == "1":
            devices = client.get_devices()
            if devices:
                print(f"\nFound {len(devices)} devices:")
                for device in devices:
                    print(f"  - {device['name']}: {device['status']}")
            else:
                print("No devices found")
                
        elif choice == "2":
            logs = client.get_logs()
            if logs:
                print(f"\nFound {len(logs)} logs:")
                for log in logs[:5]:
                    print(f"  - {log.get('device')}: {log.get('message')[:50]}...")
            else:
                print("No logs found")
                
        elif choice == "3":
            analytics = client.get_analytics()
            if analytics:
                print(f"\nAnalytics:")
                for key, value in analytics.items():
                    print(f"  - {key}: {value}")
            else:
                print("No analytics data")
                
        elif choice == "4":
            client.generate_forensic_report()
            
        elif choice == "5":
            duration = input("Monitor duration in minutes (default 5): ")
            try:
                duration = int(duration) if duration else 5
                client.monitor_real_time(duration)
            except ValueError:
                print("Invalid duration")
                
        elif choice == "6":
            break
        else:
            print("Invalid option")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='IoT Device Log Forensic System')
    parser.add_argument('--mode', choices=['api', 'cli', 'client', 'generate-data'], default='api',
                       help='Mode to run: api (Flask server), cli (CLI dashboard), client (API client), or generate-data (populate with sample data)')
    parser.add_argument('--port', type=int, default=5000, help='Port for API server')
    parser.add_argument('--host', default='0.0.0.0', help='Host for API server')
    
    args = parser.parse_args()
    
    # Initialize database tables
    db_manager.init_database()
    device_auth.init_auth_tables()
    
    if args.mode == 'cli':
        print("🖥️ Starting CLI Dashboard Mode...")
        run_cli_mode()
    elif args.mode == 'client':
        print("📡 Starting API Client Mode...")
        run_api_client()
    elif args.mode == 'generate-data':
        print("🔄 Generating Sample Data...")
        from utils.sample_data_generator import SampleDataGenerator
        generator = SampleDataGenerator(db_manager)
        result = generator.populate_test_environment()
        
        # Train ML model with new data
        print("🤖 Training ML model with generated data...")
        ml_analyzer.train_anomaly_detector()
        
        print("\n✅ Sample data generation and ML training completed!")
        print(f"Generated {result['logs_generated']} logs and {result['alerts_generated']} alerts")
        print("You can now start the API server to explore the forensic system.")
    else:
        print(f"🌐 Starting API Server Mode on {args.host}:{args.port}...")
        
        # Start real-time monitoring if not already running
        if not real_time_monitor.is_monitoring:
            print("🔍 Starting real-time monitoring...")
            real_time_monitor.start_monitoring()
        
        app.run(host=args.host, port=args.port, debug=True)
