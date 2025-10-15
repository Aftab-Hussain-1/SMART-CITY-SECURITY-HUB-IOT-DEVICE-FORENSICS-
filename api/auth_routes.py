
from flask import Blueprint, request, jsonify
from datetime import datetime
import random

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
def register_device():
    """Register a new device"""
    from app import device_auth
    
    data = request.get_json()
    device_name = data.get('device_name')
    device_type = data.get('device_type')
    location = data.get('location')
    username = data.get('username')
    password = data.get('password')
    
    if not all([device_name, device_type, username, password]):
        return jsonify({'success': False, 'message': 'Missing required fields'}), 400
    
    try:
        device_id = device_auth.register_device(device_name, device_type, location, username, password)
        
        if device_id:
            return jsonify({
                'success': True,
                'device_id': device_id,
                'message': 'Device registered successfully'
            })
        else:
            return jsonify({'success': False, 'message': 'Failed to register device'}), 500
            
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@auth_bp.route('/login', methods=['POST'])
def login_device():
    """Device login"""
    from app import device_auth
    
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    ip_address = request.remote_addr
    
    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password required'}), 400
    
    try:
        result = device_auth.authenticate_device(username, password, ip_address)
        
        if result['success']:
            return jsonify(result)
        else:
            return jsonify(result), 401
            
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@auth_bp.route('/logout', methods=['POST'])
def logout_device():
    """Device logout"""
    from app import device_auth
    
    data = request.get_json()
    session_token = data.get('session_token')
    
    if not session_token:
        return jsonify({'success': False, 'message': 'Session token required'}), 400
    
    try:
        result = device_auth.logout_device(session_token)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@auth_bp.route('/sessions', methods=['GET'])
def get_active_sessions():
    """Get active device sessions"""
    from app import device_auth
    
    try:
        sessions = device_auth.get_active_sessions()
        return jsonify({
            'success': True,
            'sessions': sessions,
            'count': len(sessions) if sessions else 0
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@auth_bp.route('/history', methods=['GET'])
def get_login_history():
    """Get device login/logout history"""
    from app import device_auth
    
    device_id = request.args.get('device_id')
    limit = int(request.args.get('limit', 100))
    
    try:
        history = device_auth.get_login_history(device_id, limit)
        return jsonify({
            'success': True,
            'history': history,
            'count': len(history) if history else 0
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@auth_bp.route('/simulate-activity', methods=['POST'])
def simulate_device_activity():
    """Simulate device login/logout activity for testing"""
    from app import device_auth, db_manager
    
    data = request.get_json()
    count = data.get('count', 10)
    
    try:
        # Get existing devices
        devices = db_manager.get_devices()
        if not devices:
            return jsonify({'success': False, 'message': 'No devices found'}), 400
        
        activity_logs = []
        
        for i in range(count):
            device = random.choice(devices)
            activity_type = random.choice(['login', 'logout', 'failed_login'])
            ip_address = f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
            
            if activity_type == 'login':
                message = f"Device {device['device_name']} logged in from {ip_address}"
                severity = "low"
                attack_type = None
            elif activity_type == 'logout':
                message = f"Device {device['device_name']} logged out from {ip_address}"
                severity = "low"
                attack_type = None
            else:  # failed_login
                message = f"Failed login attempt for device {device['device_name']} from {ip_address}"
                severity = "medium"
                attack_type = "Brute Force"
            
            log_id = db_manager.insert_log(
                device_id=device['id'],
                timestamp=datetime.now(),
                log_level="INFO" if activity_type != 'failed_login' else "WARNING",
                message=message,
                severity=severity,
                protocol="AUTH",
                source_ip=ip_address,
                attack_type=attack_type
            )
            
            if log_id:
                activity_logs.append({
                    'device': device['device_name'],
                    'activity': activity_type,
                    'ip': ip_address,
                    'message': message
                })
        
        return jsonify({
            'success': True,
            'message': f'Generated {len(activity_logs)} authentication activities',
            'activities': activity_logs
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
