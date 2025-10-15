
from flask import Blueprint, jsonify, request, Response
from datetime import datetime
import cv2

camera_bp = Blueprint('camera', __name__)

@camera_bp.route('/cameras', methods=['GET'])
def get_cameras():
    """Get list of configured cameras"""
    from app import camera_service
    
    try:
        cameras = camera_service.get_camera_status()
        return jsonify({
            'status': 'success',
            'data': cameras
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@camera_bp.route('/cameras', methods=['POST'])
def add_camera():
    """Add new IP camera"""
    from app import camera_service
    
    data = request.get_json()
    camera_id = data.get('camera_id')
    camera_url = data.get('camera_url')
    camera_name = data.get('camera_name')
    location = data.get('location', 'Unknown')
    
    if not all([camera_id, camera_url, camera_name]):
        return jsonify({'status': 'error', 'message': 'Missing required fields'}), 400
    
    try:
        success = camera_service.add_camera(camera_id, camera_url, camera_name, location)
        
        if success:
            return jsonify({
                'status': 'success',
                'message': f'Camera {camera_name} added successfully'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to add camera'
            }), 500
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@camera_bp.route('/cameras/start', methods=['POST'])
def start_camera_monitoring():
    """Start camera monitoring"""
    from app import camera_service
    
    try:
        camera_service.start_monitoring()
        return jsonify({
            'status': 'success',
            'message': 'Camera monitoring started'
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@camera_bp.route('/cameras/stop', methods=['POST'])
def stop_camera_monitoring():
    """Stop camera monitoring"""
    from app import camera_service
    
    try:
        camera_service.stop_monitoring()
        return jsonify({
            'status': 'success',
            'message': 'Camera monitoring stopped'
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@camera_bp.route('/cameras/<camera_id>/frame')
def get_camera_frame(camera_id):
    """Get current frame from camera"""
    from app import camera_service
    
    try:
        frame_data = camera_service.get_camera_frame(camera_id)
        
        if frame_data:
            return Response(frame_data, mimetype='image/jpeg')
        else:
            return jsonify({'status': 'error', 'message': 'Camera not available'}), 404
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@camera_bp.route('/cameras/<camera_id>/stream')
def camera_stream(camera_id):
    """Stream camera feed"""
    from app import camera_service
    
    def generate_frames():
        while True:
            frame_data = camera_service.get_camera_frame(camera_id)
            if frame_data:
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + frame_data + b'\r\n')
            else:
                break
                
    return Response(generate_frames(),
                   mimetype='multipart/x-mixed-replace; boundary=frame')
