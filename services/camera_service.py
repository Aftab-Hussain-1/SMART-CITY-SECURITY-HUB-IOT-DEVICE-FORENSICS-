import cv2
import threading
import time
import json
import logging
from datetime import datetime
import requests
import numpy as np
from urllib.parse import urlparse

class CameraService:
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.cameras = {}
        self.is_monitoring = False
        self.monitor_thread = None
        self.frame_processors = []

    def add_camera(self, camera_id, camera_url, camera_name, location="Unknown"):
        """Add an IP camera to monitoring"""
        try:
            # Create a more lenient camera connection test
            cap = cv2.VideoCapture(camera_url)
            cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
            cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
            cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)

            # Try to read one frame with timeout
            success = False
            for attempt in range(5):
                ret, frame = cap.read()
                if ret and frame is not None and frame.size > 0:
                    success = True
                    break
                time.sleep(0.5)

            if not success:
                logging.warning(f"Initial frame read failed for camera: {camera_url}, will retry during monitoring")
                # Try a fresh connection
                cap.release()
                cap = cv2.VideoCapture(camera_url)
                # Give it one more chance
                ret, frame = cap.read()
                if ret and frame is not None:
                    success = True

            # Register camera in database
            device_id = self.db_manager.insert_device(camera_name, "IP Camera", location)

            self.cameras[camera_id] = {
                'device_id': device_id,
                'url': camera_url,
                'name': camera_name,
                'location': location,
                'capture': cap,
                'last_frame_time': datetime.now(),
                'frame_count': 0,
                'motion_detector': cv2.createBackgroundSubtractorMOG2(),
                'is_online': success
            }

            # Generate initial log entry
            self._generate_camera_log(self.cameras[camera_id], "camera_added", "low",
                                    f"IP Camera {camera_name} added to monitoring system")

            logging.info(f"Camera {camera_name} added successfully")
            return True

        except Exception as e:
            logging.error(f"Error adding camera: {e}")
            return False

    def start_monitoring(self):
        """Start monitoring all cameras"""
        if not self.is_monitoring and self.cameras:
            self.is_monitoring = True
            self.monitor_thread = threading.Thread(target=self._monitoring_loop)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()
            logging.info("Camera monitoring started")

    def stop_monitoring(self):
        """Stop monitoring cameras"""
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join()

        # Release camera resources
        for camera_data in self.cameras.values():
            camera_data['capture'].release()
        logging.info("Camera monitoring stopped")

    def _monitoring_loop(self):
        """Main camera monitoring loop"""
        while self.is_monitoring:
            try:
                for camera_id, camera_data in self.cameras.items():
                    self._process_camera_frame(camera_id, camera_data)

                time.sleep(0.1)  # Process frames at ~10 FPS

            except Exception as e:
                logging.error(f"Camera monitoring error: {e}")
                time.sleep(1)

    def _process_camera_frame(self, camera_id, camera_data):
        """Process a single camera frame"""
        try:
            cap = camera_data['capture']
            ret, frame = cap.read()

            if not ret or frame is None:
                # Try to reconnect
                self._reconnect_camera(camera_id, camera_data)
                return

            # Update camera status
            camera_data['is_online'] = True
            camera_data['frame_count'] += 1
            camera_data['last_frame_time'] = datetime.now()

            # Detect motion and analyze frame
            motion_detected = self._detect_motion(frame, camera_data['motion_detector'])

            # Generate logs based on camera analysis
            if motion_detected:
                self._generate_camera_log(camera_data, "motion_detected", "medium",
                                        f"Motion detected in {camera_data['name']}")

            # Check for security events every 30 frames
            if camera_data['frame_count'] % 30 == 0:
                self._analyze_security_events(frame, camera_data)

        except Exception as e:
            camera_data['is_online'] = False
            logging.error(f"Frame processing error for camera {camera_id}: {e}")

    def _detect_motion(self, frame, motion_detector):
        """Detect motion in camera frame"""
        try:
            # Apply background subtraction
            fg_mask = motion_detector.apply(frame)

            # Calculate motion percentage
            motion_pixels = cv2.countNonZero(fg_mask)
            total_pixels = fg_mask.shape[0] * fg_mask.shape[1]
            motion_percentage = (motion_pixels / total_pixels) * 100

            # Return True if significant motion detected
            return motion_percentage > 5.0

        except Exception as e:
            logging.error(f"Motion detection error: {e}")
            return False

    def _analyze_security_events(self, frame, camera_data):
        """Analyze frame for security events"""
        try:
            # Simulate various security checks
            current_time = datetime.now()

            # Check for unusual activity patterns
            if current_time.hour < 6 or current_time.hour > 22:
                # Late night activity
                self._generate_camera_log(camera_data, "unusual_activity", "high",
                                        f"Unusual activity detected during off-hours at {camera_data['name']}")

            # Simulate object detection events
            import random
            if random.random() < 0.1:  # 10% chance
                event_types = [
                    ("unauthorized_access", "high", "Unauthorized person detected"),
                    ("suspicious_behavior", "medium", "Suspicious behavior pattern identified"),
                    ("perimeter_breach", "critical", "Perimeter security breach detected"),
                    ("loitering_detected", "medium", "Person loitering in restricted area"),
                    ("vehicle_analysis", "low", "Vehicle movement tracked")
                ]

                event_type, severity, message = random.choice(event_types)
                self._generate_camera_log(camera_data, event_type, severity,
                                        f"{message} at {camera_data['name']}")

        except Exception as e:
            logging.error(f"Security analysis error: {e}")

    def _generate_camera_log(self, camera_data, event_type, severity, message):
        """Generate log entry for camera event"""
        try:
            log_id = self.db_manager.execute_query(
                """
                INSERT INTO logs (device_id, timestamp, log_level, message, severity,
                                source_ip, protocol, event_type, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    camera_data['device_id'],
                    datetime.now(),
                    "INFO",
                    message,
                    severity,
                    camera_data['url'],
                    "RTSP/HTTP",
                    event_type,
                    datetime.now()
                )
            )

            # Mark as anomaly for high/critical severity
            if severity in ['high', 'critical']:
                self.db_manager.execute_query(
                    "UPDATE logs SET is_anomaly = TRUE WHERE id = ?",
                    (log_id,)
                )

            logging.info(f"Camera log generated: {event_type} - {severity}")

        except Exception as e:
            logging.error(f"Error generating camera log: {e}")

    def _reconnect_camera(self, camera_id, camera_data):
        """Attempt to reconnect to camera"""
        try:
            camera_data['is_online'] = False
            camera_data['capture'].release()
            time.sleep(1)

            # Try to create a new connection
            new_cap = cv2.VideoCapture(camera_data['url'])
            new_cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
            
            # Test the connection
            ret, frame = new_cap.read()
            if ret and frame is not None:
                camera_data['capture'] = new_cap
                camera_data['is_online'] = True
                logging.info(f"Camera {camera_id} reconnected successfully")
                
                # Generate reconnection log
                self._generate_camera_log(camera_data, "camera_reconnected", "low",
                                        f"Camera {camera_data['name']} reconnected successfully")
            else:
                new_cap.release()
                logging.error(f"Failed to reconnect camera {camera_id}")
                
                # Generate offline log
                self._generate_camera_log(camera_data, "camera_offline", "medium",
                                        f"Camera {camera_data['name']} is offline")

        except Exception as e:
            camera_data['is_online'] = False
            logging.error(f"Camera reconnection error: {e}")

    def get_camera_status(self):
        """Get status of all cameras"""
        status = {}
        for camera_id, camera_data in self.cameras.items():
            # Check if camera is truly connected by testing frame read
            is_connected = False
            if camera_data['capture'].isOpened():
                # Test if we can actually read a frame
                ret, frame = camera_data['capture'].read()
                if ret and frame is not None:
                    is_connected = True
                    # Put the frame back by recreating the capture if needed
                    camera_data['capture'].set(cv2.CAP_PROP_POS_FRAMES, 
                                              camera_data['capture'].get(cv2.CAP_PROP_POS_FRAMES) - 1)
            
            # Extract IP address from camera URL
            ip_address = self._extract_ip_from_url(camera_data['url'])
            
            status[camera_id] = {
                'name': camera_data['name'],
                'location': camera_data['location'],
                'is_connected': is_connected,
                'frame_count': camera_data['frame_count'],
                'last_frame_time': camera_data['last_frame_time'].isoformat(),
                'resolution': f"{int(camera_data['capture'].get(cv2.CAP_PROP_FRAME_WIDTH))}x{int(camera_data['capture'].get(cv2.CAP_PROP_FRAME_HEIGHT))}",
                'ip_address': ip_address
            }
        return status

    def _extract_ip_from_url(self, url):
        """Extract IP address from camera URL"""
        try:
            from urllib.parse import urlparse
            import re
            
            parsed = urlparse(url)
            hostname = parsed.hostname
            
            if hostname:
                # Check if it's already an IP address
                ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
                if re.match(ip_pattern, hostname):
                    return hostname
                else:
                    # If it's a domain name, try to resolve it
                    import socket
                    try:
                        ip = socket.gethostbyname(hostname)
                        return ip
                    except socket.gaierror:
                        return hostname  # Return hostname if can't resolve
            
            # Fallback: try to extract IP from the URL string directly
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', url)
            if ip_match:
                return ip_match.group(1)
                
            return "Unknown"
        except Exception as e:
            logging.error(f"Error extracting IP from URL {url}: {e}")
            return "Unknown"

    def get_camera_frame(self, camera_id):
        """Get current frame from specific camera"""
        if camera_id in self.cameras:
            cap = self.cameras[camera_id]['capture']
            ret, frame = cap.read()
            if ret:
                # Encode frame as JPEG
                _, buffer = cv2.imencode('.jpg', frame)
                return buffer.tobytes()
        return None