
import hashlib
import uuid
from datetime import datetime
import logging

class DeviceAuthService:
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.active_sessions = {}
        
    def init_auth_tables(self):
        """Initialize authentication tables"""
        self.db_manager.execute_query("""
            CREATE TABLE IF NOT EXISTS device_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER,
                session_token TEXT UNIQUE,
                login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                logout_time TIMESTAMP NULL,
                ip_address TEXT,
                status TEXT DEFAULT 'active',
                FOREIGN KEY (device_id) REFERENCES devices (id)
            )
        """)
        
        self.db_manager.execute_query("""
            CREATE TABLE IF NOT EXISTS device_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER,
                username TEXT,
                password_hash TEXT,
                api_key TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (device_id) REFERENCES devices (id)
            )
        """)
    
    def register_device(self, device_name, device_type, location, username=None, password=None):
        """Register a new device with authentication credentials"""
        device_id = self.db_manager.insert_device(device_name, device_type, location)
        
        if device_id and username and password:
            password_hash = self._hash_password(password)
            api_key = self._generate_api_key()
            
            self.db_manager.execute_query(
                "INSERT INTO device_credentials (device_id, username, password_hash, api_key) VALUES (?, ?, ?, ?)",
                (device_id, username, password_hash, api_key)
            )
            
            # Log device registration
            self.db_manager.insert_log(
                device_id=device_id,
                timestamp=datetime.now(),
                log_level="INFO",
                message=f"Device {device_name} registered successfully",
                severity="low",
                protocol="AUTH"
            )
            
        return device_id
    
    def authenticate_device(self, username, password, ip_address):
        """Authenticate device login"""
        creds = self.db_manager.execute_query(
            """
            SELECT dc.*, d.device_name, d.id as device_id 
            FROM device_credentials dc 
            JOIN devices d ON dc.device_id = d.id 
            WHERE dc.username = ?
            """,
            (username,),
            fetch=True
        )
        
        if creds and self._verify_password(password, creds[0]['password_hash']):
            device = creds[0]
            session_token = self._generate_session_token()
            
            # Create session
            self.db_manager.execute_query(
                "INSERT INTO device_sessions (device_id, session_token, ip_address) VALUES (?, ?, ?)",
                (device['device_id'], session_token, ip_address)
            )
            
            # Log successful login
            self.db_manager.insert_log(
                device_id=device['device_id'],
                timestamp=datetime.now(),
                log_level="INFO",
                message=f"Device {device['device_name']} logged in from {ip_address}",
                severity="low",
                protocol="AUTH",
                source_ip=ip_address
            )
            
            self.active_sessions[session_token] = {
                'device_id': device['device_id'],
                'device_name': device['device_name'],
                'login_time': datetime.now(),
                'ip_address': ip_address
            }
            
            return {
                'success': True,
                'session_token': session_token,
                'device_id': device['device_id'],
                'device_name': device['device_name']
            }
        else:
            # Log failed login attempt
            if creds:
                self.db_manager.insert_log(
                    device_id=creds[0]['device_id'],
                    timestamp=datetime.now(),
                    log_level="WARNING",
                    message=f"Failed login attempt for device {creds[0]['device_name']} from {ip_address}",
                    severity="medium",
                    protocol="AUTH",
                    source_ip=ip_address,
                    attack_type="Brute Force"
                )
            
            return {'success': False, 'message': 'Invalid credentials'}
    
    def logout_device(self, session_token):
        """Handle device logout"""
        if session_token in self.active_sessions:
            session = self.active_sessions[session_token]
            
            # Update session in database
            self.db_manager.execute_query(
                "UPDATE device_sessions SET logout_time = ?, status = 'logged_out' WHERE session_token = ?",
                (datetime.now(), session_token)
            )
            
            # Log logout
            self.db_manager.insert_log(
                device_id=session['device_id'],
                timestamp=datetime.now(),
                log_level="INFO",
                message=f"Device {session['device_name']} logged out from {session['ip_address']}",
                severity="low",
                protocol="AUTH",
                source_ip=session['ip_address']
            )
            
            del self.active_sessions[session_token]
            return {'success': True, 'message': 'Logged out successfully'}
        
        return {'success': False, 'message': 'Invalid session'}
    
    def get_active_sessions(self):
        """Get all active device sessions"""
        return self.db_manager.execute_query(
            """
            SELECT ds.*, d.device_name, d.device_type 
            FROM device_sessions ds 
            JOIN devices d ON ds.device_id = d.id 
            WHERE ds.status = 'active' 
            ORDER BY ds.login_time DESC
            """,
            fetch=True
        )
    
    def get_login_history(self, device_id=None, limit=100):
        """Get device login/logout history"""
        query = """
            SELECT ds.*, d.device_name, d.device_type 
            FROM device_sessions ds 
            JOIN devices d ON ds.device_id = d.id
        """
        params = []
        
        if device_id:
            query += " WHERE ds.device_id = ?"
            params.append(device_id)
        
        query += " ORDER BY ds.login_time DESC LIMIT ?"
        params.append(limit)
        
        return self.db_manager.execute_query(query, params, fetch=True)
    
    def _hash_password(self, password):
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def _verify_password(self, password, password_hash):
        """Verify password against hash"""
        return hashlib.sha256(password.encode()).hexdigest() == password_hash
    
    def _generate_session_token(self):
        """Generate unique session token"""
        return str(uuid.uuid4())
    
    def _generate_api_key(self):
        """Generate API key for device"""
        return str(uuid.uuid4()).replace('-', '')
