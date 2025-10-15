
import sqlite3
import os
from datetime import datetime
import logging

class DatabaseManager:
    def __init__(self):
        self.db_path = 'iot_forensic.db'
        self.connection = None
        
    def connect(self):
        try:
            self.connection = sqlite3.connect(self.db_path)
            self.connection.row_factory = sqlite3.Row
            return True
        except Exception as e:
            logging.error(f"Database connection error: {e}")
            return False
    
    def disconnect(self):
        if self.connection:
            self.connection.close()
    
    def check_connection(self):
        try:
            if self.connect():
                cursor = self.connection.cursor()
                cursor.execute("SELECT 1")
                cursor.close()
                self.disconnect()
                return True
        except:
            return False
        return False
    
    def init_database(self):
        if not self.connect():
            return False
            
        try:
            cursor = self.connection.cursor()
            
            # Create devices table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_name TEXT NOT NULL,
                    device_type TEXT NOT NULL,
                    location TEXT,
                    status TEXT DEFAULT 'active',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create logs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER,
                    timestamp TIMESTAMP NOT NULL,
                    level TEXT NOT NULL,
                    message TEXT NOT NULL,
                    protocol TEXT,
                    source_ip TEXT,
                    severity INTEGER DEFAULT 1,
                    attack_type TEXT,
                    is_anomaly BOOLEAN DEFAULT FALSE,
                    processed BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (device_id) REFERENCES devices (id)
                )
            """)
            
            # Create alerts table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    device_id INTEGER,
                    log_id INTEGER,
                    status TEXT DEFAULT 'open',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (device_id) REFERENCES devices (id),
                    FOREIGN KEY (log_id) REFERENCES logs (id)
                )
            """)
            
            # Create analytics table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS analytics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    metric_name TEXT NOT NULL,
                    metric_value REAL NOT NULL,
                    time_period TEXT NOT NULL,
                    calculated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            self.connection.commit()
            
            # Insert sample devices if none exist
            cursor.execute("SELECT COUNT(*) FROM devices")
            if cursor.fetchone()[0] == 0:
                sample_devices = [
                    ('Smart Traffic Light 001', 'Traffic Control', 'Main Street & 1st Ave'),
                    ('Environmental Sensor 002', 'Air Quality Monitor', 'City Park'),
                    ('Security Camera 003', 'Surveillance', 'Downtown Plaza'),
                    ('Smart Streetlight 004', 'Lighting', 'Residential Area'),
                    ('Parking Meter 005', 'Payment System', 'Business District')
                ]
                
                cursor.executemany(
                    "INSERT INTO devices (device_name, device_type, location) VALUES (?, ?, ?)",
                    sample_devices
                )
                self.connection.commit()
            
            self.disconnect()
            return True
            
        except Exception as e:
            logging.error(f"Database initialization error: {e}")
            if self.connection:
                self.connection.rollback()
                self.disconnect()
            return False
    
    def execute_query(self, query, params=None, fetch=False):
        """Execute a query with optional parameters"""
        if not self.connect():
            return None
            
        try:
            cursor = self.connection.cursor()
            
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            
            if fetch:
                if query.strip().upper().startswith('SELECT'):
                    results = [dict(row) for row in cursor.fetchall()]
                else:
                    results = cursor.fetchall()
                cursor.close()
                self.disconnect()
                return results
            else:
                self.connection.commit()
                cursor.close()
                self.disconnect()
                return True
                
        except Exception as e:
            logging.error(f"Query execution error: {e}")
            if self.connection:
                self.connection.rollback()
                self.disconnect()
            return None
    
    def get_logs(self, limit=100, device_id=None, severity=None):
        """Get logs with optional device and severity filter"""
        query = """
            SELECT l.*, d.device_name, d.device_type, d.location
            FROM logs l
            LEFT JOIN devices d ON l.device_id = d.id
        """
        params = []
        conditions = []
        
        if device_id:
            conditions.append("l.device_id = ?")
            params.append(device_id)
            
        if severity:
            conditions.append("l.severity = ?")
            params.append(severity)
        
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        
        query += " ORDER BY l.timestamp DESC LIMIT ?"
        params.append(limit)
        
        return self.execute_query(query, params, fetch=True)
    
    def insert_log(self, device_id, timestamp, log_level, message, severity='normal', attack_type=None, protocol=None, source_ip=None, destination_ip=None):
        """Insert a new log entry"""
        query = """
            INSERT INTO logs (device_id, timestamp, level, message, severity, attack_type, protocol, source_ip)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (device_id, timestamp, log_level, message, severity, attack_type, protocol, source_ip)
        
        if self.connect():
            try:
                cursor = self.connection.cursor()
                cursor.execute(query, params)
                log_id = cursor.lastrowid
                self.connection.commit()
                cursor.close()
                self.disconnect()
                return log_id
            except Exception as e:
                logging.error(f"Log insertion error: {e}")
                if self.connection:
                    self.connection.rollback()
                    self.disconnect()
                return None
        return None
    
    def insert_device(self, device_name, device_type, location=None):
        """Insert a new device"""
        query = "INSERT INTO devices (device_name, device_type, location) VALUES (?, ?, ?)"
        params = (device_name, device_type, location)
        
        if self.connect():
            try:
                cursor = self.connection.cursor()
                cursor.execute(query, params)
                device_id = cursor.lastrowid
                self.connection.commit()
                cursor.close()
                self.disconnect()
                return device_id
            except Exception as e:
                logging.error(f"Device insertion error: {e}")
                if self.connection:
                    self.connection.rollback()
                    self.disconnect()
                return None
        return None
    
    def get_devices(self):
        """Get all devices"""
        return self.execute_query("SELECT * FROM devices ORDER BY device_name", fetch=True)
    
    def get_alerts(self, status=None):
        """Get alerts with optional status filter"""
        query = """
            SELECT a.*, d.device_name
            FROM alerts a
            LEFT JOIN devices d ON a.device_id = d.id
        """
        params = []
        
        if status:
            query += " WHERE a.status = ?"
            params.append(status)
        
        query += " ORDER BY a.created_at DESC"
        
        return self.execute_query(query, params, fetch=True)
