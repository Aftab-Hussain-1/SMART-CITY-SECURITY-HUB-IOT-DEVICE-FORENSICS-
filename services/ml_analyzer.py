
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
import pickle
import os
from datetime import datetime, timedelta
import logging

class MLAnalyzer:
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.text_vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
        self.model_trained = False
        
    def extract_features(self, logs):
        """Extract numerical features from log data"""
        features = []
        text_features = []
        
        for log in logs:
            # Numerical features
            feature_vector = [
                len(log['message']),  # Message length
                log['message'].count(' '),  # Word count
                log['message'].count('.'),  # Dot count (IP addresses)
                log['message'].count(':'),  # Colon count (ports, protocols)
                1 if log['severity'] == 'high' else 0,  # High severity flag
                1 if log['attack_type'] else 0,  # Attack type present
                hash(log['device_id']) % 1000,  # Device ID hash
            ]
            
            # Add time-based features
            timestamp = log['timestamp']
            if isinstance(timestamp, str):
                timestamp = datetime.fromisoformat(timestamp)
            
            feature_vector.extend([
                timestamp.hour,  # Hour of day
                timestamp.weekday(),  # Day of week
                timestamp.minute,  # Minute of hour
            ])
            
            features.append(feature_vector)
            text_features.append(log['message'])
        
        return np.array(features), text_features
    
    def train_anomaly_detection_model(self, training_logs=None):
        """Train the anomaly detection model"""
        try:
            if training_logs is None:
                # Get recent logs for training
                training_logs = self.db_manager.execute_query(
                    "SELECT * FROM logs ORDER BY timestamp DESC LIMIT 1000",
                    fetch=True
                )
            
            if not training_logs or len(training_logs) < 10:
                logging.warning("Insufficient training data for ML model")
                return False
            
            # Extract features
            numerical_features, text_features = self.extract_features(training_logs)
            
            # Fit text vectorizer
            text_vectors = self.text_vectorizer.fit_transform(text_features)
            
            # Scale numerical features
            scaled_features = self.scaler.fit_transform(numerical_features)
            
            # Combine features
            combined_features = np.hstack([scaled_features, text_vectors.toarray()])
            
            # Train isolation forest
            self.isolation_forest.fit(combined_features)
            self.model_trained = True
            
            # Save model
            self.save_model()
            
            logging.info("Anomaly detection model trained successfully")
            return True
            
        except Exception as e:
            logging.error(f"Model training error: {e}")
            return False
    
    def detect_anomalies(self, logs):
        """Detect anomalies in log data"""
        if not self.model_trained:
            if not self.load_model():
                logging.warning("Model not trained, training with current data")
                if not self.train_anomaly_detection_model():
                    return []
        
        try:
            # Extract features
            numerical_features, text_features = self.extract_features(logs)
            
            # Transform features
            text_vectors = self.text_vectorizer.transform(text_features)
            scaled_features = self.scaler.transform(numerical_features)
            combined_features = np.hstack([scaled_features, text_vectors.toarray()])
            
            # Predict anomalies
            predictions = self.isolation_forest.predict(combined_features)
            anomaly_scores = self.isolation_forest.decision_function(combined_features)
            
            # Mark anomalies in database
            anomalies = []
            for i, (log, prediction, score) in enumerate(zip(logs, predictions, anomaly_scores)):
                if prediction == -1:  # Anomaly detected
                    # Update log in database
                    self.db_manager.execute_query(
                        "UPDATE logs SET is_anomaly = 1 WHERE id = ?",
                        (log['id'],)
                    )
                    
                    anomalies.append({
                        'log_id': log['id'],
                        'anomaly_score': float(score),
                        'message': log['message'],
                        'device_name': log.get('device_name', 'Unknown'),
                        'timestamp': log['timestamp']
                    })
            
            return anomalies
            
        except Exception as e:
            logging.error(f"Anomaly detection error: {e}")
            return []
    
    def analyze_attack_patterns(self, time_period='24h'):
        """Analyze attack patterns over time"""
        if time_period == '24h':
            time_delta = timedelta(hours=24)
        elif time_period == '7d':
            time_delta = timedelta(days=7)
        else:
            time_delta = timedelta(hours=24)
        
        start_time = datetime.now() - time_delta
        
        # Get attack logs
        attack_logs = self.db_manager.execute_query(
            """
            SELECT attack_type, severity, timestamp, device_id, COUNT(*) as count
            FROM logs 
            WHERE attack_type IS NOT NULL AND timestamp >= ?
            GROUP BY attack_type, severity, timestamp, device_id
            ORDER BY timestamp DESC
            """,
            (start_time,),
            fetch=True
        )
        
        # Analyze patterns
        patterns = {
            'most_common_attacks': {},
            'attack_timeline': [],
            'affected_devices': {},
            'severity_distribution': {}
        }
        
        for log in attack_logs:
            attack_type = log['attack_type']
            patterns['most_common_attacks'][attack_type] = patterns['most_common_attacks'].get(attack_type, 0) + log['count']
            patterns['affected_devices'][log['device_id']] = patterns['affected_devices'].get(log['device_id'], 0) + log['count']
            patterns['severity_distribution'][log['severity']] = patterns['severity_distribution'].get(log['severity'], 0) + log['count']
        
        return patterns
    
    def predict_risk_score(self, device_id):
        """Predict risk score for a specific device"""
        # Get recent logs for the device
        recent_logs = self.db_manager.execute_query(
            """
            SELECT * FROM logs 
            WHERE device_id = ? AND timestamp >= ?
            ORDER BY timestamp DESC
            """,
            (device_id, datetime.now() - timedelta(hours=24)),
            fetch=True
        )
        
        if not recent_logs:
            return 0.0
        
        # Calculate risk factors
        total_logs = len(recent_logs)
        high_severity_logs = sum(1 for log in recent_logs if log['severity'] == 'high')
        attack_logs = sum(1 for log in recent_logs if log['attack_type'])
        anomaly_logs = sum(1 for log in recent_logs if log.get('is_anomaly'))
        
        # Calculate risk score (0-100)
        risk_score = min(100, (
            (high_severity_logs / total_logs * 40) +
            (attack_logs / total_logs * 35) +
            (anomaly_logs / total_logs * 25)
        ) * 100)
        
        return round(risk_score, 2)
    
    def save_model(self):
        """Save trained model to file"""
        try:
            model_data = {
                'isolation_forest': self.isolation_forest,
                'scaler': self.scaler,
                'text_vectorizer': self.text_vectorizer,
                'model_trained': self.model_trained
            }
            
            with open('ml_model.pkl', 'wb') as f:
                pickle.dump(model_data, f)
            
            return True
        except Exception as e:
            logging.error(f"Model save error: {e}")
            return False
    
    def load_model(self):
        """Load trained model from file"""
        try:
            if os.path.exists('ml_model.pkl'):
                with open('ml_model.pkl', 'rb') as f:
                    model_data = pickle.load(f)
                
                self.isolation_forest = model_data['isolation_forest']
                self.scaler = model_data['scaler']
                self.text_vectorizer = model_data['text_vectorizer']
                self.model_trained = model_data['model_trained']
                
                return True
        except Exception as e:
            logging.error(f"Model load error: {e}")
        
        return False
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
import pickle
import os
from datetime import datetime, timedelta
import logging

class MLAnalyzer:
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.vectorizer = TfidfVectorizer(max_features=100, stop_words='english')
        self.is_trained = False
        
    def extract_features(self, logs):
        """Extract features from log data for ML analysis"""
        if not logs:
            return np.array([])
            
        features = []
        
        for log in logs:
            # Numerical features
            severity_score = {'low': 1, 'medium': 2, 'high': 3}.get(log.get('severity', 'low'), 1)
            
            # Time-based features
            timestamp = datetime.fromisoformat(log.get('timestamp', datetime.now().isoformat()).replace('Z', '+00:00'))
            hour = timestamp.hour
            day_of_week = timestamp.weekday()
            
            # Message length
            message_length = len(log.get('message', ''))
            
            # Attack type indicator
            has_attack = 1 if log.get('attack_type') else 0
            
            feature_vector = [
                severity_score,
                hour,
                day_of_week,
                message_length,
                has_attack
            ]
            
            features.append(feature_vector)
            
        return np.array(features)
    
    def train_anomaly_detector(self, training_logs=None):
        """Train the anomaly detection model"""
        if training_logs is None:
            training_logs = self.db_manager.get_logs(limit=1000)
            
        if not training_logs:
            logging.warning("No training data available")
            return False
            
        try:
            features = self.extract_features(training_logs)
            if features.size == 0:
                return False
                
            # Scale features
            scaled_features = self.scaler.fit_transform(features)
            
            # Train isolation forest
            self.isolation_forest.fit(scaled_features)
            self.is_trained = True
            
            logging.info("Anomaly detection model trained successfully")
            return True
            
        except Exception as e:
            logging.error(f"Error training model: {e}")
            return False
    
    def detect_anomalies(self, logs):
        """Detect anomalies in log data"""
        if not self.is_trained:
            self.train_anomaly_detector()
            
        if not logs:
            return []
            
        try:
            features = self.extract_features(logs)
            if features.size == 0:
                return []
                
            scaled_features = self.scaler.transform(features)
            anomaly_scores = self.isolation_forest.decision_function(scaled_features)
            anomaly_predictions = self.isolation_forest.predict(scaled_features)
            
            anomalies = []
            for i, (log, score, prediction) in enumerate(zip(logs, anomaly_scores, anomaly_predictions)):
                if prediction == -1:  # Anomaly detected
                    anomalies.append({
                        'log': log,
                        'anomaly_score': float(score),
                        'confidence': abs(float(score))
                    })
                    
            return sorted(anomalies, key=lambda x: x['confidence'], reverse=True)
            
        except Exception as e:
            logging.error(f"Error detecting anomalies: {e}")
            return []
    
    def analyze_attack_patterns(self):
        """Analyze attack patterns in the logs"""
        # Get logs with attack types
        attack_logs = self.db_manager.execute_query(
            """
            SELECT attack_type, severity, device_id, COUNT(*) as count, timestamp
            FROM logs 
            WHERE attack_type IS NOT NULL 
            GROUP BY attack_type, severity, device_id
            ORDER BY count DESC
            """,
            fetch=True
        )
        
        if not attack_logs:
            return {
                'most_common_attacks': {},
                'attack_timeline': [],
                'affected_devices': {},
                'severity_distribution': {}
            }
        
        patterns = {
            'most_common_attacks': {},
            'attack_timeline': [],
            'affected_devices': {},
            'severity_distribution': {}
        }
        
        for log in attack_logs:
            attack_type = log['attack_type']
            patterns['most_common_attacks'][attack_type] = patterns['most_common_attacks'].get(attack_type, 0) + log['count']
            patterns['affected_devices'][log['device_id']] = patterns['affected_devices'].get(log['device_id'], 0) + log['count']
            patterns['severity_distribution'][log['severity']] = patterns['severity_distribution'].get(log['severity'], 0) + log['count']
        
        return patterns
    
    def predict_risk_score(self, device_id):
        """Predict risk score for a specific device"""
        # Get recent logs for the device
        recent_logs = self.db_manager.execute_query(
            """
            SELECT * FROM logs 
            WHERE device_id = ? AND timestamp >= ?
            ORDER BY timestamp DESC
            """,
            (device_id, datetime.now() - timedelta(hours=24)),
            fetch=True
        )
        
        if not recent_logs:
            return 0.0
        
        # Calculate risk factors
        total_logs = len(recent_logs)
        high_severity_logs = sum(1 for log in recent_logs if log.get('severity') == 'high')
        attack_logs = sum(1 for log in recent_logs if log.get('attack_type'))
        anomaly_logs = sum(1 for log in recent_logs if log.get('is_anomaly'))
        
        # Calculate risk score (0-10 scale)
        base_score = min(total_logs / 10, 3)  # Base activity score
        severity_score = min(high_severity_logs * 2, 4)  # Severity impact
        attack_score = min(attack_logs * 1.5, 3)  # Attack impact
        
        total_score = base_score + severity_score + attack_score
        
        return min(total_score, 10.0)
    
    def generate_insights(self):
        """Generate security insights based on ML analysis"""
        logs = self.db_manager.get_logs(limit=1000)
        if not logs:
            return []
            
        insights = []
        
        # Detect anomalies
        anomalies = self.detect_anomalies(logs)
        if anomalies:
            insights.append({
                'type': 'anomaly',
                'severity': 'high',
                'message': f"Detected {len(anomalies)} anomalous events",
                'details': f"Top anomaly confidence: {anomalies[0]['confidence']:.2f}"
            })
        
        # Analyze attack patterns
        patterns = self.analyze_attack_patterns()
        if patterns['most_common_attacks']:
            top_attack = max(patterns['most_common_attacks'].items(), key=lambda x: x[1])
            insights.append({
                'type': 'attack_pattern',
                'severity': 'medium',
                'message': f"Most common attack: {top_attack[0]}",
                'details': f"Occurred {top_attack[1]} times"
            })
        
        # Check device risk scores
        devices = self.db_manager.get_devices()
        if devices:
            high_risk_devices = []
            for device in devices:
                risk_score = self.predict_risk_score(device['id'])
                if risk_score > 7:
                    high_risk_devices.append((device['device_name'], risk_score))
            
            if high_risk_devices:
                insights.append({
                    'type': 'high_risk_device',
                    'severity': 'high',
                    'message': f"{len(high_risk_devices)} high-risk devices detected",
                    'details': f"Highest risk: {high_risk_devices[0][0]} ({high_risk_devices[0][1]:.1f}/10)"
                })
        
        return insights
    
    def save_model(self, filepath):
        """Save the trained model"""
        if not self.is_trained:
            logging.error("Model not trained yet")
            return False
            
        try:
            model_data = {
                'isolation_forest': self.isolation_forest,
                'scaler': self.scaler,
                'vectorizer': self.vectorizer,
                'is_trained': self.is_trained
            }
            
            with open(filepath, 'wb') as f:
                pickle.dump(model_data, f)
                
            logging.info(f"Model saved to {filepath}")
            return True
            
        except Exception as e:
            logging.error(f"Error saving model: {e}")
            return False
    
    def load_model(self, filepath):
        """Load a trained model"""
        if not os.path.exists(filepath):
            logging.error(f"Model file not found: {filepath}")
            return False
            
        try:
            with open(filepath, 'rb') as f:
                model_data = pickle.load(f)
                
            self.isolation_forest = model_data['isolation_forest']
            self.scaler = model_data['scaler']
            self.vectorizer = model_data['vectorizer']
            self.is_trained = model_data['is_trained']
            
            logging.info(f"Model loaded from {filepath}")
            return True
            
        except Exception as e:
            logging.error(f"Error loading model: {e}")
            return False
