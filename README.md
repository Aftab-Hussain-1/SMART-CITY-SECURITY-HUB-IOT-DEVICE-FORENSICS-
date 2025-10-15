
# IoT Device Log Forensic for Investigating Smart City Security Breaches

A comprehensive forensic framework for analyzing IoT device logs in smart city infrastructure, designed to detect security breaches, identify vulnerabilities, and improve overall cybersecurity posture.

## 🎯 Project Overview

This Final Year Project (FYP) implements a complete IoT device log forensic system that addresses the growing cybersecurity challenges in smart cities. As urban areas become increasingly interconnected through IoT devices like smart cameras, environmental sensors, and traffic management systems, the risk of security breaches escalates significantly.

## 🚀 Key Features (FYP Implementation)

### Core Forensic Capabilities
- **Real-time Log Analysis**: Continuous monitoring and analysis of IoT device logs
- **Machine Learning Anomaly Detection**: Advanced ML algorithms using Isolation Forest for pattern recognition
- **Security Breach Investigation**: Comprehensive forensic analysis with correlation and time synchronization
- **Attack Pattern Recognition**: Automated detection of DDoS, brute force, malware, and other attack types
- **Network Traffic Analysis**: Deep inspection of IoT protocols (MQTT, CoAP, HTTP/HTTPS)

### Smart City Specific Features
- **Multi-Device Support**: Traffic lights, environmental sensors, surveillance cameras, smart streetlights
- **Geographic Analysis**: Location-based security incident mapping
- **Protocol Analysis**: IoT-specific protocol inspection and security assessment  
- **Device Risk Assessment**: Predictive risk scoring for individual IoT devices
- **Infrastructure Monitoring**: Comprehensive smart city infrastructure oversight

### Advanced Analytics & Visualization
- **Interactive Security Dashboard**: Real-time security posture visualization
- **Attack Timeline Visualization**: Chronological attack pattern analysis
- **Device Activity Heatmaps**: Visual representation of device activity patterns
- **Risk Assessment Charts**: Graphical risk scoring and trend analysis
- **Network Traffic Visualization**: Protocol usage and traffic pattern charts

### Forensic Reporting
- **Comprehensive Reports**: Detailed forensic analysis reports (HTML, JSON, TXT)
- **Executive Summaries**: High-level security assessment for management
- **Technical Analysis**: In-depth technical findings for security teams
- **Recommendations Engine**: Automated security improvement suggestions
- **Evidence Documentation**: Forensically sound evidence collection and documentation

## 🏗️ Architecture

### Front-end Components
- **Security Dashboard**: Real-time monitoring interface
- **Log Viewer**: Advanced log inspection and filtering
- **Alert System**: Automated threat notification system
- **Visualization Tools**: Interactive charts and graphs
- **Report Generator**: Comprehensive forensic report creation

### Back-end Services
- **Log Collection**: Multi-protocol IoT log ingestion
- **Log Processing**: Real-time analysis and classification
- **ML Engine**: Anomaly detection and pattern recognition
- **Network Analyzer**: Traffic inspection and protocol analysis
- **Alert System**: Intelligent threat detection and notification
- **Forensic Reporter**: Comprehensive analysis and documentation

### Database Layer
- **Log Storage**: Structured log data with full-text search
- **Device Registry**: IoT device inventory and metadata
- **Alert Management**: Security incident tracking
- **Analytics Storage**: Historical analysis and metrics

## 🛠️ Technology Stack

### Backend Technologies
- **Python 3.8+**: Core development language
- **Flask**: Web framework and API development
- **SQLite**: Database for log storage and analysis
- **scikit-learn**: Machine learning and anomaly detection
- **pandas/numpy**: Data analysis and manipulation

### Frontend & Visualization
- **HTML/CSS/JavaScript**: Web interface
- **Chart.js**: Interactive data visualization
- **Bootstrap**: Responsive UI framework
- **matplotlib/seaborn**: Statistical visualization

### Machine Learning & Analysis
- **Isolation Forest**: Anomaly detection algorithm
- **TF-IDF Vectorization**: Text analysis for log messages
- **Time Series Analysis**: Temporal pattern recognition
- **Statistical Analysis**: Correlation and trend analysis

## 📊 Machine Learning Implementation

### Anomaly Detection
- **Algorithm**: Isolation Forest with contamination parameter tuning
- **Features**: Message length, temporal patterns, severity scores, device behavior
- **Training**: Automated model training on historical log data
- **Prediction**: Real-time anomaly scoring and classification

### Pattern Recognition
- **Attack Signatures**: Regex-based attack pattern matching
- **Behavior Analysis**: Device-specific normal behavior modeling
- **Network Analysis**: Protocol-specific anomaly detection
- **Risk Scoring**: Multi-factor risk assessment algorithm

## 🚦 Getting Started

### 1. Installation & Setup
```bash
# Clone the repository
git clone <repository-url>
cd IoT-Device-Log-Forensic

# Install dependencies
pip install -r requirements.txt

# Initialize database
python app.py --mode generate-data
```

### 2. Generate Sample Data (For Testing)
```bash
# Populate with realistic IoT logs
python app.py --mode generate-data
```

### 3. Start the System
```bash
# Start API server (recommended)
python app.py --mode api --host 0.0.0.0 --port 5000

# Or start CLI dashboard
python app.py --mode cli

# Or start API client
python app.py --mode client
```

### 4. Access the Dashboard
- **Web Dashboard**: http://localhost:5000/dashboard
- **API Documentation**: http://localhost:5000/api/
- **Health Check**: http://localhost:5000/health

## 📡 API Endpoints

### Core Endpoints
- `GET /api/logs` - Retrieve device logs with filtering
- `GET /api/devices` - List monitored IoT devices  
- `GET /api/alerts` - Security alerts and incidents
- `GET /api/analytics` - System analytics and metrics

### Advanced Features
- `GET /api/real-time/monitor` - Real-time monitoring status
- `POST /api/real-time/start` - Start real-time monitoring
- `GET /api/network/analysis` - Network traffic analysis
- `POST /api/reports/forensic` - Generate forensic reports
- `POST /api/anomalies/detect` - Run anomaly detection
- `GET /api/security/score/<device_id>` - Device risk assessment

### Forensic Analysis
- `GET /api/logs/correlation` - Log correlation analysis
- `GET /api/visualization/dashboard` - Dashboard data
- `POST /api/ml/train` - Train ML models
- `GET /api/features` - Available system features

## 🔍 Forensic Analysis Capabilities

### Log Correlation & Time Synchronization
- **Temporal Correlation**: Event correlation within time windows
- **Device Correlation**: Cross-device incident analysis
- **Attack Chain Reconstruction**: Multi-stage attack identification
- **Evidence Timeline**: Chronological evidence documentation

### Network Traffic Analysis  
- **Protocol Inspection**: Deep packet inspection for IoT protocols
- **Traffic Pattern Analysis**: Abnormal traffic detection
- **Bandwidth Analysis**: Data exfiltration detection
- **Geographic Analysis**: Location-based threat assessment

### Attack Detection & Classification
- **DDoS Detection**: Distributed denial of service identification
- **Brute Force Detection**: Authentication attack recognition
- **Malware Analysis**: Malicious payload identification
- **Data Exfiltration**: Unauthorized data transfer detection

## 📈 Use Cases & Applications

### Smart City Infrastructure
- **Traffic Management**: Monitor traffic control systems for tampering
- **Environmental Monitoring**: Detect sensor data manipulation
- **Public Safety**: Surveillance system security analysis
- **Utility Management**: Smart grid and lighting security

### Security Operations
- **Incident Response**: Rapid security incident investigation
- **Threat Hunting**: Proactive threat identification
- **Compliance Reporting**: Regulatory compliance documentation
- **Risk Assessment**: Infrastructure vulnerability assessment

### Research & Development
- **Security Research**: IoT security pattern analysis
- **Algorithm Development**: ML model improvement and testing
- **Threat Intelligence**: Attack pattern documentation
- **Academic Studies**: Smart city security research

## 🎓 Academic Relevance

### Degree Program Alignment
- **Digital Forensics**: Evidence collection and analysis methodologies
- **Cybersecurity**: Threat detection and incident response
- **IoT Security**: Device-specific security challenges
- **Data Analytics**: Big data analysis and pattern recognition
- **Network Security**: Protocol analysis and traffic inspection

### Research Contributions
- **Novel Approach**: IoT-specific forensic framework
- **ML Integration**: Advanced anomaly detection for IoT logs
- **Smart City Focus**: Infrastructure-specific security analysis
- **Practical Implementation**: Real-world applicable solution

## 📋 Future Enhancements

### Planned Features
- **ELK Stack Integration**: Elasticsearch, Logstash, Kibana integration
- **Splunk Compatibility**: Enterprise SIEM integration
- **Wireshark Integration**: Deep packet analysis capabilities
- **Advanced ML Models**: Deep learning and neural networks
- **Blockchain Evidence**: Immutable evidence storage

### Scalability Improvements
- **Distributed Processing**: Multi-node log processing
- **Cloud Integration**: AWS/Azure cloud deployment
- **Real-time Streaming**: Apache Kafka integration
- **High Availability**: Redundant system architecture

## 🤝 Contributing

This is an academic project for Final Year Project (FYP) submission. Contributions, suggestions, and feedback are welcome for educational purposes.

## 📄 License

This project is developed for academic purposes as part of a Final Year Project in Cybersecurity and Digital Forensics.

## 📞 Contact

For academic inquiries or collaboration opportunities related to IoT security research, please contact through the institution's official channels.

---

**Note**: This system is designed for educational and research purposes. For production deployment, additional security hardening and compliance measures should be implemented.
