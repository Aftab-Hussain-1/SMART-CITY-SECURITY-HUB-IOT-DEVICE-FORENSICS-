// Camera Integration and Device Authentication JavaScript

let cameras = [];
let isMonitoring = false;
let deviceSessions = [];

class CameraManager {
    constructor() {
        this.cameras = {};
        this.isMonitoring = false;
    }

    async addCamera(cameraData) {
        try {
            const response = await fetch('/api/cameras', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(cameraData)
            });

            const result = await response.json();

            if (result.status === 'success') {
                this.showNotification('Camera added successfully', 'success');
                this.loadCameras();
            } else {
                this.showNotification('Failed to add camera: ' + result.message, 'error');
            }
        } catch (error) {
            this.showNotification('Error adding camera: ' + error.message, 'error');
        }
    }

    async loadCameras() {
        try {
            const response = await fetch('/api/cameras');
            const result = await response.json();

            if (result.status === 'success') {
                this.cameras = result.data;
                this.updateCameraList();
            }
        } catch (error) {
            console.error('Error loading cameras:', error);
        }
    }

    async startMonitoring() {
        try {
            const response = await fetch('/api/cameras/start', {
                method: 'POST'
            });

            const result = await response.json();

            if (result.status === 'success') {
                this.isMonitoring = true;
                this.showNotification('Camera monitoring started', 'success');
                this.updateMonitoringStatus();
            }
        } catch (error) {
            this.showNotification('Error starting monitoring: ' + error.message, 'error');
        }
    }

    async stopMonitoring() {
        try {
            const response = await fetch('/api/cameras/stop', {
                method: 'POST'
            });

            const result = await response.json();

            if (result.status === 'success') {
                this.isMonitoring = false;
                this.showNotification('Camera monitoring stopped', 'info');
                this.updateMonitoringStatus();
            }
        } catch (error) {
            this.showNotification('Error stopping monitoring: ' + error.message, 'error');
        }
    }

    updateCameraList() {
        const cameraList = document.getElementById('camera-list');
        if (!cameraList) return;

        cameraList.innerHTML = '';
        updateDeviceStatusGrid();

        Object.entries(this.cameras).forEach(([cameraId, camera]) => {
            const cameraCard = document.createElement('div');
            cameraCard.className = 'camera-card glass-card rounded-xl p-4 mb-4';

            // Determine camera status with better logic
            const isOnline = camera.is_connected && camera.frame_count > 0;
            const statusText = isOnline ? '🟢 Online' : 
                              camera.frame_count > 0 ? '🟡 Connecting' : '🔴 Offline';
            const statusClass = isOnline ? 'status-online' : 
                               camera.frame_count > 0 ? 'status-warning' : 'status-offline';

            cameraCard.innerHTML = `
                <div class="flex items-center justify-between mb-3">
                    <h4 class="text-lg font-semibold text-gray-200">${camera.name}</h4>
                    <span class="status-indicator ${statusClass}">
                        ${statusText}
                    </span>
                </div>
                <div class="camera-info text-sm text-gray-400">
                    <p>📍 Location: ${camera.location}</p>
                    <p>🌐 IP: ${camera.ip_address || 'Unknown'}</p>
                    <p>📊 Frames: ${camera.frame_count}</p>
                    <p>🕒 Last Frame: ${new Date(camera.last_frame_time).toLocaleString()}</p>
                    ${camera.resolution ? `<p>📐 Resolution: ${camera.resolution}</p>` : ''}
                </div>
                <div class="camera-controls mt-3">
                    <button onclick="cameraManager.viewCameraFeed('${cameraId}')" 
                            class="btn btn-primary mr-2" ${!isOnline ? 'disabled' : ''}>View Feed</button>
                    <button onclick="cameraManager.showCameraLogs('${cameraId}')" 
                            class="btn btn-secondary mr-2">View Logs</button>
                    <button onclick="cameraManager.refreshCameraStatus('${cameraId}')" 
                            class="btn btn-info">🔄 Refresh Status</button>
                </div>
            `;

            cameraList.appendChild(cameraCard);
        });
    }

    updateMonitoringStatus() {
        const statusElement = document.getElementById('monitoring-status');
        if (statusElement) {
            statusElement.innerHTML = `
                <span class="status-indicator ${this.isMonitoring ? 'status-online' : 'status-offline'}">
                    ${this.isMonitoring ? '🟢 Monitoring Active' : '🔴 Monitoring Stopped'}
                </span>
            `;
        }
    }

    viewCameraFeed(cameraId) {
        const camera = this.cameras[cameraId];
        if (!camera) return;

        const modal = document.createElement('div');
        modal.className = 'camera-modal fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center z-50';

        modal.innerHTML = `
            <div class="modal-content bg-gray-800 rounded-xl p-6 max-w-4xl max-h-full overflow-auto">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-xl font-semibold text-gray-200">Camera Feed: ${camera.name}</h3>
                    <button onclick="this.closest('.camera-modal').remove()" 
                            class="text-gray-400 hover:text-white text-2xl">&times;</button>
                </div>
                <div class="camera-feed-container">
                    <img id="camera-stream-${cameraId}" 
                         src="/api/cameras/${cameraId}/frame" 
                         alt="Camera Feed" 
                         class="w-full h-auto rounded-lg"
                         style="max-height: 500px; object-fit: contain;">
                </div>
                <div class="camera-controls mt-4">
                    <button onclick="cameraManager.refreshFeed('${cameraId}')" 
                            class="btn btn-primary">Refresh</button>
                </div>
            </div>
        `;

        document.body.appendChild(modal);

        // Auto-refresh feed every 5 seconds
        const refreshInterval = setInterval(() => {
            this.refreshFeed(cameraId);
        }, 5000);

        // Clean up interval when modal is closed
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                clearInterval(refreshInterval);
                modal.remove();
            }
        });
    }

    refreshFeed(cameraId) {
        const img = document.getElementById(`camera-stream-${cameraId}`);
        if (img) {
            img.src = `/api/cameras/${cameraId}/frame?t=${Date.now()}`;
        }
    }

    showCameraLogs(cameraId) {
        const camera = this.cameras[cameraId];
        if (!camera) return;

        // Filter logs in the main log table to show only camera-related logs
        const deviceFilter = document.getElementById('device-filter');
        const searchInput = document.getElementById('log-search');

        if (deviceFilter) {
            // Try to find camera in device filter options
            for (let option of deviceFilter.options) {
                if (option.textContent.toLowerCase().includes('camera') || 
                    option.textContent.includes(camera.name)) {
                    deviceFilter.value = option.value;
                    break;
                }
            }
        }

        if (searchInput) {
            searchInput.value = camera.name;
        }

        // Trigger log update
        if (typeof updateLogTable === 'function') {
            updateLogTable();
        }

        // Scroll to log section
        const logSection = document.querySelector('#log-entries').closest('.glass-card');
        if (logSection) {
            logSection.scrollIntoView({ behavior: 'smooth' });
        }

        this.showNotification(`Filtered logs for camera: ${camera.name}`, 'info');
    }

    async refreshCameraStatus(cameraId) {
        try {
            const response = await fetch('/api/cameras');
            const result = await response.json();

            if (result.status === 'success') {
                this.cameras = result.data;
                this.updateCameraList();
                this.showNotification('Camera status refreshed', 'success');
            }
        } catch (error) {
            this.showNotification('Error refreshing camera status: ' + error.message, 'error');
        }
    }

    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification fixed top-4 right-4 z-50 p-4 rounded-lg text-white ${
            type === 'success' ? 'bg-green-600' : 
            type === 'error' ? 'bg-red-600' : 
            type === 'warning' ? 'bg-yellow-600' : 'bg-blue-600'
        }`;

        notification.textContent = message;
        document.body.appendChild(notification);

        setTimeout(() => {
            notification.remove();
        }, 5000);
    }

    showAddCameraModal() {
        const modal = document.createElement('div');
        modal.className = 'camera-modal fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center z-50';

        modal.innerHTML = `
            <div class="modal-content bg-gray-800 rounded-xl p-6 max-w-md w-full mx-4">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-xl font-semibold text-gray-200">Add IP Camera</h3>
                    <button onclick="this.closest('.camera-modal').remove()" 
                            class="text-gray-400 hover:text-white text-2xl">&times;</button>
                </div>
                <form onsubmit="cameraManager.handleAddCamera(event)">
                    <div class="mb-4">
                        <label class="block text-gray-300 text-sm font-medium mb-2">Camera ID</label>
                        <input type="text" name="camera_id" required 
                               class="input-field w-full" placeholder="cam001">
                    </div>
                    <div class="mb-4">
                        <label class="block text-gray-300 text-sm font-medium mb-2">Camera Name</label>
                        <input type="text" name="camera_name" required 
                               class="input-field w-full" placeholder="Main Entrance Camera">
                    </div>
                    <div class="mb-4">
                        <label class="block text-gray-300 text-sm font-medium mb-2">Camera URL</label>
                        <input type="text" name="camera_url" required 
                               class="input-field w-full" placeholder="rtsp://192.168.1.100:554/stream">
                    </div>
                    <div class="mb-4">
                        <label class="block text-gray-300 text-sm font-medium mb-2">Location</label>
                        <input type="text" name="location" 
                               class="input-field w-full" placeholder="Building A - Entrance">
                    </div>
                    <div class="flex gap-3">
                        <button type="submit" class="btn btn-primary flex-1">Add Camera</button>
                        <button type="button" onclick="this.closest('.camera-modal').remove()" 
                                class="btn btn-secondary flex-1">Cancel</button>
                    </div>
                </form>
            </div>
        `;

        document.body.appendChild(modal);
    }

    handleAddCamera(event) {
        event.preventDefault();

        const formData = new FormData(event.target);
        const cameraData = {
            camera_id: formData.get('camera_id'),
            camera_name: formData.get('camera_name'),
            camera_url: formData.get('camera_url'),
            location: formData.get('location') || 'Unknown'
        };

        this.addCamera(cameraData);
        event.target.closest('.camera-modal').remove();
    }
}

// Sensor Management Class
class SensorManager {
    constructor() {
        this.sensors = {};
        this.sensorTypes = [
            'Temperature Sensor',
            'Humidity Sensor', 
            'Air Quality Sensor',
            'Motion Detector',
            'Light Sensor',
            'Pressure Sensor',
            'Sound Sensor',
            'Proximity Sensor'
        ];
    }

    showAddSensorModal() {
        const modal = document.createElement('div');
        modal.className = 'sensor-modal fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center z-50';

        modal.innerHTML = `
            <div class="modal-content bg-white rounded-xl p-6 max-w-md w-full mx-4">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-xl font-semibold text-slate-700">Add New Sensor</h3>
                    <button onclick="this.closest('.sensor-modal').remove()" 
                            class="text-slate-400 hover:text-slate-600 text-2xl">&times;</button>
                </div>
                <form onsubmit="sensorManager.handleAddSensor(event)">
                    <div class="mb-4">
                        <label class="block text-slate-600 text-sm font-medium mb-2">Sensor Name</label>
                        <input type="text" name="sensor_name" required 
                               class="input-field w-full" placeholder="Temperature Sensor 01">
                    </div>
                    <div class="mb-4">
                        <label class="block text-slate-600 text-sm font-medium mb-2">Sensor Type</label>
                        <select name="sensor_type" required class="input-field w-full">
                            ${this.sensorTypes.map(type => 
                                `<option value="${type}">${type}</option>`
                            ).join('')}
                        </select>
                    </div>
                    <div class="mb-4">
                        <label class="block text-slate-600 text-sm font-medium mb-2">Location</label>
                        <input type="text" name="location" 
                               class="input-field w-full" placeholder="Building A - Room 101">
                    </div>
                    <div class="mb-4">
                        <label class="block text-slate-600 text-sm font-medium mb-2">IP Address</label>
                        <input type="text" name="ip_address" 
                               class="input-field w-full" placeholder="192.168.1.100">
                    </div>
                    <div class="flex gap-3">
                        <button type="submit" class="btn btn-primary flex-1">Add Sensor</button>
                        <button type="button" onclick="this.closest('.sensor-modal').remove()" 
                                class="btn btn-secondary flex-1">Cancel</button>
                    </div>
                </form>
            </div>
        `;

        document.body.appendChild(modal);
    }

    handleAddSensor(event) {
        event.preventDefault();

        const formData = new FormData(event.target);
        const sensorData = {
            name: formData.get('sensor_name'),
            type: formData.get('sensor_type'),
            location: formData.get('location') || 'Unknown',
            ip_address: formData.get('ip_address') || 'N/A',
            status: Math.random() > 0.2 ? 'online' : 'offline',
            last_reading: new Date().toLocaleString(),
            value: this.generateSensorReading(formData.get('sensor_type'))
        };

        const sensorId = `sensor_${Date.now()}`;
        this.sensors[sensorId] = sensorData;

        this.updateSensorGrid();
        this.showNotification(`Sensor ${sensorData.name} added successfully!`, 'success');
        event.target.closest('.sensor-modal').remove();
    }

    generateSensorReading(sensorType) {
        const readings = {
            'Temperature Sensor': Math.floor(Math.random() * 40) + 15 + '°C',
            'Humidity Sensor': Math.floor(Math.random() * 60) + 20 + '%',
            'Air Quality Sensor': Math.floor(Math.random() * 300) + 50 + ' AQI',
            'Motion Detector': Math.random() > 0.5 ? 'Motion Detected' : 'No Motion',
            'Light Sensor': Math.floor(Math.random() * 1000) + ' Lux',
            'Pressure Sensor': Math.floor(Math.random() * 200) + 1000 + ' hPa',
            'Sound Sensor': Math.floor(Math.random() * 80) + 20 + ' dB',
            'Proximity Sensor': Math.floor(Math.random() * 200) + ' cm'
        };
        return readings[sensorType] || 'N/A';
    }

    updateSensorGrid() {
        const sensorGrid = document.getElementById('sensor-grid');
        if (!sensorGrid) return;

        sensorGrid.innerHTML = '';

        // Add default sensors if none exist
        if (Object.keys(this.sensors).length === 0) {
            this.addDefaultSensors();
        }

        Object.entries(this.sensors).forEach(([sensorId, sensor]) => {
            const sensorCard = document.createElement('div');
            sensorCard.className = `sensor-card ${sensor.status}`;

            sensorCard.innerHTML = `
                <div class="flex items-center justify-between mb-3">
                    <h4 class="text-lg font-semibold text-slate-700">${sensor.name}</h4>
                    <span class="status-indicator status-${sensor.status}">
                        ${sensor.status === 'online' ? '🟢 Online' : '🔴 Offline'}
                    </span>
                </div>
                <div class="sensor-info text-sm text-slate-600 space-y-2">
                    <p><strong>Type:</strong> ${sensor.type}</p>
                    <p><strong>Location:</strong> ${sensor.location}</p>
                    <p><strong>IP:</strong> ${sensor.ip_address}</p>
                    <p><strong>Current Reading:</strong> <span class="font-semibold text-blue-600">${sensor.value}</span></p>
                    <p><strong>Last Update:</strong> ${sensor.last_reading}</p>
                </div>
                <div class="sensor-controls mt-3 flex gap-2">
                    <button onclick="sensorManager.viewSensorData('${sensorId}')" 
                            class="btn btn-primary text-xs px-3 py-1">View Data</button>
                    <button onclick="sensorManager.calibrateSensor('${sensorId}')" 
                            class="btn btn-secondary text-xs px-3 py-1">Calibrate</button>
                </div>
            `;

            sensorGrid.appendChild(sensorCard);
        });
    }

    addDefaultSensors() {
        const defaultSensors = [
            { name: 'Main Street Temp Sensor', type: 'Temperature Sensor', location: 'Main Street Junction', ip: '192.168.1.50' },
            { name: 'City Hall Air Quality', type: 'Air Quality Sensor', location: 'City Hall Entrance', ip: '192.168.1.51' },
            { name: 'Park Motion Detector', type: 'Motion Detector', location: 'Central Park', ip: '192.168.1.52' },
            { name: 'Bridge Humidity Sensor', type: 'Humidity Sensor', location: 'Main Bridge', ip: '192.168.1.53' },
            { name: 'Stadium Light Sensor', type: 'Light Sensor', location: 'Sports Stadium', ip: '192.168.1.54' },
            { name: 'Mall Sound Monitor', type: 'Sound Sensor', location: 'Shopping Mall', ip: '192.168.1.55' }
        ];

        defaultSensors.forEach((sensor, index) => {
            const sensorId = `default_sensor_${index}`;
            this.sensors[sensorId] = {
                ...sensor,
                status: Math.random() > 0.15 ? 'online' : 'offline',
                last_reading: new Date(Date.now() - Math.random() * 3600000).toLocaleString(),
                value: this.generateSensorReading(sensor.type)
            };
        });
    }

    refreshSensors() {
        Object.keys(this.sensors).forEach(sensorId => {
            this.sensors[sensorId].last_reading = new Date().toLocaleString();
            this.sensors[sensorId].value = this.generateSensorReading(this.sensors[sensorId].type);
            this.sensors[sensorId].status = Math.random() > 0.1 ? 'online' : 'offline';
        });

        this.updateSensorGrid();
        updateDeviceStatusGrid();
        this.showNotification('Sensor data refreshed successfully!', 'success');
    }

    viewSensorData(sensorId) {
        const sensor = this.sensors[sensorId];
        if (!sensor) return;

        const modal = document.createElement('div');
        modal.className = 'sensor-modal fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center z-50';

        modal.innerHTML = `
            <div class="modal-content bg-white rounded-xl p-6 max-w-2xl max-h-full overflow-auto">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-xl font-semibold text-slate-700">Sensor Data: ${sensor.name}</h3>
                    <button onclick="this.closest('.sensor-modal').remove()" 
                            class="text-slate-400 hover:text-slate-600 text-2xl">&times;</button>
                </div>
                <div class="sensor-data-view space-y-4">
                    <div class="grid grid-cols-2 gap-4">
                        <div class="p-4 bg-slate-50 rounded-lg">
                            <h4 class="font-semibold text-slate-700">Current Reading</h4>
                            <p class="text-2xl font-bold text-blue-600">${sensor.value}</p>
                        </div>
                        <div class="p-4 bg-slate-50 rounded-lg">
                            <h4 class="font-semibold text-slate-700">Status</h4>
                            <p class="text-lg capitalize font-semibold ${sensor.status === 'online' ? 'text-green-600' : 'text-red-600'}">
                                ${sensor.status}
                            </p>
                        </div>
                    </div>
                    <div class="space-y-2">
                        <p><strong>Type:</strong> ${sensor.type}</p>
                        <p><strong>Location:</strong> ${sensor.location}</p>
                        <p><strong>IP Address:</strong> ${sensor.ip_address}</p>
                        <p><strong>Last Reading:</strong> ${sensor.last_reading}</p>
                    </div>
                </div>
                <div class="mt-6 flex justify-end">
                    <button onclick="this.closest('.sensor-modal').remove()" 
                            class="btn btn-primary">Close</button>
                </div>
            </div>
        `;

        document.body.appendChild(modal);
    }

    calibrateSensor(sensorId) {
        this.showNotification('Sensor calibration initiated...', 'info');
        setTimeout(() => {
            this.showNotification('Sensor calibration completed successfully!', 'success');
            this.refreshSensors();
        }, 2000);
    }

    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification fixed top-4 right-4 z-50 p-4 rounded-lg text-white ${
            type === 'success' ? 'bg-green-500' : 
            type === 'error' ? 'bg-red-500' : 
            type === 'warning' ? 'bg-yellow-500' : 'bg-blue-500'
        }`;

        notification.textContent = message;
        document.body.appendChild(notification);

        setTimeout(() => {
            notification.remove();
        }, 5000);
    }
}

// Initialize managers
const cameraManager = new CameraManager();
const sensorManager = new SensorManager();

// Device Overview Functions
function showDeviceOverview() {
    const modal = document.createElement('div');
    modal.className = 'sensor-modal fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center z-50';

    const totalDevices = Object.keys(sensorManager.sensors).length + Object.keys(cameraManager.cameras).length;
    const onlineDevices = Object.values(sensorManager.sensors).filter(s => s.status === 'online').length + 
                         Object.values(cameraManager.cameras).filter(c => c.is_connected).length;

    modal.innerHTML = `
        <div class="modal-content bg-white rounded-xl p-6 max-w-4xl max-h-full overflow-auto">
            <div class="flex items-center justify-between mb-6">
                <h3 class="text-2xl font-semibold text-slate-700">📊 Device Overview</h3>
                <button onclick="this.closest('.sensor-modal').remove()" 
                        class="text-slate-400 hover:text-slate-600 text-2xl">&times;</button>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
                <div class="stat-card text-center">
                    <div class="text-3xl font-bold text-blue-600">${totalDevices}</div>
                    <div class="text-sm text-slate-600 mt-2">Total Devices</div>
                </div>
                <div class="stat-card text-center">
                    <div class="text-3xl font-bold text-green-600">${onlineDevices}</div>
                    <div class="text-sm text-slate-600 mt-2">Online Devices</div>
                </div>
                <div class="stat-card text-center">
                    <div class="text-3xl font-bold text-orange-600">${totalDevices - onlineDevices}</div>
                    <div class="text-sm text-slate-600 mt-2">Offline Devices</div>
                </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div>
                    <h4 class="text-lg font-semibold mb-3">🌡️ Sensors (${Object.keys(sensorManager.sensors).length})</h4>
                    <div class="space-y-2 max-h-60 overflow-y-auto">
                        ${Object.entries(sensorManager.sensors).map(([id, sensor]) => `
                            <div class="flex justify-between items-center p-3 bg-slate-50 rounded">
                                <span class="font-medium">${sensor.name}</span>
                                <span class="text-sm ${sensor.status === 'online' ? 'text-green-600' : 'text-red-600'}">
                                    ${sensor.status === 'online' ? '🟢 Online' : '🔴 Offline'}
                                </span>
                            </div>
                        `).join('')}
                    </div>
                </div>

                <div>
                    <h4 class="text-lg font-semibold mb-3">📹 Cameras (${Object.keys(cameraManager.cameras).length})</h4>
                    <div class="space-y-2 max-h-60 overflow-y-auto">
                        ${Object.entries(cameraManager.cameras).map(([id, camera]) => `
                            <div class="flex justify-between items-center p-3 bg-slate-50 rounded">
                                <span class="font-medium">${camera.name}</span>
                                <span class="text-sm ${camera.is_connected ? 'text-green-600' : 'text-red-600'}">
                                    ${camera.is_connected ? '🟢 Online' : '🔴 Offline'}
                                </span>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        </div>
    `;

    document.body.appendChild(modal);
}

function updateDeviceStatusGrid() {
    const statusGrid = document.getElementById('device-status-grid');
    if (!statusGrid) return;

    const allDevices = [
        ...Object.entries(sensorManager.sensors).map(([id, device]) => ({
            id, ...device, type: 'sensor'
        })),
        ...Object.entries(cameraManager.cameras).map(([id, device]) => ({
            id, ...device, type: 'camera', status: device.is_connected ? 'online' : 'offline'
        }))
    ];

    if (allDevices.length === 0) {
        statusGrid.innerHTML = `
            <div class="col-span-full text-center py-8 text-slate-500">
                <div class="text-4xl mb-4">📱</div>
                <p>No devices deployed yet. Start by adding sensors or cameras.</p>
            </div>
        `;
        return;
    }

    statusGrid.innerHTML = allDevices.map(device => `
        <div class="device-card p-4 bg-white rounded-xl border-2 border-slate-200 hover:border-blue-300 transition-all duration-300 hover:shadow-lg transform hover:-translate-y-1">
            <div class="flex items-center justify-between mb-3">
                <div class="flex items-center space-x-2">
                    <span class="text-2xl">${device.type === 'sensor' ? '🌡️' : '📹'}</span>
                    <h4 class="text-lg font-semibold text-slate-700">${device.name}</h4>
                </div>
                <span class="status-indicator px-3 py-1 rounded-full text-xs font-semibold ${device.status === 'online' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}">
                    ${device.status === 'online' ? '🟢 ONLINE' : '🔴 OFFLINE'}
                </span>
            </div>

            <div class="space-y-2 text-sm">
                <div class="flex justify-between">
                    <span class="text-slate-500">Type:</span>
                    <span class="font-medium text-slate-700">${device.type === 'sensor' ? device.type : 'Camera'}</span>
                </div>
                <div class="flex justify-between">
                    <span class="text-slate-500">Location:</span>
                    <span class="font-medium text-slate-700">${device.location}</span>
                </div>
                <div class="flex justify-between">
                    <span class="text-slate-500">IP:</span>
                    <span class="font-mono text-xs text-slate-600">${device.ip_address || device.url || 'Unknown'}</span>
                </div>
                ${device.type === 'sensor' ? `
                    <div class="pt-2 border-t border-slate-100">
                        <div class="flex justify-between items-center">
                            <span class="text-slate-500">Current Reading:</span>
                            <span class="font-bold text-blue-600">${device.value}</span>
                        </div>
                        <div class="flex justify-between text-xs mt-1">
                            <span class="text-slate-400">Last Update:</span>
                            <span class="text-slate-500">${device.last_reading}</span>
                        </div>
                    </div>
                ` : `
                    <div class="pt-2 border-t border-slate-100">
                        <div class="flex justify-between text-xs">
                            <span class="text-slate-400">Resolution:</span>
                            <span class="text-slate-500">${device.resolution || 'Not specified'}</span>
                        </div>
                    </div>
                `}
            </div>

            <div class="mt-4 flex gap-2">
                ${device.type === 'sensor' ? `
                    <button onclick="sensorManager.viewSensorData('${device.id}')" 
                            class="flex-1 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold py-2 px-3 rounded-lg transition-colors">
                        VIEW DATA
                    </button>
                    <button onclick="sensorManager.calibrateSensor('${device.id}')" 
                            class="flex-1 bg-slate-600 hover:bg-slate-700 text-white text-xs font-semibold py-2 px-3 rounded-lg transition-colors">
                        CALIBRATE
                    </button>
                ` : `
                    <button onclick="cameraManager.viewCameraFeed('${device.id}')" 
                            class="flex-1 bg-green-600 hover:bg-green-700 text-white text-xs font-semibold py-2 px-3 rounded-lg transition-colors">
                        VIEW STREAM
                    </button>
                    <button onclick="cameraManager.toggleCamera('${device.id}')" 
                            class="flex-1 bg-orange-600 hover:bg-orange-700 text-white text-xs font-semibold py-2 px-3 rounded-lg transition-colors">
                        ${device.status === 'online' ? 'STOP' : 'START'}
                    </button>
                `}
            </div>
        </div>
    `).join('');
}

// Load cameras and sensors when page loads
document.addEventListener('DOMContentLoaded', () => {
    // Check if we're on the main dashboard
    const appContainer = document.getElementById('app-container');
    const authContainer = document.getElementById('auth-container');

    // Only initialize dashboard components if we're on the dashboard
    if (appContainer && !appContainer.classList.contains('hidden')) {
        cameraManager.loadCameras();
        sensorManager.updateSensorGrid();
        updateDeviceStatusGrid();

        // Add your specific IP camera automatically
        setTimeout(() => {
            const yourCameraData = {
                camera_id: 'main_security_cam',
                camera_name: 'Main Security Camera',
                camera_url: 'http://192.168.23.103:8080/video',
                location: 'Main Building Entrance'
            };

            cameraManager.addCamera(yourCameraData);
            cameraManager.showNotification('Your IP camera (192.168.23.103) has been integrated successfully!', 'success');
        }, 1000);

        // Initialize monitoring status
        cameraManager.updateMonitoringStatus();

        // Load device sessions
        loadDeviceSessions();

        // Setup device authentication form
        setupDeviceAuth();

        // Auto-refresh camera status every 30 seconds
        setInterval(() => {
            if (cameraManager.cameras && Object.keys(cameraManager.cameras).length > 0) {
                cameraManager.loadCameras();
            }
        }, 30000);
    }
});


// Device Authentication Functions
function setupDeviceAuth() {
    // Only add device registration form on the main dashboard (not login page)
    const appContainer = document.getElementById('app-container');
    const authContainer = document.getElementById('auth-container');

    // Check if we're on the main dashboard and not on the login page
    if (!appContainer || authContainer && !authContainer.classList.contains('hidden')) {
        return; // Don't add auth section on login page
    }

    // Add device registration form after camera section
    const cameraSection = document.querySelector('.glass-card');
    if (cameraSection) {
        const authSection = document.createElement('div');
        authSection.className = 'glass-card rounded-2xl overflow-hidden mb-8';
        authSection.innerHTML = `
            <div class="px-6 py-6 border-b border-gray-700">
                <h3 class="text-xl font-semibold text-gray-200 flex items-center">
                    🔐 Device Authentication
                </h3>
            </div>
            <div class="p-6 space-y-4">
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                        <label class="block text-sm text-gray-300 mb-2">Device Name</label>
                        <input type="text" id="deviceName" class="w-full px-3 py-2 bg-gray-700 text-white rounded border border-gray-600">
                    </div>
                    <div>
                        <label class="block text-sm text-gray-300 mb-2">Device Type</label>
                        <select id="deviceType" class="w-full px-3 py-2 bg-gray-700 text-white rounded border border-gray-600">
                            <option value="IoT Sensor">IoT Sensor</option>
                            <option value="Smart Camera">Smart Camera</option>
                            <option value="Environmental Monitor">Environmental Monitor</option>
                            <option value="Traffic Controller">Traffic Controller</option>
                            <option value="Security System">Security System</option>
                        </select>
                    </div>
                    <div>
                        <label class="block text-sm text-gray-300 mb-2">Username</label>
                        <input type="text" id="deviceUsername" class="w-full px-3 py-2 bg-gray-700 text-white rounded border border-gray-600">
                    </div>
                    <div>
                        <label class="block text-sm text-gray-300 mb-2">Password</label>
                        <input type="password" id="devicePassword" class="w-full px-3 py-2 bg-gray-700 text-white rounded border border-gray-600">
                    </div>
                </div>
                <div class="flex space-x-4">
                    <button onclick="registerDevice()" class="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700">
                        Register Device
                    </button>
                    <button onclick="simulateDeviceLogin()" class="px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700">
                        Simulate Login
                    </button>
                    <button onclick="generateAuthActivity()" class="px-4 py-2 bg-purple-600 text-white rounded hover:bg-purple-700">
                        Generate Activity
                    </button>
                </div>
                <div id="authStatus" class="mt-4"></div>
                <div id="activeSessions" class="mt-4"></div>
            </div>
        `;

        cameraSection.parentNode.insertBefore(authSection, cameraSection.nextSibling);
    }
}

async function registerDevice() {
    const deviceName = document.getElementById('deviceName').value;
    const deviceType = document.getElementById('deviceType').value;
    const username = document.getElementById('deviceUsername').value;
    const password = document.getElementById('devicePassword').value;

    if (!deviceName || !username || !password) {
        showAuthStatus('Please fill in all required fields', 'error');
        return;
    }

    try {
        const response = await fetch('/api/auth/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                device_name: deviceName,
                device_type: deviceType,
                location: 'IoT Network',
                username: username,
                password: password
            })
        });

        const data = await response.json();

        if (data.success) {
            showAuthStatus(`Device ${deviceName} registered successfully!`, 'success');
            // Clear form
            document.getElementById('deviceName').value = '';
            document.getElementById('deviceUsername').value = '';
            document.getElementById('devicePassword').value = '';
            // Reload logs to show registration event
            window.loadLogs && window.loadLogs();
        } else {
            showAuthStatus(`Registration failed: ${data.message}`, 'error');
        }
    } catch (error) {
        showAuthStatus(`Error: ${error.message}`, 'error');
    }
}

async function simulateDeviceLogin() {
    const username = document.getElementById('deviceUsername').value;
    const password = document.getElementById('devicePassword').value;

    if (!username || !password) {
        showAuthStatus('Please enter username and password to simulate login', 'error');
        return;
    }

    try {
        const response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username: username,
                password: password
            })
        });

        const data = await response.json();

        if (data.success) {
            showAuthStatus(`Device ${data.device_name} logged in successfully!`, 'success');
            loadDeviceSessions();
            window.loadLogs && window.loadLogs();
        } else {
            showAuthStatus(`Login failed: ${data.message}`, 'error');
        }
    } catch (error) {
        showAuthStatus(`Error: ${error.message}`, 'error');
    }
}

async function generateAuthActivity() {
    try {
        const response = await fetch('/api/auth/simulate-activity', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ count: 10 })
        });

        const data = await response.json();

        if (data.success) {
            showAuthStatus(`Generated ${data.activities.length} authentication activities`, 'success');
            window.loadLogs && window.loadLogs();
        } else {
            showAuthStatus(`Failed to generate activity: ${data.message}`, 'error');
        }
    } catch (error) {
        showAuthStatus(`Error: ${error.message}`, 'error');
    }
}

async function loadDeviceSessions() {
    try {
        const response = await fetch('/api/auth/sessions');
        const data = await response.json();

        if (data.success && data.sessions) {
            displayActiveSessions(data.sessions);
        }
    } catch (error) {
        console.error('Error loading device sessions:', error);
    }
}

function displayActiveSessions(sessions) {
    const container = document.getElementById('activeSessions');
    if (!container) return;

    if (sessions.length === 0) {
        container.innerHTML = '<p class="text-gray-400">No active device sessions</p>';
        return;
    }

    container.innerHTML = `
        <h4 class="text-lg font-medium text-gray-200 mb-3">Active Device Sessions (${sessions.length})</h4>
        <div class="space-y-2">
            ${sessions.map(session => `
                <div class="flex justify-between items-center p-3 bg-gray-700 rounded">
                    <div>
                        <span class="text-white font-medium">${session.device_name}</span>
                        <span class="text-gray-400 text-sm ml-2">${session.ip_address}</span>
                    </div>
                    <span class="text-green-400 text-sm">${new Date(session.login_time).toLocaleTimeString()}</span>
                </div>
            `).join('')}
        </div>
    `;
}

function showAuthStatus(message, type) {
    const statusDiv = document.getElementById('authStatus');
    if (statusDiv) {
        statusDiv.className = `p-3 rounded ${type === 'success' ? 'bg-green-600' : 'bg-red-600'} text-white`;
        statusDiv.textContent = message;

        setTimeout(() => {
            statusDiv.textContent = '';
            statusDiv.className = '';
        }, 5000);
    }
}