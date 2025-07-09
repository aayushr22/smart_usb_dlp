const socket = io();
let isConnected = false;

// Socket.io connection handlers
socket.on('connect', () => {
    updateConnectionStatus(true);
    socket.emit('get_devices');
});

socket.on('disconnect', () => {
    updateConnectionStatus(false);
});

socket.on('connect_error', (error) => {
    updateConnectionStatus(false);
    showConnectionError('Failed to connect to server. Please check if the server is running.');
});

socket.on('usb_event', (data) => {
    addDeviceToList(data, true);
    updateStats();
    updateLastUpdated();
});

socket.on('device_list', (data) => {
    renderDeviceList(data.devices || []);
    updateStats();
    updateLastUpdated();
});

// connection status indicator
function updateConnectionStatus(connected) {
    const dot = document.getElementById('connection-dot');
    const text = document.getElementById('connection-text');
    isConnected = connected;

    if (connected) {
        dot.classList.remove('disconnected');
        text.textContent = 'Connected to DLP System';
        const errorDiv = document.querySelector('.connection-error');
        if (errorDiv) errorDiv.remove();
    } else {
        dot.classList.add('disconnected');
        text.textContent = 'Connection Lost';
    }
}

function updateLastUpdated() {
    document.getElementById('last-updated').textContent =
        'Last updated: ' + new Date().toLocaleString();
}

function showConnectionError(message) {
    const container = document.getElementById('device-container');
    container.innerHTML = `
        <div class="connection-error">
            <span style="font-size: 1.5rem;">⚠️</span>
            <div>
                <strong>Connection Error:</strong> ${message}
                <br><small>Make sure your Python server is running on port 5000</small>
            </div>
        </div>
    `;
}

// Device icon selection based on device type/name/id
function getDeviceIcon(device) {
    const deviceName = (device.name || '').toLowerCase();
    const deviceId = (device.device_id || '').toLowerCase();

    if (deviceName.includes('mtp') || deviceName.includes('phone') || deviceId.includes('phone')) {
        return 'phone';
    } else if (deviceName.includes('storage') || deviceName.includes('usb')) {
        return 'storage';
    } else if (deviceName.includes('camera')) {
        return 'camera';
    } else if (deviceName.includes('mouse')) {
        return 'mouse';
    } else if (deviceName.includes('keyboard')) {
        return 'keyboard';
    }
    return 'connected';
}

// Status
function getStatusInfo(device) {
    const deviceName = (device.name || '').toLowerCase();

    if (deviceName.includes('mtp')) {
        return { class: 'status-mtp', text: 'MTP Device' };
    } else if (deviceName.includes('unknown')) {
        return { class: 'status-alert', text: 'Unknown Device' };
    } else {
        return { class: 'status-connected', text: 'Connected' };
    }
}

function addDeviceToList(device, isNew = false) {
    const container = document.getElementById('device-container');
    const loadingDiv = container.querySelector('.loading');
    const noEventsDiv = container.querySelector('.no-events');
    if (loadingDiv) loadingDiv.remove();
    if (noEventsDiv) noEventsDiv.remove();

    const deviceIcon = getDeviceIcon(device);
    const statusInfo = getStatusInfo(device);
    const timestamp = device.timestamp || new Date().toLocaleString();

    const deviceDiv = document.createElement('div');
    deviceDiv.className = 'device-item' + (isNew ? ' new' : '');

    deviceDiv.innerHTML = `
        <div class="device-header">
            <div class="device-info">
                <div class="device-icon">${deviceIcon}</div>
                <div class="device-details">
                    <h3>${device.name || 'Unknown Device'}</h3>
                    <div class="device-id">${device.device_id || 'No ID available'}</div>
                </div>
            </div>
            <div class="device-meta">
                <div class="device-time">
                    <span></span>
                    <span>${timestamp}</span>
                </div>
                <span class="status-badge ${statusInfo.class}">
                    ${statusInfo.text}
                </span>
            </div>
        </div>
    `;

    container.insertBefore(deviceDiv, container.firstChild);

    if (isNew) {
        setTimeout(() => {
            deviceDiv.classList.remove('new');
        }, 3000);
    }
}
function renderDeviceList(devices) {
    const container = document.getElementById('device-container');
    container.innerHTML = '';

    if (!devices || devices.length === 0) {
        container.innerHTML = `
            <div class="no-events">
                <div class="icon"></div>
                <h3>No devices connected</h3>
                <p>Connect a USB device to see it appear here</p>
            </div>
        `;
        return;
    }

    devices.forEach(device => {
        addDeviceToList(device, false);
    });
}

function updateStats() {
    const devices = document.querySelectorAll('.device-item');
    const mtpDevices = document.querySelectorAll('.status-mtp');

    document.getElementById('total-devices').textContent = devices.length;
    document.getElementById('mtp-devices').textContent = mtpDevices.length;
    document.getElementById('threat-level').textContent =
        mtpDevices.length > 0 ? 'Monitor' : 'Normal';
}

function refreshDevices() {
    if (isConnected) {
        socket.emit('get_devices');
    } else {
        socket.connect();
    }
}

document.addEventListener('keydown', function(e) {
    if (e.key === 'F5' || (e.ctrlKey && e.key.toLowerCase() === 'r')) {
        e.preventDefault();
        refreshDevices();
    }
});

document.addEventListener('DOMContentLoaded', function() {
});