from flask import Flask, jsonify, render_template_string
from flask_socketio import SocketIO, emit
import json
import threading
import time
import queue
import logging

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# Global storage for USB events
usb_events = []
usb_event_queue = queue.Queue()

# HTML template
HTML_DASHBOARD = """
<!DOCTYPE html>
<html>
<head>
    <title>USB Security Monitor - Real Time</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .device-list { margin-top: 20px; }
        .device-item { 
            border: 1px solid #ddd; 
            margin: 10px 0; 
            padding: 15px; 
            border-radius: 5px; 
            background: #f9f9f9;
        }
        .device-item.new { 
            background: #d4edda; 
            border-color: #c3e6cb; 
            animation: highlight 2s ease-in-out;
        }
        @keyframes highlight { 
            0% { background: #d1ecf1; } 
            100% { background: #f9f9f9; } 
        }
        .device-name { font-weight: bold; color: #2c3e50; }
        .device-time { color: #666; font-size: 0.9em; }
        .status { 
            display: inline-block; 
            padding: 2px 8px; 
            border-radius: 3px; 
            font-size: 0.8em; 
        }
        .connected { background: #d4edda; color: #155724; }
        .mtp-detected { background: #fff3cd; color: #856404; }
        .stats { display: flex; gap: 20px; margin: 20px 0; }
        .stat-box { 
            background: white; 
            padding: 20px; 
            border-radius: 5px; 
            box-shadow: 0 2px 4px rgba(0,0,0,0.1); 
            flex: 1; 
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>USB Security Monitor</h1>
            <p>Real-time USB device detection and monitoring</p>
        </div>
        
        <div class="stats">
            <div class="stat-box">
                <h3>Total Devices</h3>
                <div id="total-devices">0</div>
            </div>
            <div class="stat-box">
                <h3>MTP Devices</h3>
                <div id="mtp-devices">0</div>
            </div>
            <div class="stat-box">
                <h3>Last Activity</h3>
                <div id="last-activity">-</div>
            </div>
        </div>
        
        <div class="device-list">
            <h2>Connected Devices</h2>
            <div id="device-container">
                <p>Waiting for USB devices...</p>
            </div>
        </div>
    </div>

    <script>
        const socket = io();
        let deviceCount = 0;
        let mtpCount = 0;
        
        socket.on('connect', function() {
            console.log('Connected to server');
            // Request current device list
            socket.emit('get_devices');
        });
        
        socket.on('usb_event', function(data) {
            console.log('USB Event:', data);
            addDeviceToList(data);
            updateStats();
        });
        
        socket.on('device_list', function(data) {
            console.log('Device list:', data);
            const container = document.getElementById('device-container');
            container.innerHTML = '';
            
            if (data.devices.length === 0) {
                container.innerHTML = '<p>No devices connected</p>';
                return;
            }
            
            data.devices.forEach(device => {
                addDeviceToList(device, false);
            });
            updateStats();
        });
        
        function addDeviceToList(device, isNew = true) {
            const container = document.getElementById('device-container');
            
            // Remove "waiting" message if it exists
            const waiting = container.querySelector('p');
            if (waiting && waiting.textContent.includes('Waiting')) {
                waiting.remove();
            }
            
            const deviceDiv = document.createElement('div');
            deviceDiv.className = 'device-item' + (isNew ? ' new' : '');
            
            const isMTP = device.name && device.name.toLowerCase().includes('mtp');
            const status = isMTP ? 'MTP Detected' : 'Connected';
            const statusClass = isMTP ? 'mtp-detected' : 'connected';
            
            deviceDiv.innerHTML = `
                <div class="device-name">${device.name || 'Unknown Device'}</div>
                <div class="device-time"> ${device.timestamp || new Date().toLocaleString()}</div>
                <span class="status ${statusClass}">${status}</span>
            `;
            
            container.insertBefore(deviceDiv, container.firstChild);
            
            // Remove highlight after animation
            if (isNew) {
                setTimeout(() => {
                    deviceDiv.classList.remove('new');
                }, 2000);
            }
        }
        
        function updateStats() {
            const devices = document.querySelectorAll('.device-item');
            const mtpDevices = document.querySelectorAll('.mtp-detected');
            
            document.getElementById('total-devices').textContent = devices.length;
            document.getElementById('mtp-devices').textContent = mtpDevices.length;
            document.getElementById('last-activity').textContent = new Date().toLocaleString();
        }
        
        // Handle connection errors
        socket.on('connect_error', function(error) {
            console.error('Connection failed:', error);
            document.getElementById('device-container').innerHTML = 
                '<p style="color: red;">Connection to server failed. Please refresh the page.</p>';
        });
    </script>
</body>
</html>
"""

@app.route('/')
def dashboard():
    return render_template_string(HTML_DASHBOARD)

@app.route('/api/devices')
def get_devices():
    return jsonify({
        'devices': usb_events,
        'count': len(usb_events),
        'timestamp': time.time()
    })

@socketio.on('connect')
def handle_connect():
    print('Client connected to dashboard')
    emit('device_list', {'devices': usb_events})

@socketio.on('get_devices')
def handle_get_devices():
    emit('device_list', {'devices': usb_events})

def add_usb_event(device_info):
    """Function to be called by USB monitor"""
    event = {
        'name': device_info.get('name', 'Unknown Device'),
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'device_id': device_info.get('device_id', ''),
        'event_type': device_info.get('event_type', 'connected')
    }
    
    usb_events.append(event)
    
    # last 50 events
    if len(usb_events) > 50:
        usb_events.pop(0)
    
    # Broadcast
    socketio.emit('usb_event', event)
    print(f"Dashboard updated with device: {event['name']}")

def start_dashboard_server():
    """Start the dashboard server"""
    print("Starting USB Dashboard Server on http://localhost:8081")
    socketio.run(app, host='0.0.0.0', port=8081, debug=False)

if __name__ == '__main__':
    start_dashboard_server()