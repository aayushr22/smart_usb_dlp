"""
Smart USB DLP System - Main Application
"""

import os
import sys
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import time
import logging
from datetime import datetime
from flask import Flask, render_template, jsonify, request, send_from_directory
from flask_socketio import SocketIO
from threading import Thread
from usb.usb_monitor import USBMonitor
from usb.usb_ml_model import USBMLModel

# logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/dlp_system.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='static', static_url_path='/static')
socketio = SocketIO(app, cors_allowed_origins="*")
usb_events = []

class USBDLPSystem:
    """Main USB Data Loss Prevention System"""

    def __init__(self):
        """Initialize the DLP system components"""
        logger.info("Initializing USB DLP System")

        # Initialize components
        self.ml_model = USBMLModel()
        self.usb_monitor = USBMonitor()
        self.event_log = []
        self.blocked_devices = set()
        self.alert_threshold = 0.85
        self.max_events = 50  # Keep last 50 events
        self.system_running = False

        logger.info("System initialization complete")

    def start_monitoring(self):
        """Start all monitoring services"""
        logger.info("Starting monitoring services")
        self.system_running = True

        # Start USB monitoring in background thread
        self.monitor_thread = Thread(target=self.monitor_usb_activity, daemon=True)
        self.monitor_thread.start()

        # Start processing events from queue
        self.processor_thread = Thread(target=self.process_events, daemon=True)
        self.processor_thread.start()

    def stop_monitoring(self):
        """Stop all monitoring services"""
        logger.info("Stopping monitoring services")
        self.system_running = False

    def monitor_usb_activity(self):
        """Monitor USB activity using USBMonitor"""
        try:
            while self.system_running:
                try:
                    if hasattr(self.usb_monitor, 'run_as_service'):
                        self.usb_monitor.run_as_service()
                    else:
                        time.sleep(1)
                except Exception as e:
                    logger.warning(f"USB monitor service error: {str(e)}")
                    time.sleep(5)
        except Exception as e:
            logger.error(f"USB monitoring failed: {str(e)}")

    def process_events(self):
        """Process events from the USB monitor"""
        while self.system_running:
            try:
                events = []
                if hasattr(self.usb_monitor, 'get_recent_events'):
                    events = self.usb_monitor.get_recent_events()

                for event in events:
                    action, score = self.process_event(event)

                    log_entry = {
                        'timestamp': datetime.now().isoformat(),
                        'event_type': event.get('event_type', 'UNKNOWN'),
                        'device_id': event.get('device_id', 'Unknown Device'),
                        'device_info': event.get('device_info', {}),
                        'action': action,
                        'score': score,
                        'bytes_transferred': event.get('bytes_transferred', 0)
                    }
                    self.event_log.append(log_entry)
                    if len(self.event_log) > self.max_events:
                        self.event_log = self.event_log[-self.max_events:]

                    socketio.emit('usb_event', log_entry)

                    logger.info(f"Processed event: {event.get('event_type', 'UNKNOWN')} - Action: {action} (Score: {score:.2f})")

                time.sleep(1)  # every second

            except Exception as e:
                logger.error(f"Event processing error: {str(e)}")
                time.sleep(5)

    def process_event(self, event):
        """Process a USB event through ML model"""
        try:
            if hasattr(self.ml_model, 'predict_event'):
                score = self.ml_model.predict_event(event)
            else:
                score = self.simple_risk_assessment(event)

            if score >= self.alert_threshold:
                device_id = event.get('device_id')
                if device_id and device_id not in self.blocked_devices:
                    self.blocked_devices.add(device_id)
                    return ('block', score)
                return ('alert', score)
            elif score >= 0.5:
                return ('alert', score)
            else:
                return ('allow', score)

        except Exception as e:
            logger.error(f"Event processing failed: {str(e)}")
            return ('allow', 0.0)

    def simple_risk_assessment(self, event):
        """Simple risk assessment when ML model is not available"""
        score = 0.0

        event_type = event.get('event_type', '').upper()
        device_info = event.get('device_info', {})

        if event_type == 'DATA_TRANSFER':
            score += 0.3
            bytes_transferred = event.get('bytes_transferred', 0)
            if bytes_transferred > 100 * 1024 * 1024:
                score += 0.4
            elif bytes_transferred > 10 * 1024 * 1024:
                score += 0.2

        if event_type == 'DEVICE_CONNECTED':
            score += 0.1

        if device_info.get('is_phone', False):
            score += 0.3

        if not device_info.get('manufacturer') or device_info.get('manufacturer') == 'Unknown':
            score += 0.2

        return min(score, 1.0)

    def get_active_devices(self):
        """Get currently active devices"""
        if hasattr(self.usb_monitor, 'active_devices'):
            return self.usb_monitor.active_devices
        return {}

    def add_demo_events(self):
        """Add demo events for testing when no real events exist"""
        if len(self.event_log) == 0:
            demo_events = [
                {
                    'timestamp': datetime.now().isoformat(),
                    'event_type': 'SYSTEM_START',
                    'device_id': 'DLP System',
                    'device_info': {'device_type': 'System', 'manufacturer': 'Internal'},
                    'action': 'allow',
                    'score': 0.0,
                    'bytes_transferred': 0
                }
            ]
            self.event_log.extend(demo_events)

    def export_events_for_splunk_mltk(self, export_path='data/lookups/usb_events_for_splunk.csv'):
        """Export recent USB events to CSV for Splunk MLTK ingestion"""
        import csv
        fieldnames = [
            'timestamp', 'event_type', 'device_id', 'manufacturer', 'model', 'serial_number',
            'action', 'score', 'bytes_transferred'
        ]
        with open(export_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for event in self.event_log:
                row = {
                    'timestamp': event.get('timestamp'),
                    'event_type': event.get('event_type'),
                    'device_id': event.get('device_id'),
                    'manufacturer': event.get('device_info', {}).get('manufacturer', ''),
                    'model': event.get('device_info', {}).get('model', ''),
                    'serial_number': event.get('device_info', {}).get('serial_number', ''),
                    'action': event.get('action'),
                    'score': event.get('score'),
                    'bytes_transferred': event.get('bytes_transferred'),
                }
                writer.writerow(row)
        logger.info(f"Exported events for Splunk MLTK to {export_path}")

# Initialize
dlp_system = USBDLPSystem()

# SocketIO Events
@socketio.on('connect')
def handle_connect():
    logger.info('Client connected to dashboard')
    socketio.emit('device_list', {'devices': usb_events})

@socketio.on('get_devices')
def handle_get_devices():
    socketio.emit('device_list', {'devices': usb_events})

# Flask
@app.route('/')
def dashboard():
    print("Serving dashboard.html from static folder")
    """Dashboard showing system status"""
    return send_from_directory('static', 'dashboard.html')

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory(app.static_folder, filename)

@app.route('/api/events', methods=['GET'])
def get_events():
    """Get recent security events"""
    try:
        if len(dlp_system.event_log) == 0:
            dlp_system.add_demo_events()

        active_devices = dlp_system.get_active_devices()

        response_data = {
            "blocked_devices": list(dlp_system.blocked_devices),
            "recent_events": dlp_system.event_log[-10:],
            "active_devices": active_devices,
            "system_status": {
                "running": dlp_system.system_running,
                "last_check": datetime.now().isoformat()
            }
        }

        return jsonify(response_data)
    except Exception as e:
        logger.error(f"API error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/block', methods=['POST'])
def block_device():
    """Manually block a device"""
    try:
        device_id = request.json.get('device_id')
        if device_id:
            dlp_system.blocked_devices.add(device_id)
            logger.info(f"Device manually blocked: {device_id}")
            return jsonify({"status": "success", "device_id": device_id})
        return jsonify({"status": "error", "message": "No device_id provided"}), 400
    except Exception as e:
        logger.error(f"Block device error: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/unblock', methods=['POST'])
def unblock_device():
    """Manually unblock a device"""
    try:
        device_id = request.json.get('device_id')
        if device_id and device_id in dlp_system.blocked_devices:
            dlp_system.blocked_devices.remove(device_id)
            logger.info(f"Device manually unblocked: {device_id}")
            return jsonify({"status": "success", "device_id": device_id})
        return jsonify({"status": "error", "message": "Device not found or not blocked"}), 400
    except Exception as e:
        logger.error(f"Unblock device error: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/status', methods=['GET'])
def get_status():
    """Get system status"""
    try:
        return jsonify({
            "system_running": dlp_system.system_running,
            "active_devices_count": len(dlp_system.get_active_devices()),
            "blocked_devices_count": len(dlp_system.blocked_devices),
            "total_events": len(dlp_system.event_log),
            "last_update": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Status error: {str(e)}")
        return jsonify({"error": str(e)}), 500

def run_flask_app():
    """Run the Flask web interface with SocketIO"""
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)

def main():
    """Main application entry point"""
    try:
        os.makedirs('logs', exist_ok=True)
        dlp_system.start_monitoring()

        logger.info("Starting USB DLP System...")
        logger.info("Dashboard will be available at http://localhost:5000")
        run_flask_app()

    except KeyboardInterrupt:
        logger.info("Shutting down system...")
        dlp_system.stop_monitoring()
        sys.exit(0)
    except Exception as e:
        logger.error(f"System error: {str(e)}")
        dlp_system.stop_monitoring()
        sys.exit(1)

if __name__ == "__main__":
    main()