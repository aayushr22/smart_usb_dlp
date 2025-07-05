"""
Smart USB DLP System - Main Application
"""

import os
import sys
import time
import logging
from datetime import datetime
from flask import Flask, render_template, jsonify, request
from threading import Thread
from usb_monitor import USBMonitor
from bin.usb_ml_model import USBMLModel

# Configure logging
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

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory(app.static_folder, filename)

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
        
        logger.info("System initialization complete")

    def start_monitoring(self):
        """Start all monitoring services"""
        logger.info("Starting monitoring services")
        
        # Start USB monitoring in background thread
        self.monitor_thread = Thread(target=self.monitor_usb_activity, daemon=True)
        self.monitor_thread.start()
        
        # Start processing events from queue
        self.processor_thread = Thread(target=self.process_events, daemon=True)
        self.processor_thread.start()

    def monitor_usb_activity(self):
        """Monitor USB activity using USBMonitor"""
        try:
            self.usb_monitor.run_as_service()
        except Exception as e:
            logger.error(f"USB monitoring failed: {str(e)}")

    def process_events(self):
        """Process events from the USB monitor"""
        while True:
            try:
                # Get recent events from monitor
                events = self.usb_monitor.get_recent_events()
                
                for event in events:
                    # Process each event through ML model
                    action, score = self.process_event(event)
                    
                    # Log the processed event
                    log_entry = {
                        'timestamp': datetime.now().isoformat(),
                        'event': event,
                        'action': action,
                        'score': score
                    }
                    self.event_log.append(log_entry)
                    
                    logger.info(f"Processed event: {event['event_type']} - Action: {action} (Score: {score:.2f})")
                
                time.sleep(1)  # Process events every second
                
            except Exception as e:
                logger.error(f"Event processing error: {str(e)}")
                time.sleep(5)

    def process_event(self, event):
        """Process a USB event through ML model"""
        try:
            score = self.ml_model.predict_event(event)
            
            if score >= self.alert_threshold:
                device_id = event.get('device_id')
                if device_id and device_id not in self.blocked_devices:
                    self.blocked_devices.add(device_id)
                    return ('block', score)
                return ('alert', score)
            return ('allow', score)
            
        except Exception as e:
            logger.error(f"Event processing failed: {str(e)}")
            return ('allow', 0.0)

# Initialize system
dlp_system = USBDLPSystem()

# Flask Routes
@app.route('/')
def dashboard():
    """Dashboard showing system status"""
    system_status = {
        "usb_devices_blocked": len(dlp_system.blocked_devices),
        "last_scan": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "threat_level": "Normal",
        "active_devices": len(dlp_system.usb_monitor.active_devices)
    }
    return render_template('dashboard.html', status=system_status)

@app.route('/api/events', methods=['GET'])
def get_events():
    """Get recent security events"""
    return jsonify({
        "blocked_devices": list(dlp_system.blocked_devices),
        "recent_events": dlp_system.event_log[-10:],
        "active_devices": dlp_system.usb_monitor.active_devices
    })

@app.route('/api/block', methods=['POST'])
def block_device():
    """Manually block a device"""
    device_id = request.json.get('device_id')
    if device_id:
        dlp_system.blocked_devices.add(device_id)
        return jsonify({"status": "success", "device_id": device_id})
    return jsonify({"status": "error", "message": "No device_id provided"}), 400

def run_flask_app():
    """Run the Flask web interface"""
    app.run(host='0.0.0.0', port=5000, debug=False)

def main():
    """Main application entry point"""
    try:
        # Start monitoring services
        dlp_system.start_monitoring()
        
        # Start Flask app
        logger.info("Starting USB DLP System...")
        logger.info("Dashboard will be available at http://localhost:5000")
        run_flask_app()
        
    except Exception as e:
        logger.error(f"System error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()