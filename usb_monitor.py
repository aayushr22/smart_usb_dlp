"""
Smart USB DLP System - USB Monitoring Module
"""

import os
import json
import psutil
import platform
import subprocess
import time
import logging
from datetime import datetime
from threading import Thread, Lock
import queue

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class USBMonitor:
    """
    Real-time USB device monitoring
    """
    
    def __init__(self, data_path='tmp/usb_monitor_data'):
        self.data_path = data_path
        self.event_queue = queue.Queue()
        self.active_devices = {}
        self.recent_events = []
        self.event_history = []
        self.monitoring_active = False
        self.event_lock = Lock()
        
        os.makedirs(data_path, exist_ok=True)
        self.load_events()

    def run_as_service(self):
        """Main monitoring loop"""
        self.monitoring_active = True
        logger.info("Starting USB monitoring service...")
        
        while self.monitoring_active:
            try:
                self.check_device_changes()
                self.monitor_active_transfers()
                
                # Save events periodically
                if len(self.event_history) % 10 == 0:
                    self.save_events()
                
                time.sleep(2)
                
            except Exception as e:
                logger.error(f"Monitoring error: {str(e)}")
                time.sleep(5)

    def check_device_changes(self):
        """Check for USB device connections/disconnections"""
        current_devices = {}
        partitions = psutil.disk_partitions()
        
        for partition in partitions:
            if 'removable' in partition.opts or 'usb' in partition.device.lower():
                device_info = self.get_device_info(partition)
                current_devices[device_info['device_id']] = device_info
        
        # Check for new devices
        for device_id, device_info in current_devices.items():
            if device_id not in self.active_devices:
                self.handle_device_connected(device_info)
        
        # Check for removed devices
        for device_id in list(self.active_devices.keys()):
            if device_id not in current_devices:
                self.handle_device_disconnected(device_id)
        
        self.active_devices = current_devices

    def get_device_info(self, partition):
        """Get detailed info about a USB device"""
        try:
            usage = psutil.disk_usage(partition.mountpoint)
            return {
                'device_id': partition.device,
                'mountpoint': partition.mountpoint,
                'filesystem': partition.fstype,
                'total_space': usage.total,
                'used_space': usage.used,
                'free_space': usage.free,
                'detection_time': datetime.now().isoformat(),
                'device_type': 'USB Storage'
            }
        except Exception as e:
            logger.error(f"Failed to get device info: {str(e)}")
            return {
                'device_id': partition.device,
                'mountpoint': partition.mountpoint,
                'detection_time': datetime.now().isoformat(),
                'error': str(e)
            }

    def handle_device_connected(self, device_info):
        """Process new device connection"""
        event = {
            'event_type': 'DEVICE_CONNECTED',
            'timestamp': datetime.now().isoformat(),
            'device_id': device_info['device_id'],
            'device_info': device_info
        }
        self.add_event(event)
        logger.info(f"USB device connected: {device_info['device_id']}")

    def handle_device_disconnected(self, device_id):
        """Process device disconnection"""
        event = {
            'event_type': 'DEVICE_DISCONNECTED',
            'timestamp': datetime.now().isoformat(),
            'device_id': device_id
        }
        self.add_event(event)
        logger.info(f"USB device disconnected: {device_id}")

    def monitor_active_transfers(self):
        """Monitor data transfers on connected devices"""
        for device_id, device_info in self.active_devices.items():
            try:
                if 'mountpoint' in device_info:
                    current_usage = psutil.disk_usage(device_info['mountpoint'])
                    
                    if 'last_usage' in device_info:
                        bytes_changed = abs(current_usage.used - device_info['last_usage'].used)
                        if bytes_changed > 1024:  # 1KB threshold
                            self.handle_data_transfer(device_id, bytes_changed, current_usage)
                    
                    device_info['last_usage'] = current_usage
            except Exception as e:
                logger.debug(f"Transfer monitoring failed: {str(e)}")

    def handle_data_transfer(self, device_id, bytes_transferred, current_usage):
        """Process detected data transfer"""
        event = {
            'event_type': 'DATA_TRANSFER',
            'timestamp': datetime.now().isoformat(),
            'device_id': device_id,
            'bytes_written': bytes_transferred,
            'total_used': current_usage.used,
            'total_free': current_usage.free
        }
        self.add_event(event)
        logger.info(f"Data transfer detected on {device_id}: {bytes_transferred} bytes")

    def add_event(self, event):
        """Add event to queue and history"""
        with self.event_lock:
            self.recent_events.append(event)
            self.event_history.append(event)
            
            if len(self.recent_events) > 100:
                self.recent_events = self.recent_events[-100:]

    def get_recent_events(self, limit=10):
        """Get recent events"""
        with self.event_lock:
            return self.recent_events[-limit:] if self.recent_events else []

    def save_events(self):
        """Save events to file"""
        try:
            with open(os.path.join(self.data_path, 'usb_events.json'), 'w') as f:
                json.dump(self.event_history[-1000:], f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save events: {str(e)}")

    def load_events(self):
        """Load events from file"""
        try:
            events_file = os.path.join(self.data_path, 'usb_events.json')
            if os.path.exists(events_file):
                with open(events_file, 'r') as f:
                    self.event_history = json.load(f)
        except Exception as e:
            logger.error(f"Failed to load events: {str(e)}")