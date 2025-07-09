"""
Smart USB DLP System - Enhanced USB Monitoring Module with MTP/Phone Support
"""

import os
import sys
import json
import psutil
import platform
import subprocess
import time
import logging
from datetime import datetime
from threading import Thread, Lock
import queue
import re
import winreg
import requests

current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

try:
    import wmi
    WMI_AVAILABLE = True
except ImportError:
    WMI_AVAILABLE = False
    
from usb_threat_engine import SplunkLogger

# logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class USBMonitor:
    """
    Real-time USB device monitoring with MTP/Phone support and Splunk integration
    """
    
    def __init__(self, data_path='tmp/usb_monitor_data'):
        self.data_path = data_path
        self.event_queue = queue.Queue()
        self.active_devices = {}
        self.recent_events = []
        self.event_history = []
        self.monitoring_active = False
        self.event_lock = Lock()
        self.splunk_logger = SplunkLogger()
        
        self.mtp_devices = {}
        self.last_file_counts = {}
        
        if platform.system() == 'Windows' and WMI_AVAILABLE:
            try:
                self.wmi_connection = wmi.WMI(moniker='winmgmts:')
                logger.info("WMI connection established successfully")
            except Exception as e:
                logger.error(f"Failed to establish WMI connection: {str(e)}")
                self.wmi_connection = None
        else:
            self.wmi_connection = None
        
        os.makedirs(data_path, exist_ok=True)
        self.load_events()

    def run_as_service(self):
        """Main monitoring loop"""
        self.monitoring_active = True
        
        # monitoring
        self.splunk_logger.log_usb_event(
            event_type="monitoring_started",
            event_data={"status": "starting"},
            threat_level="INFO"
        )
        
        logger.info("Starting Enhanced USB monitoring service with MTP support...")
        
        while self.monitoring_active:
            try:
                self.check_device_changes()
                self.monitor_active_transfers()
                self.monitor_mtp_transfers() 
                
                if len(self.event_history) % 10 == 0:
                    self.save_events()
                
                time.sleep(2)
                
            except KeyboardInterrupt:
                self.stop_monitoring()
                break
            except Exception as e:
                logger.error(f"Monitoring error: {str(e)}")
                self.splunk_logger.log_usb_event(
                    event_type="monitoring_error",
                    event_data={"error": str(e)},
                    threat_level="ERROR"
                )
                time.sleep(5)

    def check_device_changes(self):
        """device change detection with MTP support"""
        current_devices = self._get_connected_devices()
        
        # Check
        for device_id, device_info in current_devices.items():
            if device_id not in self.active_devices:
                self.handle_device_connected(device_info)
        
        for device_id in list(self.active_devices.keys()):
            if device_id not in current_devices:
                self.handle_device_disconnected(device_id)
        
        self.active_devices = current_devices

    def _get_connected_devices(self):
        """device detection with MTP support"""
        if platform.system() == 'Windows':
            return self._get_windows_devices_enhanced()
        else:
            return self._get_linux_devices()

    def _get_windows_devices_enhanced(self):
        """Windows device detection with MTP/Phone support"""
        devices = {}
        
        try:
            if self.wmi_connection:
                for disk in self.wmi_connection.Win32_LogicalDisk(DriveType=2):
                    device_info = {
                        'device_id': disk.DeviceID,
                        'mountpoint': disk.DeviceID + '\\',
                        'filesystem': disk.FileSystem or 'Unknown',
                        'total_space': int(disk.Size) if disk.Size else 0,
                        'used_space': int(disk.Size) - int(disk.FreeSpace) if disk.Size and disk.FreeSpace else 0,
                        'free_space': int(disk.FreeSpace) if disk.FreeSpace else 0,
                        'detection_time': datetime.now().isoformat(),
                        'device_type': 'USB_Storage',
                        'protocol': 'Mass Storage',
                        'label': disk.VolumeName or 'Unknown',
                        'serial_number': disk.VolumeSerialNumber or 'Unknown',
                        'is_phone': False
                    }
                    devices[device_info['device_id']] = device_info
                    logger.info(f"Found USB storage device: {device_info['device_id']}")
            
            if self.wmi_connection:
                for pnp in self.wmi_connection.Win32_PnPEntity():
                    device_name = str(pnp.Name or '').lower()
                    device_desc = str(pnp.Description or '').lower()
                    device_id = str(pnp.DeviceID or '')
                    
                    phone_indicators = [
                        'mtp', 'ptp', 'android', 'iphone', 'samsung', 'huawei', 
                        'xiaomi', 'oppo', 'vivo', 'oneplus', 'google pixel',
                        'mobile', 'phone', 'smartphone', 'portable device'
                    ]
                    
                    mtp_indicators = [
                        'media transfer protocol', 'picture transfer protocol',
                        'mtp device', 'ptp device', 'portable device'
                    ]
                    
                    is_phone = any(indicator in device_name for indicator in phone_indicators)
                    is_mtp = any(indicator in device_desc for indicator in mtp_indicators)
                    
                    if (is_phone or is_mtp) and 'usb' in device_id.lower():
                        device_info = {
                            'device_id': device_id,
                            'device_name': pnp.Name or 'Unknown Phone',
                            'device_type': 'Mobile_Device',
                            'protocol': 'MTP/PTP',
                            'description': pnp.Description or 'Unknown',
                            'manufacturer': pnp.Manufacturer or 'Unknown',
                            'detection_time': datetime.now().isoformat(),
                            'is_phone': True,
                            'status': pnp.Status or 'Unknown'
                        }
                        devices[device_id] = device_info
                        logger.info(f"Found MTP/Phone device: {device_info['device_name']}")
            
            mtp_devices = self._get_mtp_devices_from_registry()
            devices.update(mtp_devices)
            
        except Exception as e:
            logger.warning(f"Enhanced device detection failed, using fallback: {str(e)}")
            
            try:
                partitions = psutil.disk_partitions()
                for partition in partitions:
                    if 'removable' in partition.opts.lower():
                        try:
                            usage = psutil.disk_usage(partition.mountpoint)
                            device_info = {
                                'device_id': partition.device,
                                'mountpoint': partition.mountpoint,
                                'filesystem': partition.fstype,
                                'total_space': usage.total,
                                'used_space': usage.used,
                                'free_space': usage.free,
                                'detection_time': datetime.now().isoformat(),
                                'device_type': 'USB_Storage',
                                'protocol': 'Mass Storage',
                                'is_phone': False
                            }
                            devices[device_info['device_id']] = device_info
                        except Exception as partition_error:
                            logger.debug(f"Partition error: {str(partition_error)}")
                            
            except Exception as fallback_error:
                logger.error(f"All device detection methods failed: {str(fallback_error)}")
        
        return devices

    def _get_mtp_devices_from_registry(self):
        """MTP devices from Windows registry"""
        mtp_devices = {}
        
        try:
            registry_paths = [
                r"SYSTEM\CurrentControlSet\Enum\USB",
                r"SYSTEM\CurrentControlSet\Control\DeviceClasses\{6ac27878-a6fa-4155-ba85-f98f491d4f33}"
            ]
            
            for reg_path in registry_paths:
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
                        for i in range(winreg.QueryInfoKey(key)[0]):
                            try:
                                subkey_name = winreg.EnumKey(key, i)
                                if any(x in subkey_name.lower() for x in ['mtp', 'ptp', 'android']):
                                    device_info = {
                                        'device_id': f"REG_{subkey_name}",
                                        'device_name': subkey_name,
                                        'device_type': 'Mobile_Device',
                                        'protocol': 'MTP/PTP',
                                        'detection_time': datetime.now().isoformat(),
                                        'is_phone': True,
                                        'source': 'registry'
                                    }
                                    mtp_devices[device_info['device_id']] = device_info
                            except Exception as subkey_error:
                                continue
                except Exception as reg_error:
                    logger.debug(f"Registry access error for {reg_path}: {str(reg_error)}")
                    
        except Exception as e:
            logger.debug(f"Registry-based MTP detection failed: {str(e)}")
        
        return mtp_devices

    def monitor_mtp_transfers(self):
        """Monitor file transfers on MTP devices"""
        for device_id, device_info in self.active_devices.items():
            if device_info.get('is_phone', False) and device_info.get('protocol') == 'MTP/PTP':
                try:
                    self._monitor_mtp_via_events(device_id, device_info)
                    
                    self._monitor_mtp_via_handles(device_id, device_info)
                    
                except Exception as e:
                    logger.debug(f"MTP monitoring error for {device_id}: {str(e)}")

    def _monitor_mtp_via_events(self, device_id, device_info):
        """Monitor MTP transfers via Windows event logs"""
        try:
            if self.wmi_connection:
                events = self.wmi_connection.Win32_NTLogEvent(
                    Logfile='System',
                    EventCode=[20001, 20003, 43]
                )
                
                for event in events:
                    if device_id in str(event.Message or ''):
                        self._handle_mtp_event(device_id, event, device_info)
                        
        except Exception as e:
            logger.debug(f"Event log monitoring failed: {str(e)}")

    def _monitor_mtp_via_handles(self, device_id, device_info):
        """Monitor MTP transfers via system handles"""
        try:
            result = subprocess.run(
                ['powershell', '-Command', 
                 f'Get-Process | Where-Object {{$_.ProcessName -like "*mtp*" -or $_.ProcessName -like "*phone*"}} | Measure-Object'],
                capture_output=True, text=True, timeout=5
            )
            
            if result.returncode == 0:
                current_time = datetime.now().isoformat()
                if device_id not in self.last_file_counts:
                    self.last_file_counts[device_id] = {'time': current_time, 'activity': 0}
                self.last_file_counts[device_id]['activity'] += 1
                
                if self.last_file_counts[device_id]['activity'] > 5:
                    self._handle_mtp_transfer(device_id, device_info)
                    self.last_file_counts[device_id]['activity'] = 0
                    
        except Exception as e:
            logger.debug(f"Handle monitoring failed: {str(e)}")

    def _handle_mtp_event(self, device_id, event, device_info):
        """Handle detected MTP event"""
        event_data = {
            'event_type': 'MTP_EVENT',
            'timestamp': datetime.now().isoformat(),
            'device_id': device_id,
            'device_info': device_info,
            'event_code': event.EventCode,
            'message': event.Message
        }
        
        self.add_event(event_data)
        
        # Log to Splunk
        self.splunk_logger.log_usb_event(
            event_type="mtp_device_event",
            event_data=event_data,
            threat_level="INFO"
        )

    def _handle_mtp_transfer(self, device_id, device_info):
        """Handle detected MTP file transfer"""
        transfer_event = {
            'event_type': 'MTP_TRANSFER',
            'timestamp': datetime.now().isoformat(),
            'device_id': device_id,
            'device_info': device_info,
            'protocol': 'MTP/PTP',
            'estimated_size': 'Unknown'
        }
        
        self.add_event(transfer_event)
        
        # Log to Splunk
        splunk_data = {
            'device_id': device_id,
            'device_name': device_info.get('device_name', 'Unknown'),
            'protocol': 'MTP/PTP',
            'is_phone': True,
            'manufacturer': device_info.get('manufacturer', 'Unknown'),
            'transfer_type': 'MTP_FILE_TRANSFER'
        }
        
        self.splunk_logger.log_usb_event(
            event_type="mtp_file_transfer",
            event_data=splunk_data,
            threat_level="MEDIUM" 
        )
        
        logger.info(f"MTP file transfer detected on {device_info.get('device_name', device_id)}")

    def handle_device_connected(self, device_info):
        """device connection handler"""
        event = {
            'event_type': 'DEVICE_CONNECTED',
            'timestamp': datetime.now().isoformat(),
            'device_id': device_info['device_id'],
            'device_info': device_info,
            'is_phone': device_info.get('is_phone', False),
            'protocol': device_info.get('protocol', 'Unknown')
        }
        self.add_event(event)
        
        splunk_event = {
            'device_type': device_info.get('device_type', 'Unknown'),
            'protocol': device_info.get('protocol', 'Unknown'),
            'is_phone': device_info.get('is_phone', False),
            'connection_time': datetime.now().isoformat(),
            'manufacturer': device_info.get('manufacturer', 'Unknown'),
            'device_name': device_info.get('device_name', 'Unknown')
        }
        
        threat_level = "INFO"
        if device_info.get('is_phone', False):
            threat_level = "MEDIUM"
        elif device_info.get('device_type') == 'Unknown':
            threat_level = "HIGH"
        
        self.splunk_logger.log_usb_event(
            event_type="usb_device_connected",
            event_data=splunk_event,
            threat_level=threat_level
        )
        try:
            requests.post("http://localhost:8081/api/usb-event", json=device_info, timeout=1)
        except:
            pass
        
        device_desc = device_info.get('device_name', device_info['device_id'])
        logger.info(f"Device connected: {device_desc} (Protocol: {device_info.get('protocol', 'Unknown')})")

    def handle_device_disconnected(self, device_id):
        """device disconnection handler"""
        device_info = self.active_devices.get(device_id, {})
        
        event = {
            'event_type': 'DEVICE_DISCONNECTED',
            'timestamp': datetime.now().isoformat(),
            'device_id': device_id,
            'was_phone': device_info.get('is_phone', False)
        }
        self.add_event(event)
        
        if device_id in self.last_file_counts:
            del self.last_file_counts[device_id]
        
        # Splunk
        self.splunk_logger.log_usb_event(
            event_type="usb_device_disconnected",
            event_data={
                "device_id": device_id,
                "was_phone": device_info.get('is_phone', False),
                "protocol": device_info.get('protocol', 'Unknown')
            },
            threat_level="INFO"
        )
        
        logger.info(f"Device disconnected: {device_id}")

    def monitor_active_transfers(self):
        """Monitor data transfers on connected storage devices"""
        for device_id, device_info in self.active_devices.items():
            try:
                if 'mountpoint' in device_info and not device_info.get('is_phone', False):
                    current_usage = psutil.disk_usage(device_info['mountpoint'])
                    
                    if 'last_usage' in device_info:
                        bytes_changed = abs(current_usage.used - device_info['last_usage'].used)
                        if bytes_changed > 1024:
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
            'total_free': current_usage.free,
            'protocol': 'Mass Storage'
        }
        self.add_event(event)
        
        transfer_details = {
            'device_id': device_id,
            'bytes_transferred': bytes_transferred,
            'total_used': current_usage.used,
            'total_free': current_usage.free,
            'protocol': 'Mass Storage',
            'is_phone': False
        }
        threat_level = "INFO"
        if bytes_transferred > 100 * 1024 * 1024:
            threat_level = "HIGH"
        elif bytes_transferred > 10 * 1024 * 1024:
            threat_level = "MEDIUM"
        
        self.splunk_logger.log_usb_event(
            event_type="usb_data_transfer",
            event_data=transfer_details,
            threat_level=threat_level
        )
        
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

    def stop_monitoring(self):
        """Stop the monitoring service"""
        self.monitoring_active = False
        logger.info("Stopping USB monitoring service...")
        self.splunk_logger.log_usb_event(
            event_type="monitoring_stopped",
            event_data={"status": "stopped"},
            threat_level="INFO"
        )

    def _get_linux_devices(self):
        """Get USB devices on Linux (existing implementation)"""
        devices = {}
        try:
            partitions = psutil.disk_partitions()
            for partition in partitions:
                if 'removable' in partition.opts.lower() or partition.device.startswith('/dev/sd'):
                    try:
                        usage = psutil.disk_usage(partition.mountpoint)
                        device_info = {
                            'device_id': partition.device,
                            'mountpoint': partition.mountpoint,
                            'filesystem': partition.fstype,
                            'total_space': usage.total,
                            'used_space': usage.used,
                            'free_space': usage.free,
                            'detection_time': datetime.now().isoformat(),
                            'device_type': 'USB_Storage',
                            'protocol': 'Mass Storage',
                            'is_phone': False
                        }
                        devices[device_info['device_id']] = device_info
                    except Exception as e:
                        logger.debug(f"Couldn't get info for {partition.device}: {str(e)}")
        except Exception as e:
            logger.error(f"Linux device detection failed: {str(e)}")
        return devices

if __name__ == "__main__":
    monitor = USBMonitor()
    try:
        monitor.run_as_service()
    except KeyboardInterrupt:
        monitor.stop_monitoring()