import os
from pathlib import Path

class SplunkConfig:
    """Splunk configuration settings"""
    
    # Splunk HTTP Event Collector
    SPLUNK_HOST = os.getenv('SPLUNK_HOST', 'localhost')
    SPLUNK_PORT = os.getenv('SPLUNK_PORT', '8088')
    SPLUNK_TOKEN = os.getenv('SPLUNK_TOKEN', '2b32ea42-8e5c-4dba-88b5-06998e6b3868')
    SPLUNK_INDEX = os.getenv('SPLUNK_INDEX', 'usb_security')
    
    # Splunk management settings
    SPLUNK_MGMT_PORT = os.getenv('SPLUNK_MGMT_PORT', '8089')
    SPLUNK_USERNAME = os.getenv('SPLUNK_USERNAME', 'aayushr2201@gmail.com')
    SPLUNK_PASSWORD = os.getenv('SPLUNK_PASSWORD', 'Aayush@22')
    
    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = 'logs/usb_security.log'
    
    EVENT_TYPES = {
        'USB_CONNECTED': 'usb_device_connected',
        'USB_REMOVED': 'usb_device_removed',
        'THREAT_DETECTED': 'threat_detected',
        'ANALYSIS_COMPLETE': 'analysis_complete',
        'SECURITY_ALERT': 'security_alert',
        'MONITORING_START': 'monitoring_started',
        'MONITORING_STOP': 'monitoring_stopped',
        'ERROR': 'error'
    }
    
    THREAT_LEVELS = {
        'LOW': 'LOW',
        'MEDIUM': 'MEDIUM',
        'HIGH': 'HIGH',
        'CRITICAL': 'CRITICAL',
        'INFO': 'INFO',
        'ERROR': 'ERROR'
    }
    
    @classmethod
    def validate_config(cls):
        """Validate Splunk configuration"""
        errors = []
        
        if not cls.SPLUNK_TOKEN:
            errors.append("SPLUNK_TOKEN is required")
        
        if not cls.SPLUNK_HOST:
            errors.append("SPLUNK_HOST is required")
        
        log_dir = Path(cls.LOG_FILE).parent
        log_dir.mkdir(exist_ok=True)
        
        return errors
    
    @classmethod
    def get_splunk_url(cls):
        """Get Splunk HEC URL"""
        return f"https://{cls.SPLUNK_HOST}:{cls.SPLUNK_PORT}/services/collector"
    
    @classmethod
    def get_splunk_mgmt_url(cls):
        """Get Splunk management URL"""
        return f"https://{cls.SPLUNK_HOST}:{cls.SPLUNK_MGMT_PORT}"