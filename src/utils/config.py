"""
Smart USB DLP System - Configuration Management
Central configuration for threat detection parameters and system settings
Updated with MTP protocol support
"""

import os
import json
from pathlib import Path
import logging

class USBConfig:
    """Configuration management for USB threat detection system"""
    
    def __init__(self, config_file='config.json'):
        self.config_file = config_file
        self.config = self.load_config()
        self._setup_logging()
    
    def _setup_logging(self):
        """Setup logging based on configuration"""
        log_level = self.config.get('logging', {}).get('level', 'INFO')
        log_file = self.config.get('logging', {}).get('file', 'tmp/usb_threat_engine.log')
        
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        
        logging.basicConfig(
            level=getattr(logging, log_level.upper()),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
    
    def load_config(self):
        """Load configuration from file or return defaults"""
        default_config = {
            'thresholds': {
                'large_transfer_mb': 1000,
                'frequent_access_count': 10,
                'suspicious_hours': [0, 1, 2, 3, 4, 5, 22, 23],
                'max_devices_per_user': 5,
                'anomaly_score_threshold': -0.5,
                'critical_risk_score': 8.0,
                'high_risk_score': 5.0,
                'medium_risk_score': 2.0,
                'mtp_large_transfer_mb': 500,
                'mtp_max_concurrent_transfers': 3,
                'mtp_session_timeout_minutes': 30
            },
            
            # Risk Calculation Weights
            'risk_weights': {
                'size_factor': 0.3,
                'frequency_factor': 0.2,
                'time_factor': 0.2,
                'device_factor': 0.1,
                'pattern_factor': 0.2
            },
            
            # Response Actions by Risk Level
            'response_actions': {
                'CRITICAL': ['block', 'alert', 'log', 'notify_admin'],
                'HIGH': ['alert', 'log', 'notify_admin'],
                'MEDIUM': ['log', 'notify_user'],
                'LOW': ['log']
            },
            
            # Machine Learning Settings
            'ml_settings': {
                'model_path': 'tmp/usb_ml_models',
                'deep_model_path': 'tmp/usb_deep_models',
                'retrain_interval_hours': 24,
                'feature_columns': [
                    'bytes_written', 'session_duration', 'hour', 'day_of_week', 
                    'device_usage_count', 'time_since_last_transfer',
                    'bytes_per_second', 'session_frequency', 'unusual_time_score',
                    'device_risk_score', 'data_velocity', 'protocol_type_risk',
                    'mtp_transfer_pattern', 'device_trust_score'
                ],
                'threat_indicators': [
                    'known_malicious_pattern', 'suspicious_file_types',
                    'encryption_detected', 'steganography_risk',
                    'data_exfiltration_signature', 'insider_threat_score',
                    'mtp_protocol_abuse', 'unauthorized_device_access'
                ]
            },
            
            # Protocol settings
            'protocols': {
                'mass_storage': {
                    'enabled': True,
                    'risk_level': 'MEDIUM',
                    'monitor_file_operations': True,
                    'monitor_registry_changes': True
                },
                'mtp': {
                    'enabled': True,
                    'risk_level': 'HIGH',
                    'monitor_wmp_events': True,
                    'monitor_shell_events': True,
                    'monitor_com_events': True,
                    'track_media_files': True,
                    'track_document_files': True,
                    'session_logging': True
                },
                'ptp': {
                    'enabled': True,
                    'risk_level': 'MEDIUM',
                    'monitor_image_transfers': True
                }
            },
            
            # MTP monitoring settings
            'mtp_monitoring': {
                'event_sources': [
                    'Microsoft-Windows-WMP',
                    'Microsoft-Windows-Shell-Core',
                    'Microsoft-Windows-Kernel-Process',
                    'Microsoft-Windows-COM+'
                ],
                'file_extensions_to_monitor': [
                    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff',  
                    '.mp4', '.avi', '.mov', '.wmv', '.flv', '.mkv',    
                    '.mp3', '.wav', '.flac', '.aac', '.ogg', '.wma',   
                    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', 
                    '.txt', '.csv', '.zip', '.rar', '.7z',           
                    '.apk', '.exe', '.msi', '.deb', '.rpm'            
                ],
                'monitor_folders': [
                    'DCIM', 'Pictures', 'Documents', 'Downloads', 
                    'Music', 'Videos', 'Android/data'
                ],
                'detect_file_operations': [
                    'copy_from_device', 'copy_to_device', 'delete_from_device',
                    'create_folder', 'delete_folder', 'rename_file'
                ]
            },
            
            # Splunk Integration
            'splunk_integration': {
                'enabled': False,  # Set to True to enable Splunk integration
                'host': 'localhost',
                'port': 8089,
                'username': 'aayushr2201@gmail.com',
                'password': 'Aayush@22',
                'index': 'usb_security',
                'sourcetype': 'usb:threat',
                'ssl_verify': False,
                'timeout': 30,
                'retry_count': 3,
                'batch_size': 100
            },
            
            'splunk': {
                'host': 'localhost',
                'port': 8089,
                'username': 'aayushr2201@gmail.com',
                'password': 'Aayush@22',
                'index': 'usb_security',
                'sourcetype': 'usb:threat',
                'ssl_verify': False,
                'timeout': 30,
                'retry_count': 3,
                'batch_size': 100
            },
            
            # Database
            'database': {
                'type': 'sqlite',
                'path': 'tmp/usb_threats.db',
                'backup_interval_hours': 6,
                'max_size_mb': 1000,
                'vacuum_interval_hours': 24
            },
            
            # Logging
            'logging': {
                'level': 'INFO',
                'file': 'tmp/usb_threat_engine.log',
                'max_size_mb': 100,
                'backup_count': 5,
                'mtp_debug': False, 
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            },
            
            # Device Categories and Risk Levels
            'device_categories': {
                'USB_Flash': {'risk_level': 'MEDIUM', 'max_size_gb': 128, 'protocol': 'mass_storage'},
                'External_HDD': {'risk_level': 'HIGH', 'max_size_gb': 5000, 'protocol': 'mass_storage'},
                'USB_SSD': {'risk_level': 'HIGH', 'max_size_gb': 2000, 'protocol': 'mass_storage'},
                'Mobile_Device': {'risk_level': 'HIGH', 'max_size_gb': 512, 'protocol': 'mtp'},
                'Smartphone': {'risk_level': 'HIGH', 'max_size_gb': 1000, 'protocol': 'mtp'},
                'Tablet': {'risk_level': 'HIGH', 'max_size_gb': 1000, 'protocol': 'mtp'},
                'Digital_Camera': {'risk_level': 'MEDIUM', 'max_size_gb': 256, 'protocol': 'ptp'},
                'Unknown': {'risk_level': 'CRITICAL', 'max_size_gb': 0, 'protocol': 'unknown'}
            },
            
            # File Type Risk Assessment
            'file_types': {
                'documents': {'risk_level': 'MEDIUM', 'extensions': ['.doc', '.docx', '.pdf', '.txt', '.xlsx', '.ppt']},
                'images': {'risk_level': 'LOW', 'extensions': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff']},
                'videos': {'risk_level': 'MEDIUM', 'extensions': ['.mp4', '.avi', '.mov', '.wmv', '.flv', '.mkv']},
                'audio': {'risk_level': 'LOW', 'extensions': ['.mp3', '.wav', '.flac', '.aac', '.ogg', '.wma']},
                'software': {'risk_level': 'CRITICAL', 'extensions': ['.exe', '.msi', '.deb', '.apk', '.app']},
                'data': {'risk_level': 'HIGH', 'extensions': ['.csv', '.json', '.xml', '.sql', '.db']},
                'backup': {'risk_level': 'HIGH', 'extensions': ['.zip', '.rar', '.7z', '.tar', '.gz']},
                'encrypted': {'risk_level': 'CRITICAL', 'extensions': ['.gpg', '.enc', '.aes', '.pgp']},
                'system': {'risk_level': 'CRITICAL', 'extensions': ['.sys', '.dll', '.reg', '.ini', '.cfg']}
            },
            
            # Device Trust Levels
            'device_trust': {
                'trusted_devices': [], 
                'corporate_devices': [],  
                'personal_devices': [],  
                'blocked_devices': [],   
                'trust_decay_days': 30,  
                'auto_trust_threshold': 10 
            },
            
            # Alerts
            'alerts': {
                'email_enabled': False,
                'email_server': 'aayush.company.com',
                'email_port': 587,
                'email_from': 'aayush@company.com',
                'email_to': ['aayushr2201@gmail.com', 'security-team@company.com'],
                'email_username': '',
                'email_password': '',
                'email_use_tls': True,
                'slack_enabled': False,
                'slack_webhook': '',
                'sms_enabled': False,
                'mtp_alerts_enabled': True,
                'real_time_alerts': True
            },
            
            # Performance 
            'performance': {
                'batch_size': 1000,
                'max_concurrent_analyses': 5,
                'cache_size_mb': 256,
                'cleanup_interval_hours': 12,
                'mtp_event_buffer_size': 5000,
                'mtp_processing_threads': 2,
                'memory_limit_mb': 512,
                'disk_usage_threshold_percent': 85
            }
        }
        
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    loaded_config = json.load(f)
                    merged_config = self.merge_configs(default_config, loaded_config)
                    print(f"Configuration loaded from {self.config_file}")
                    return merged_config
            except json.JSONDecodeError as e:
                print(f"Error parsing config file {self.config_file}: {e}. Using defaults.")
                return default_config
            except Exception as e:
                print(f"Error loading config: {e}. Using defaults.")
                return default_config
        else:
            print(f"Config file {self.config_file} not found. Creating with defaults.")
            self.save_config(default_config)
            return default_config
    
    def merge_configs(self, default, loaded):
        """Recursively merge loaded config with defaults"""
        result = default.copy()
        for key, value in loaded.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self.merge_configs(result[key], value)
            else:
                result[key] = value
        return result
    
    def save_config(self, config=None):
        """Save configuration to file"""
        if config is None:
            config = self.config
        
        try:
            config_dir = os.path.dirname(self.config_file)
            if config_dir and not os.path.exists(config_dir):
                os.makedirs(config_dir, exist_ok=True)
            
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            print(f"Configuration saved to {self.config_file}")
        except Exception as e:
            print(f"Error saving config: {e}")
    
    def get(self, key, default=None):
        """Get configuration value with dot notation support"""
        if not key:
            return default
            
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key, value):
        """Set configuration value with dot notation support"""
        if not key:
            return
            
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
        self.save_config()
    
    def get_threat_thresholds(self):
        """Get threat detection thresholds"""
        return self.config.get('thresholds', {})
    
    def get_ml_settings(self):
        """Get machine learning settings"""
        return self.config.get('ml_settings', {})
    
    def get_splunk_config(self):
        """Get Splunk configuration - prefers splunk_integration key"""
        # try the primary key
        splunk_config = self.config.get('splunk_integration', {})
        if not splunk_config:
            splunk_config = self.config.get('splunk', {})
        return splunk_config
    
    def get_mtp_monitoring_config(self):
        """Get MTP monitoring configuration"""
        return self.config.get('mtp_monitoring', {})
    
    def get_protocol_config(self, protocol):
        """Get protocol-specific configuration"""
        return self.config.get('protocols', {}).get(protocol, {})
    
    def get_response_actions(self, risk_level):
        """Get response actions for risk level"""
        return self.config.get('response_actions', {}).get(risk_level, ['log'])
    
    def get_device_risk_level(self, device_type):
        """Get risk level for device type"""
        return self.config.get('device_categories', {}).get(device_type, {}).get('risk_level', 'MEDIUM')
    
    def get_device_protocol(self, device_type):
        """Get protocol for device type"""
        return self.config.get('device_categories', {}).get(device_type, {}).get('protocol', 'unknown')
    
    def is_suspicious_hour(self, hour):
        """Check if hour is suspicious"""
        suspicious_hours = self.config.get('thresholds', {}).get('suspicious_hours', [])
        return hour in suspicious_hours
    
    def get_risk_weights(self):
        """Get risk calculation weights"""
        return self.config.get('risk_weights', {})
    
    def is_mtp_enabled(self):
        """Check if MTP monitoring is enabled"""
        return self.config.get('protocols', {}).get('mtp', {}).get('enabled', False)
    
    def get_mtp_file_extensions(self):
        """Get list of MTP file extensions to monitor"""
        return self.config.get('mtp_monitoring', {}).get('file_extensions_to_monitor', [])
    
    def get_mtp_folders_to_monitor(self):
        """Get list of MTP folders to monitor"""
        return self.config.get('mtp_monitoring', {}).get('monitor_folders', [])
    
    def is_device_trusted(self, device_id):
        """Check if device is trusted"""
        trusted_devices = self.config.get('device_trust', {}).get('trusted_devices', [])
        return device_id in trusted_devices
    
    def add_trusted_device(self, device_id):
        """Add device to trusted list"""
        if 'device_trust' not in self.config:
            self.config['device_trust'] = {'trusted_devices': []}
        if 'trusted_devices' not in self.config['device_trust']:
            self.config['device_trust']['trusted_devices'] = []
            
        if device_id not in self.config['device_trust']['trusted_devices']:
            self.config['device_trust']['trusted_devices'].append(device_id)
            self.save_config()
            print(f"Added device {device_id} to trusted list")
    
    def remove_trusted_device(self, device_id):
        """Remove device from trusted list"""
        trusted_devices = self.config.get('device_trust', {}).get('trusted_devices', [])
        if device_id in trusted_devices:
            trusted_devices.remove(device_id)
            self.save_config()
            print(f"Removed device {device_id} from trusted list")
    
    def get_file_type_risk(self, file_extension):
        """Get risk level for file type"""
        if not file_extension:
            return 'MEDIUM'
            
        file_extension = file_extension.lower()
        if not file_extension.startswith('.'):
            file_extension = '.' + file_extension
            
        for file_type, config in self.config.get('file_types', {}).items():
            if file_extension in config.get('extensions', []):
                return config.get('risk_level', 'MEDIUM')
        return 'MEDIUM'  # Default 
    
    def validate_config(self):
        """Validate configuration and return any issues"""
        issues = []
        

        required_sections = ['thresholds', 'ml_settings', 'protocols', 'database']
        for section in required_sections:
            if section not in self.config:
                issues.append(f"Missing required section: {section}")
        
        splunk_config = self.get_splunk_config()
        if splunk_config.get('enabled', False):
            required_splunk_keys = ['host', 'port', 'username', 'password']
            for key in required_splunk_keys:
                if not splunk_config.get(key):
                    issues.append(f"Missing Splunk configuration: {key}")
        
        paths_to_check = [
            ('ml_settings.model_path', 'ML model path'),
            ('database.path', 'Database path'),
            ('logging.file', 'Log file path')
        ]
        
        for path_key, description in paths_to_check:
            path = self.get(path_key)
            if path:
                path_dir = os.path.dirname(path)
                if path_dir and not os.path.exists(path_dir):
                    try:
                        os.makedirs(path_dir, exist_ok=True)
                        print(f"Created directory for {description}: {path_dir}")
                    except Exception as e:
                        issues.append(f"Cannot create directory for {description}: {e}")
        
        return issues
    
    def print_config_summary(self):
        """Print a summary of the current configuration"""
        print("\n" + "="*60)
        print("USB DLP System Configuration Summary")
        print("="*60)
        
        print(f"Configuration file: {self.config_file}")
        print(f"Large transfer threshold: {self.get('thresholds.large_transfer_mb', 'N/A')} MB")
        print(f"MTP transfer threshold: {self.get('thresholds.mtp_large_transfer_mb', 'N/A')} MB")
        print(f"MTP monitoring enabled: {self.is_mtp_enabled()}")
        print(f"Splunk integration enabled: {self.get_splunk_config().get('enabled', False)}")
        print(f"Database type: {self.get('database.type', 'N/A')}")
        print(f"Log level: {self.get('logging.level', 'N/A')}")
        print(f"Trusted devices: {len(self.get('device_trust.trusted_devices', []))}")
        
        # Validating
        issues = self.validate_config()
        if issues:
            print("\nConfiguration Issues:")
            for issue in issues:
                print(f"  - {issue}")
        else:
            print("\nConfiguration validation: PASSED")
        
        print("="*60)

config = USBConfig()

def get_config(key, default=None):
    """Get configuration value"""
    return config.get(key, default)

def set_config(key, value):
    """Set configuration value"""
    config.set(key, value)

def get_threat_thresholds():
    """Get threat detection thresholds"""
    return config.get_threat_thresholds()

def get_ml_settings():
    """Get ML settings"""
    return config.get_ml_settings()

def get_splunk_config():
    """Get Splunk configuration"""
    return config.get_splunk_config()

def get_mtp_config():
    """Get MTP configuration"""
    return config.get_mtp_monitoring_config()

def is_mtp_enabled():
    """Check if MTP monitoring is enabled"""
    return config.is_mtp_enabled()

def validate_config():
    """Validate configuration"""
    return config.validate_config()

def print_config_summary():
    """Print configuration summary"""
    return config.print_config_summary()

if __name__ == "__main__":
    # Test
    print("USB DLP System Configuration Test")
    config.print_config_summary()
    
    print("\nTesting configuration access:")
    print(f"Splunk config (primary method): {get_splunk_config()}")
    print(f"MTP file extensions (first 5): {get_config('mtp_monitoring.file_extensions_to_monitor', [])[:5]}")
    
    print(f"\nTesting splunk_integration key access:")
    print(f"  Direct access: {'splunk_integration' in config.config}")
    print(f"  Via get_splunk_config(): {bool(get_splunk_config())}")
    print(f"  Enabled status: {get_splunk_config().get('enabled', False)}")