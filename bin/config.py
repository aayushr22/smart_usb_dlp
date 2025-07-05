#!/usr/bin/env python3
"""
Smart USB DLP System - Configuration Management
Central configuration for threat detection parameters and system settings
"""

import os
import json
from pathlib import Path

class USBConfig:
    """Configuration management for USB threat detection system"""
    
    def __init__(self, config_file='config.json'):
        self.config_file = config_file
        self.config = self.load_config()
    
    def load_config(self):
        """Load configuration from file or return defaults"""
        default_config = {
            # Threat Detection Thresholds
            'thresholds': {
                'large_transfer_mb': 1000,
                'frequent_access_count': 10,
                'suspicious_hours': [0, 1, 2, 3, 4, 5, 22, 23],
                'max_devices_per_user': 5,
                'anomaly_score_threshold': -0.5,
                'critical_risk_score': 8.0,
                'high_risk_score': 5.0,
                'medium_risk_score': 2.0
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
                    'device_risk_score', 'data_velocity'
                ],
                'threat_indicators': [
                    'known_malicious_pattern', 'suspicious_file_types',
                    'encryption_detected', 'steganography_risk',
                    'data_exfiltration_signature', 'insider_threat_score'
                ]
            },
            
            # Splunk Integration
            'splunk': {
                'host': 'localhost',
                'port': 8089,
                'username': 'admin',
                'password': 'changeme',
                'index': 'usb_security',
                'sourcetype': 'usb:threat',
                'ssl_verify': False
            },
            
            # Database Settings
            'database': {
                'type': 'sqlite',
                'path': 'tmp/usb_threats.db',
                'backup_interval_hours': 6
            },
            
            # Logging Configuration
            'logging': {
                'level': 'INFO',
                'file': 'tmp/usb_threat_engine.log',
                'max_size_mb': 100,
                'backup_count': 5
            },
            
            # Device Categories and Risk Levels
            'device_categories': {
                'USB_Flash': {'risk_level': 'MEDIUM', 'max_size_gb': 128},
                'External_HDD': {'risk_level': 'HIGH', 'max_size_gb': 5000},
                'USB_SSD': {'risk_level': 'HIGH', 'max_size_gb': 2000},
                'Mobile_Device': {'risk_level': 'LOW', 'max_size_gb': 512},
                'Unknown': {'risk_level': 'CRITICAL', 'max_size_gb': 0}
            },
            
            # File Type Risk Assessment
            'file_types': {
                'documents': {'risk_level': 'LOW', 'extensions': ['.doc', '.pdf', '.txt']},
                'images': {'risk_level': 'LOW', 'extensions': ['.jpg', '.png', '.gif']},
                'software': {'risk_level': 'HIGH', 'extensions': ['.exe', '.msi', '.deb']},
                'data': {'risk_level': 'MEDIUM', 'extensions': ['.csv', '.json', '.xml']},
                'backup': {'risk_level': 'HIGH', 'extensions': ['.zip', '.rar', '.7z']},
                'encrypted': {'risk_level': 'CRITICAL', 'extensions': ['.gpg', '.enc']}
            },
            
            # Alert Settings
            'alerts': {
                'email_enabled': True,
                'email_server': 'smtp.company.com',
                'email_port': 587,
                'email_from': 'security@company.com',
                'email_to': ['admin@company.com', 'security-team@company.com'],
                'slack_enabled': False,
                'slack_webhook': '',
                'sms_enabled': False
            },
            
            # Performance Settings
            'performance': {
                'batch_size': 1000,
                'max_concurrent_analyses': 5,
                'cache_size_mb': 256,
                'cleanup_interval_hours': 12
            }
        }
        
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    loaded_config = json.load(f)
                    # Merge with defaults to ensure all keys exist
                    return self.merge_configs(default_config, loaded_config)
            except Exception as e:
                print(f"Error loading config: {e}. Using defaults.")
                return default_config
        else:
            self.save_config(default_config)
            return default_config
    
    def merge_configs(self, default, loaded):
        """Recursively merge loaded config with defaults"""
        for key, value in loaded.items():
            if key in default and isinstance(default[key], dict) and isinstance(value, dict):
                default[key] = self.merge_configs(default[key], value)
            else:
                default[key] = value
        return default
    
    def save_config(self, config=None):
        """Save configuration to file"""
        if config is None:
            config = self.config
        
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            print(f"Configuration saved to {self.config_file}")
        except Exception as e:
            print(f"Error saving config: {e}")
    
    def get(self, key, default=None):
        """Get configuration value with dot notation support"""
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
        return self.config['thresholds']
    
    def get_ml_settings(self):
        """Get machine learning settings"""
        return self.config['ml_settings']
    
    def get_splunk_config(self):
        """Get Splunk configuration"""
        return self.config['splunk']
    
    def get_response_actions(self, risk_level):
        """Get response actions for risk level"""
        return self.config['response_actions'].get(risk_level, ['log'])
    
    def get_device_risk_level(self, device_type):
        """Get risk level for device type"""
        return self.config['device_categories'].get(device_type, {}).get('risk_level', 'MEDIUM')
    
    def is_suspicious_hour(self, hour):
        """Check if hour is suspicious"""
        return hour in self.config['thresholds']['suspicious_hours']
    
    def get_risk_weights(self):
        """Get risk calculation weights"""
        return self.config['risk_weights']

# Global configuration instance
config = USBConfig()

# Convenience functions
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

if __name__ == "__main__":
    # Test configuration
    print("USB DLP System Configuration")
    print("=" * 40)
    print(f"Large transfer threshold: {get_config('thresholds.large_transfer_mb')} MB")
    print(f"Suspicious hours: {get_config('thresholds.suspicious_hours')}")
    print(f"ML model path: {get_config('ml_settings.model_path')}")
    print(f"Splunk host: {get_config('splunk.host')}")
    print(f"Database type: {get_config('database.type')}")