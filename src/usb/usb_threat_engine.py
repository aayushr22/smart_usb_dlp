"""
Smart USB DLP System - Threat Detection Engine with Splunk Integration
Real-time threat analysis and response for USB data exfiltration
"""
import time
import sys
import os
import json
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import logging
from pathlib import Path
import requests
import warnings
warnings.filterwarnings('ignore')

current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

try:
    from usb_ml_model import USBMLModel
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

class SplunkLogger:
    def __init__(self):
        self.splunk_host = os.getenv('SPLUNK_HOST', 'localhost')
        self.splunk_port = os.getenv('SPLUNK_PORT', '8088')
        self.splunk_token = os.getenv('SPLUNK_TOKEN', '2b32ea42-8e5c-4dba-88b5-06998e6b3868')
        self.splunk_index = os.getenv('SPLUNK_INDEX', 'usb_security')
        
        # Setup
        self.logger = logging.getLogger('usb_threat_engine.splunk')
        handler = logging.FileHandler('tmp/usb_threat_engine_splunk.log')
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
    
    def send_to_splunk(self, event_data):
        """Send event to Splunk HTTP Event Collector"""
        try:
            url = f"https://{self.splunk_host}:{self.splunk_port}/services/collector"
            headers = {
                'Authorization': f'Splunk {self.splunk_token}',
                'Content-Type': 'application/json'
            }
            
            splunk_event = {
                "time": int(time.time()),
                "index": self.splunk_index,
                "source": "usb_threat_engine",
                "sourcetype": "usb_security_json",
                "event": event_data
            }
            
            response = requests.post(url, headers=headers, json=splunk_event, verify=False)
            if response.status_code == 200:
                self.logger.info(f"Event sent to Splunk successfully")
            else:
                self.logger.error(f"Failed to send to Splunk: {response.status_code}")
                
        except Exception as e:
            self.logger.error(f"Splunk integration error: {str(e)}")
    
    def log_usb_event(self, event_type, event_data, threat_level="INFO", details=None):
        """Log USB security event to Splunk"""
        splunk_event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "threat_level": threat_level,
            "details": details or {},
            "system_info": {
                "hostname": os.getenv('COMPUTERNAME', 'unknown'),
                "user": os.getenv('USERNAME', 'unknown')
            },
            "event_data": event_data
        }
        
        self.logger.info(f"USB Event: {json.dumps(splunk_event)}")
        
        self.send_to_splunk(splunk_event)
        
        return splunk_event

# main logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('tmp/usb_threat_engine.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class USBThreatEngine:
    """
    Comprehensive threat detection engine for USB activities
    Combines rule-based detection with ML-powered anomaly detection
    """
    
    def __init__(self, config_path='tmp/threat_config.json'):
        self.config_path = config_path
        self.ml_model = None
        self.threat_rules = {}
        self.user_baselines = {}
        self.device_registry = {}
        self.threat_history = []
        self.splunk_logger = SplunkLogger()
        
        if ML_AVAILABLE:
            try:
                self.ml_model = USBMLModel()
                logger.info("ML model loaded successfully")
            except Exception as e:
                logger.warning(f"Failed to load ML model: {e}")
                self.ml_model = None
        
        # Load 
        self.load_config()
        
        # Initialize
        self.init_threat_rules()
    
    def load_config(self):
        """Load threat detection configuration"""
        default_config = {
            'thresholds': {
                'large_transfer_mb': 1000,
                'frequent_access_count': 10,
                'suspicious_hours': [0, 1, 2, 3, 4, 5, 22, 23],
                'max_devices_per_user': 5,
                'anomaly_score_threshold': -0.5
            },
            'risk_weights': {
                'size_factor': 0.3,
                'frequency_factor': 0.2,
                'time_factor': 0.2,
                'device_factor': 0.1,
                'pattern_factor': 0.2
            },
            'response_actions': {
                'CRITICAL': ['block', 'alert', 'log'],
                'HIGH': ['alert', 'log'],
                'MEDIUM': ['log'],
                'LOW': ['log']
            },
            'splunk_integration': {
                'enabled': True,
                'log_all_events': False,
                'log_threats_only': True
            }
        }
        
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    self.config = json.load(f)
                logger.info("Configuration loaded from file")
            else:
                self.config = default_config
                self.save_config()
                logger.info("Default configuration created")
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            self.config = default_config
    
    def save_config(self):
        """Save current configuration to file"""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving config: {e}")
    
    def init_threat_rules(self):
        """Initialize threat detection rules"""
        self.threat_rules = {
            'large_transfer': {
                'name': 'Large Data Transfer',
                'description': 'Detects unusually large data transfers',
                'severity': 'HIGH',
                'check_function': self._check_large_transfer
            },
            'off_hours_activity': {
                'name': 'Off-Hours Activity',
                'description': 'Detects USB activity during suspicious hours',
                'severity': 'MEDIUM',
                'check_function': self._check_off_hours
            },
            'frequent_access': {
                'name': 'Frequent Access Pattern',
                'description': 'Detects excessive USB access frequency',
                'severity': 'MEDIUM',
                'check_function': self._check_frequent_access
            },
            'multiple_devices': {
                'name': 'Multiple Device Usage',
                'description': 'Detects users with unusually many devices',
                'severity': 'MEDIUM',
                'check_function': self._check_multiple_devices
            },
            'unknown_device': {
                'name': 'Unknown Device',
                'description': 'Detects usage of unregistered devices',
                'severity': 'HIGH',
                'check_function': self._check_unknown_device
            },
            'rapid_successive_transfers': {
                'name': 'Rapid Successive Transfers',
                'description': 'Detects multiple rapid transfers',
                'severity': 'HIGH',
                'check_function': self._check_rapid_transfers
            },
            'weekend_activity': {
                'name': 'Weekend Activity',
                'description': 'Detects unusual weekend USB activity',
                'severity': 'LOW',
                'check_function': self._check_weekend_activity
            }
        }
        
        logger.info(f"Initialized {len(self.threat_rules)} threat detection rules")
    
    def analyze_event(self, event):
        """
        Analyze USB event for potential threats
        Returns: threat_score (float)
        """
        try:
            threat_score = 0
            if event.get('action') == 'connect':
                threat_score += 10
                if self.config['splunk_integration']['enabled']:
                    self.splunk_logger.log_usb_event(
                        event_type="usb_device_connected",
                        event_data=event,
                        threat_level="INFO"
                    )
            if event.get('device_type') == 'unknown':
                threat_score += 20
            if event.get('size', 0) > 1000000:
                threat_score += 15
            return threat_score
            
        except Exception as e:
            logging.error(f"Event analysis failed: {str(e)}")
            if self.config['splunk_integration']['enabled']:
                self.splunk_logger.log_usb_event(
                    event_type="analysis_error",
                    event_data=event,
                    threat_level="ERROR",
                    details={"error": str(e)}
                )
            return 0

    def analyze_activity(self, activity_data):
        """
        Main threat analysis function
        Analyzes USB activity data and returns threat assessment
        """
        if isinstance(activity_data, dict):
            activity_data = pd.DataFrame([activity_data])
        elif not isinstance(activity_data, pd.DataFrame):
            activity_data = pd.DataFrame(activity_data)
        
        results = []
        
        for idx, record in activity_data.iterrows():
            threat_assessment = self._analyze_single_record(record)
            results.append(threat_assessment)
            
            # Log to Splunk
            if self.config['splunk_integration']['enabled']:
                if (self.config['splunk_integration']['log_all_events'] or 
                    (self.config['splunk_integration']['log_threats_only'] and 
                     threat_assessment['threats_detected'])):
                    self._log_threat_assessment(threat_assessment)
        
        return results


    def _check_large_transfer(self, record):
        """Check for unusually large data transfers"""
        try:
            bytes_written = record.get('bytes_written', 0)
            threshold = self.config['thresholds']['large_transfer_mb'] * 1024 * 1024
            
            if bytes_written > threshold:
                return {
                    'is_threat': True,
                    'details': {
                        'bytes_written': bytes_written,
                        'threshold': threshold,
                        'size_mb': bytes_written / (1024 * 1024)
                    }
                }
            return {'is_threat': False}
        except Exception as e:
            logger.error(f"Error in _check_large_transfer: {e}")
            return {'is_threat': False}
    
    def _check_off_hours(self, record):
        """Check for off-hours USB activity"""
        try:
            timestamp = record.get('timestamp', datetime.now().isoformat())
            if isinstance(timestamp, str):
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            else:
                dt = timestamp
            
            hour = dt.hour
            suspicious_hours = self.config['thresholds']['suspicious_hours']
            
            if hour in suspicious_hours:
                return {
                    'is_threat': True,
                    'details': {
                        'hour': hour,
                        'suspicious_hours': suspicious_hours
                    }
                }
            return {'is_threat': False}
        except Exception as e:
            logger.error(f"Error in _check_off_hours: {e}")
            return {'is_threat': False}
    
    def _check_frequent_access(self, record):
        """Check for frequent access patterns"""
        try:
            user = record.get('user', 'unknown')
            recent_threshold = datetime.now() - timedelta(hours=1)
            recent_accesses = [
                t for t in self.threat_history 
                if t.get('user') == user and 
                datetime.fromisoformat(t.get('timestamp', '1970-01-01')) > recent_threshold
            ]
            
            threshold = self.config['thresholds']['frequent_access_count']
            
            if len(recent_accesses) >= threshold:
                return {
                    'is_threat': True,
                    'details': {
                        'user': user,
                        'recent_accesses': len(recent_accesses),
                        'threshold': threshold
                    }
                }
            return {'is_threat': False}
        except Exception as e:
            logger.error(f"Error in _check_frequent_access: {e}")
            return {'is_threat': False}
    
    def _check_multiple_devices(self, record):
        """Check for users with multiple devices"""
        try:
            user = record.get('user', 'unknown')
            device_id = record.get('device_id', 'unknown')
            
            # Track
            if user not in self.user_baselines:
                self.user_baselines[user] = {'devices': set()}
            
            self.user_baselines[user]['devices'].add(device_id)
            device_count = len(self.user_baselines[user]['devices'])
            
            threshold = self.config['thresholds']['max_devices_per_user']
            
            if device_count > threshold:
                return {
                    'is_threat': True,
                    'details': {
                        'user': user,
                        'device_count': device_count,
                        'threshold': threshold,
                        'devices': list(self.user_baselines[user]['devices'])
                    }
                }
            return {'is_threat': False}
        except Exception as e:
            logger.error(f"Error in _check_multiple_devices: {e}")
            return {'is_threat': False}
    
    def _check_unknown_device(self, record):
        """Check for unknown/unregistered devices"""
        try:
            device_id = record.get('device_id', 'unknown')
            if device_id not in self.device_registry:
                self.device_registry[device_id] = {
                    'first_seen': datetime.now().isoformat(),
                    'approved': False
                }
                
                return {
                    'is_threat': True,
                    'details': {
                        'device_id': device_id,
                        'reason': 'Unknown device not in registry'
                    }
                }
            
            # Check if device is approved
            if not self.device_registry[device_id].get('approved', False):
                return {
                    'is_threat': True,
                    'details': {
                        'device_id': device_id,
                        'reason': 'Device not approved'
                    }
                }
            
            return {'is_threat': False}
        except Exception as e:
            logger.error(f"Error in _check_unknown_device: {e}")
            return {'is_threat': False}
    
    def _check_rapid_transfers(self, record):
        """Check for rapid successive transfers"""
        try:
            user = record.get('user', 'unknown')
            device_id = record.get('device_id', 'unknown')
            timestamp = record.get('timestamp', datetime.now().isoformat())
            
            if isinstance(timestamp, str):
                current_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            else:
                current_time = timestamp
            
            # Check for last 5 minutes
            recent_threshold = current_time - timedelta(minutes=5)
            recent_transfers = [
                t for t in self.threat_history 
                if t.get('user') == user and 
                t.get('device_id') == device_id and
                datetime.fromisoformat(t.get('timestamp', '1970-01-01')) > recent_threshold
            ]
            
            if len(recent_transfers) >= 3:
                return {
                    'is_threat': True,
                    'details': {
                        'user': user,
                        'device_id': device_id,
                        'recent_transfers': len(recent_transfers),
                        'time_window': '5 minutes'
                    }
                }
            return {'is_threat': False}
        except Exception as e:
            logger.error(f"Error in _check_rapid_transfers: {e}")
            return {'is_threat': False}
    
    def _check_weekend_activity(self, record):
        """Check for weekend USB activity"""
        try:
            timestamp = record.get('timestamp', datetime.now().isoformat())
            if isinstance(timestamp, str):
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            else:
                dt = timestamp
            if dt.weekday() >= 5:
                return {
                    'is_threat': True,
                    'details': {
                        'day': dt.strftime('%A'),
                        'weekday': dt.weekday()
                    }
                }
            return {'is_threat': False}
        except Exception as e:
            logger.error(f"Error in _check_weekend_activity: {e}")
            return {'is_threat': False}
    
    def _run_ml_analysis(self, record):
        """Run ML-based anomaly detection"""
        try:
            if not self.ml_model:
                return {'is_anomaly': False}
            
            # Convert
            features = self._extract_features(record)
            anomaly_score = self.ml_model.predict_anomaly(features)
            
            threshold = self.config['thresholds']['anomaly_score_threshold']
            is_anomaly = anomaly_score < threshold
            
            return {
                'is_anomaly': is_anomaly,
                'anomaly_score': anomaly_score,
                'severity': 'HIGH' if anomaly_score < -1.0 else 'MEDIUM',
                'details': {
                    'anomaly_score': anomaly_score,
                    'threshold': threshold
                }
            }
        except Exception as e:
            logger.error(f"Error in _run_ml_analysis: {e}")
            return {'is_anomaly': False}
    
    def _extract_features(self, record):
        """Extract features for ML analysis"""
        try:
            return {
                'bytes_written': record.get('bytes_written', 0),
                'hour': datetime.now().hour,
                'weekday': datetime.now().weekday(),
                'user_hash': hash(record.get('user', 'unknown')) % 1000,
                'device_hash': hash(record.get('device_id', 'unknown')) % 1000
            }
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            return {}
    
    def _calculate_risk_score(self, record, threat_assessment):
        """Calculate overall risk score"""
        try:
            base_score = 0.0
            weights = self.config['risk_weights']
            
            # Size 
            bytes_written = record.get('bytes_written', 0)
            if bytes_written > 0:
                size_factor = min(bytes_written / (1024 * 1024 * 1024), 1.0)  # Normalize to GB
                base_score += size_factor * weights['size_factor']
            
            # Frequency 
            user = record.get('user', 'unknown')
            user_threats = [t for t in self.threat_history if t.get('user') == user]
            frequency_factor = min(len(user_threats) / 10.0, 1.0)
            base_score += frequency_factor * weights['frequency_factor']
            
            # Time
            current_hour = datetime.now().hour
            if current_hour in self.config['thresholds']['suspicious_hours']:
                base_score += weights['time_factor']
            
            # Device
            device_id = record.get('device_id', 'unknown')
            if device_id not in self.device_registry:
                base_score += weights['device_factor']
            
            # Pattern 
            threat_count = len(threat_assessment.get('threats_detected', []))
            pattern_factor = min(threat_count / 5.0, 1.0)
            base_score += pattern_factor * weights['pattern_factor']
            
            # ML
            if threat_assessment.get('ml_anomaly_score'):
                ml_score = abs(threat_assessment['ml_anomaly_score'])
                ml_factor = min(ml_score / 2.0, 1.0)
                base_score += ml_factor * 0.2
            
            return min(base_score, 1.0)
        except Exception as e:
            logger.error(f"Error calculating risk score: {e}")
            return 0.0
    
    def _determine_risk_level(self, risk_score):
        """Determine risk level based on score"""
        if risk_score >= 0.8:
            return 'CRITICAL'
        elif risk_score >= 0.6:
            return 'HIGH'
        elif risk_score >= 0.3:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _get_recommended_actions(self, threat_assessment):
        """Get recommended actions based on risk level"""
        risk_level = threat_assessment.get('risk_level', 'LOW')
        return self.config['response_actions'].get(risk_level, ['log'])
    
    def _generate_threat_details(self, record, threat_assessment):
        """Generate detailed threat information"""
        return {
            'record_summary': {
                'user': record.get('user', 'unknown'),
                'device_id': record.get('device_id', 'unknown'),
                'bytes_written': record.get('bytes_written', 0),
                'timestamp': record.get('timestamp', datetime.now().isoformat())
            },
            'threat_summary': {
                'total_threats': len(threat_assessment.get('threats_detected', [])),
                'risk_score': threat_assessment.get('risk_score', 0.0),
                'risk_level': threat_assessment.get('risk_level', 'LOW')
            }
        }
    
    def update_user_baseline(self, user, record):
        """Update user baseline behavior"""
        try:
            if user not in self.user_baselines:
                self.user_baselines[user] = {
                    'devices': set(),
                    'total_transfers': 0,
                    'total_bytes': 0,
                    'first_seen': datetime.now().isoformat(),
                    'last_seen': datetime.now().isoformat()
                }
            
            baseline = self.user_baselines[user]
            baseline['devices'].add(record.get('device_id', 'unknown'))
            baseline['total_transfers'] += 1
            baseline['total_bytes'] += record.get('bytes_written', 0)
            baseline['last_seen'] = datetime.now().isoformat()
            
        except Exception as e:
            logger.error(f"Error updating user baseline: {e}")
    
    def get_threat_statistics(self):
        """Get threat detection statistics"""
        try:
            total_threats = len(self.threat_history)
            
            # Risk level
            risk_levels = {}
            threat_types = {}
            
            for threat in self.threat_history:
                risk_level = threat.get('risk_level', 'LOW')
                risk_levels[risk_level] = risk_levels.get(risk_level, 0) + 1
                
                for detected_threat in threat.get('threats_detected', []):
                    threat_name = detected_threat.get('name', 'Unknown')
                    threat_types[threat_name] = threat_types.get(threat_name, 0) + 1
            
            return {
                'total_threats': total_threats,
                'risk_level_breakdown': risk_levels,
                'threat_breakdown': threat_types,
                'unique_users': len(self.user_baselines),
                'unique_devices': len(self.device_registry)
            }
        except Exception as e:
            logger.error(f"Error getting threat statistics: {e}")
            return {
                'total_threats': 0,
                'risk_level_breakdown': {},
                'threat_breakdown': {},
                'unique_users': 0,
                'unique_devices': 0
            }
    
    def process_batch(self, data_file):
        """Process a batch of USB activity data"""
        try:
            if self.config['splunk_integration']['enabled']:
                self.splunk_logger.log_usb_event(
                    event_type="batch_processing_start",
                    event_data={"file": data_file},
                    threat_level="INFO"
                )
            
            if data_file.endswith('.csv'):
                data = pd.read_csv(data_file)
            else:
                with open(data_file, 'r') as f:
                    data = pd.DataFrame(json.load(f))
            
            logger.info(f"Processing {len(data)} records from {data_file}")
            
            # Analyze
            results = []
            for idx, record in data.iterrows():
                threat_assessment = self._analyze_single_record(record)
                results.append(threat_assessment)
                
                self.update_user_baseline(record.get('user', 'unknown'), record)
            
            # summary
            total_threats = sum(1 for r in results if r['threats_detected'])
            threat_rate = (total_threats / len(results)) * 100
            
            logger.info(f"Batch processing completed: {total_threats} threats detected ({threat_rate:.1f}%)")
            
            if self.config['splunk_integration']['enabled']:
                self.splunk_logger.log_usb_event(
                    event_type="batch_processing_complete",
                    event_data={
                        "file": data_file,
                        "total_records": len(results),
                        "threats_detected": total_threats,
                        "threat_rate": threat_rate
                    },
                    threat_level="INFO"
                )
            
            return results
            
        except Exception as e:
            logger.error(f"Error processing batch: {e}")
            # Log batch error
            if self.config['splunk_integration']['enabled']:
                self.splunk_logger.log_usb_event(
                    event_type="batch_processing_error",
                    event_data={"file": data_file},
                    threat_level="ERROR",
                    details={"error": str(e)}
                )
            raise

def main():
    """Main execution function"""
    if len(sys.argv) < 2:
        print("Usage: python usb_threat_engine.py <command> [args]")
        print("Commands: analyze, batch, stats, config")
        sys.exit(1)
    
    command = sys.argv[1].lower()
    engine = USBThreatEngine()
    
    if command == 'analyze':
        # Analyze
        sample_data = '../lookups/usb_activity_sample.csv'
        if os.path.exists(sample_data):
            results = engine.process_batch(sample_data)
            print(f"Analyzed {len(results)} records")
            
            # top threats
            threats = [r for r in results if r['threats_detected']]
            print(f"\nFound {len(threats)} threats:")
            for threat in threats[:5]:
                print(f"  User: {threat['user']}, Risk: {threat['risk_level']}, Score: {threat['risk_score']}")
        else:
            print("Sample data not found. Run generate_sample_data.py first.")
    
    elif command == 'batch':
        if len(sys.argv) < 3:
            print("Usage: python usb_threat_engine.py batch <data_file>")
            sys.exit(1)
        
        data_file = sys.argv[2]
        results = engine.process_batch(data_file)
        print(f"Processed {len(results)} records")
    
    elif command == 'stats':
        stats = engine.get_threat_statistics()
        print("Threat Detection Statistics:")
        print(f"  Total Threats: {stats['total_threats']}")
        print(f"  Risk Level Breakdown: {stats['risk_level_breakdown']}")
        print(f"  Top Threat Types: {stats['threat_breakdown']}")
    
    elif command == 'config':
        print("Current Configuration:")
        print(json.dumps(engine.config, indent=2))
    
    else:
        print(f"Unknown command: {command}")

if __name__ == "__main__":
    main()