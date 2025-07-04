#!/usr/bin/env python3
"""
Smart USB DLP System - Threat Detection Engine
Real-time threat analysis and response for USB data exfiltration
"""

import sys
import os
import json
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import logging
from pathlib import Path
import warnings
warnings.filterwarnings('ignore')

# Import ML model if available
try:
    from usb_ml_model import USBMLModel
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/tmp/usb_threat_engine.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class USBThreatEngine:
    """
    Comprehensive threat detection engine for USB activities
    Combines rule-based detection with ML-powered anomaly detection
    """
    
    def __init__(self, config_path='/tmp/threat_config.json'):
        self.config_path = config_path
        self.ml_model = None
        self.threat_rules = {}
        self.user_baselines = {}
        self.device_registry = {}
        self.threat_history = []
        
        # Initialize ML model if available
        if ML_AVAILABLE:
            try:
                self.ml_model = USBMLModel()
                logger.info("ML model loaded successfully")
            except Exception as e:
                logger.warning(f"Failed to load ML model: {e}")
                self.ml_model = None
        
        # Load configuration
        self.load_config()
        
        # Initialize threat rules
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
        
        return results
    
    def _analyze_single_record(self, record):
        """Analyze a single USB activity record"""
        threat_assessment = {
            'timestamp': record.get('timestamp', datetime.now().isoformat()),
            'user': record.get('user', 'unknown'),
            'device_id': record.get('device_id', 'unknown'),
            'bytes_written': record.get('bytes_written', 0),
            'threats_detected': [],
            'risk_score': 0.0,
            'risk_level': 'LOW',
            'recommended_actions': [],
            'ml_anomaly_score': None,
            'threat_details': {}
        }
        
        # Run rule-based threat detection
        for rule_id, rule in self.threat_rules.items():
            try:
                threat_result = rule['check_function'](record)
                if threat_result['is_threat']:
                    threat_assessment['threats_detected'].append({
                        'rule_id': rule_id,
                        'name': rule['name'],
                        'description': rule['description'],
                        'severity': rule['severity'],
                        'details': threat_result.get('details', {})
                    })
            except Exception as e:
                logger.error(f"Error in rule {rule_id}: {e}")
        
        # Run ML-based anomaly detection if available
        if self.ml_model and ML_AVAILABLE:
            try:
                ml_results = self._run_ml_analysis(record)
                threat_assessment['ml_anomaly_score'] = ml_results.get('anomaly_score')
                if ml_results.get('is_anomaly'):
                    threat_assessment['threats_detected'].append({
                        'rule_id': 'ml_anomaly',
                        'name': 'ML Anomaly Detection',
                        'description': 'Machine learning detected anomalous pattern',
                        'severity': ml_results.get('severity', 'MEDIUM'),
                        'details': ml_results.get('details', {})
                    })
            except Exception as e:
                logger.error(f"Error in ML analysis: {e}")
        
        # Calculate overall risk score
        threat_assessment['risk_score'] = self._calculate_risk_score(record, threat_assessment)
        threat_assessment['risk_level'] = self._determine_risk_level(threat_assessment['risk_score'])
        
        # Determine recommended actions
        threat_assessment['recommended_actions'] = self._get_recommended_actions(threat_assessment)
        
        # Store threat details
        threat_assessment['threat_details'] = self._generate_threat_details(record, threat_assessment)
        
        return threat_assessment
    
    def _check_large_transfer(self, record):
        """Check for large data transfer threat"""
        threshold_bytes = self.config['thresholds']['large_transfer_mb'] * 1024 * 1024
        bytes_written = record.get('bytes_written', 0)
        
        if bytes_written > threshold_bytes:
            return {
                'is_threat': True,
                'details': {
                    'bytes_written': bytes_written,
                    'threshold': threshold_bytes,
                    'size_gb': round(bytes_written / (1024**3), 2)
                }
            }
        return {'is_threat': False}
    
    def _check_off_hours(self, record):
        """Check for off-hours activity"""
        try:
            if 'timestamp' in record:
                timestamp = pd.to_datetime(record['timestamp'])
                hour = timestamp.hour
            else:
                hour = record.get('hour', 12)
            
            suspicious_hours = self.config['thresholds']['suspicious_hours']
            
            if hour in suspicious_hours:
                return {
                    'is_threat': True,
                    'details': {
                        'hour': hour,
                        'suspicious_hours': suspicious_hours
                    }
                }
        except Exception as e:
            logger.error(f"Error checking off-hours: {e}")
        
        return {'is_threat': False}
    
    def _check_frequent_access(self, record):
        """Check for frequent access pattern"""
        user = record.get('user', 'unknown')
        current_time = datetime.now()
        
        # Count recent activities for this user (last hour)
        recent_activities = [
            activity for activity in self.threat_history
            if activity.get('user') == user and
            (current_time - pd.to_datetime(activity.get('timestamp', current_time))).total_seconds() < 3600
        ]
        
        threshold = self.config['thresholds']['frequent_access_count']
        
        if len(recent_activities) >= threshold:
            return {
                'is_threat': True,
                'details': {
                    'recent_count': len(recent_activities),
                    'threshold': threshold,
                    'time_window': '1 hour'
                }
            }
        return {'is_threat': False}
    
    def _check_multiple_devices(self, record):
        """Check for multiple device usage"""
        user = record.get('user', 'unknown')
        
        if user not in self.device_registry:
            self.device_registry[user] = set()
        
        device_id = record.get('device_id', 'unknown')
        self.device_registry[user].add(device_id)
        
        max_devices = self.config['thresholds']['max_devices_per_user']
        
        if len(self.device_registry[user]) > max_devices:
            return {
                'is_threat': True,
                'details': {
                    'device_count': len(self.device_registry[user]),
                    'threshold': max_devices,
                    'devices': list(self.device_registry[user])
                }
            }
        return {'is_threat': False}
    
    def _check_unknown_device(self, record):
        """Check for unknown device usage"""
        device_type = record.get('device_type', 'Unknown')
        manufacturer = record.get('manufacturer', 'Unknown')
        
        if device_type == 'Unknown' or manufacturer == 'Unknown':
            return {
                'is_threat': True,
                'details': {
                    'device_type': device_type,
                    'manufacturer': manufacturer,
                    'device_id': record.get('device_id', 'unknown')
                }
            }
        return {'is_threat': False}
    
    def _check_rapid_transfers(self, record):
        """Check for rapid successive transfers"""
        user = record.get('user', 'unknown')
        current_time = datetime.now()
        
        # Count activities in last 5 minutes
        recent_activities = [
            activity for activity in self.threat_history
            if activity.get('user') == user and
            (current_time - pd.to_datetime(activity.get('timestamp', current_time))).total_seconds() < 300
        ]
        
        if len(recent_activities) >= 3:  # 3 or more in 5 minutes
            return {
                'is_threat': True,
                'details': {
                    'rapid_count': len(recent_activities),
                    'time_window': '5 minutes'
                }
            }
        return {'is_threat': False}
    
    def _check_weekend_activity(self, record):
        """Check for weekend activity"""
        try:
            if 'timestamp' in record:
                timestamp = pd.to_datetime(record['timestamp'])
                day_of_week = timestamp.weekday()
            else:
                day_of_week = record.get('day_of_week', 1)
            
            # Weekend: Saturday (5) and Sunday (6)
            if day_of_week >= 5:
                return {
                    'is_threat': True,
                    'details': {
                        'day_of_week': day_of_week,
                        'day_name': ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'][day_of_week]
                    }
                }
        except Exception as e:
            logger.error(f"Error checking weekend activity: {e}")
        
        return {'is_threat': False}
    
    def _run_ml_analysis(self, record):
        """Run ML-based anomaly detection"""
        try:
            # Prepare data for ML model
            df = pd.DataFrame([record])
            df = self.ml_model.extract_features(df)
            
            # Get ML predictions
            results = self.ml_model.predict_anomalies(df)
            
            if len(results) > 0:
                result = results.iloc[0]
                is_anomaly = result.get('combined_anomaly', 0) == 1
                anomaly_score = result.get('anomaly_score', 0)
                risk_level = result.get('risk_level', 'LOW')
                
                return {
                    'is_anomaly': is_anomaly,
                    'anomaly_score': anomaly_score,
                    'severity': risk_level,
                    'details': {
                        'dbscan_anomaly': result.get('dbscan_anomaly', 0),
                        'isolation_anomaly': result.get('isolation_anomaly', 0),
                        'risk_level': risk_level
                    }
                }
        except Exception as e:
            logger.error(f"ML analysis failed: {e}")
        
        return {'is_anomaly': False, 'anomaly_score': 0}
    
    def _calculate_risk_score(self, record, threat_assessment):
        """Calculate overall risk score"""
        base_score = 0.0
        weights = self.config['risk_weights']
        
        # Size factor
        bytes_written = record.get('bytes_written', 0)
        size_score = min(bytes_written / (1024**3), 5.0)  # Cap at 5GB
        base_score += size_score * weights['size_factor']
        
        # Frequency factor (based on threat count)
        threat_count = len(threat_assessment['threats_detected'])
        frequency_score = min(threat_count * 2.0, 10.0)  # Cap at 10
        base_score += frequency_score * weights['frequency_factor']
        
        # Time factor
        try:
            if 'timestamp' in record:
                timestamp = pd.to_datetime(record['timestamp'])
                hour = timestamp.hour
            else:
                hour = record.get('hour', 12)
            
            # Higher score for off-hours
            if hour in self.config['thresholds']['suspicious_hours']:
                time_score = 5.0
            else:
                time_score = 1.0
            base_score += time_score * weights['time_factor']
        except:
            pass
        
        # Device factor
        device_type = record.get('device_type', 'Unknown')
        if device_type == 'Unknown':
            device_score = 8.0
        elif device_type in ['External_HDD', 'USB_SSD']:
            device_score = 3.0
        else:
            device_score = 1.0
        base_score += device_score * weights['device_factor']
        
        # Pattern factor (ML anomaly score)
        ml_score = threat_assessment.get('ml_anomaly_score', 0)
        if ml_score:
            pattern_score = abs(ml_score) * 5.0  # Scale anomaly score
            base_score += pattern_score * weights['pattern_factor']
        
        return round(base_score, 2)
    
    def _determine_risk_level(self, risk_score):
        """Determine risk level based on score"""
        if risk_score >= 8.0:
            return 'CRITICAL'
        elif risk_score >= 5.0:
            return 'HIGH'
        elif risk_score >= 2.0:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _get_recommended_actions(self, threat_assessment):
        """Get recommended actions based on risk level"""
        risk_level = threat_assessment['risk_level']
        return self.config['response_actions'].get(risk_level, ['log'])
    
    def _generate_threat_details(self, record, threat_assessment):
        """Generate detailed threat information"""
        return {
            'analysis_time': datetime.now().isoformat(),
            'user_profile': self._get_user_profile(record.get('user', 'unknown')),
            'device_info': {
                'device_id': record.get('device_id', 'unknown'),
                'device_type': record.get('device_type', 'Unknown'),
                'manufacturer': record.get('manufacturer', 'Unknown')
            },
            'transfer_info': {
                'bytes_written': record.get('bytes_written', 0),
                'session_duration': record.get('session_duration', 0),
                'size_mb': round(record.get('bytes_written', 0) / (1024**2), 2)
            },
            'threat_summary': {
                'total_threats': len(threat_assessment['threats_detected']),
                'highest_severity': self._get_highest_severity(threat_assessment['threats_detected']),
                'risk_score': threat_assessment['risk_score'],
                'risk_level': threat_assessment['risk_level']
            }
        }
    
    def _get_user_profile(self, user):
        """Get or create user profile"""
        if user not in self.user_baselines:
            self.user_baselines[user] = {
                'total_activities': 0,
                'total_bytes': 0,
                'device_count': 0,
                'threat_count': 0,
                'last_activity': None
            }
        
        return self.user_baselines[user]
    
    def _get_highest_severity(self, threats):
        """Get highest severity from threat list"""
        if not threats:
            return 'NONE'
        
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        for severity in severity_order:
            if any(threat['severity'] == severity for threat in threats):
                return severity
        return 'LOW'
    
    def update_user_baseline(self, user, activity_record):
        """Update user baseline with new activity"""
        if user not in self.user_baselines:
            self.user_baselines[user] = {
                'total_activities': 0,
                'total_bytes': 0,
                'device_count': 0,
                'threat_count': 0,
                'last_activity': None
            }
        
        profile = self.user_baselines[user]
        profile['total_activities'] += 1
        profile['total_bytes'] += activity_record.get('bytes_written', 0)
        profile['last_activity'] = activity_record.get('timestamp', datetime.now().isoformat())
        
        if user in self.device_registry:
            profile['device_count'] = len(self.device_registry[user])
    
    def get_threat_statistics(self):
        """Get threat detection statistics"""
        total_threats = len(self.threat_history)
        
        if total_threats == 0:
            return {
                'total_threats': 0,
                'threat_breakdown': {},
                'risk_level_breakdown': {},
                'top_users': [],
                'top_devices': []
            }
        
        # Analyze threat history
        threat_breakdown = {}
        risk_level_breakdown = {}
        user_threats = {}
        device_threats = {}
        
        for threat in self.threat_history:
            # Threat type breakdown
            for detected_threat in threat.get('threats_detected', []):
                threat_name = detected_threat['name']
                threat_breakdown[threat_name] = threat_breakdown.get(threat_name, 0) + 1
            
            # Risk level breakdown
            risk_level = threat.get('risk_level', 'LOW')
            risk_level_breakdown[risk_level] = risk_level_breakdown.get(risk_level, 0) + 1
            
            # User threats
            user = threat.get('user', 'unknown')
            user_threats[user] = user_threats.get(user, 0) + 1
            
            # Device threats
            device = threat.get('device_id', 'unknown')
            device_threats[device] = device_threats.get(device, 0) + 1
        
        return {
            'total_threats': total_threats,
            'threat_breakdown': threat_breakdown,
            'risk_level_breakdown': risk_level_breakdown,
            'top_users': sorted(user_threats.items(), key=lambda x: x[1], reverse=True)[:10],
            'top_devices': sorted(device_threats.items(), key=lambda x: x[1], reverse=True)[:10]
        }
    
    def process_batch(self, data_file):
        """Process a batch of USB activity data"""
        try:
            # Load data
            if data_file.endswith('.csv'):
                data = pd.read_csv(data_file)
            else:
                with open(data_file, 'r') as f:
                    data = pd.DataFrame(json.load(f))
            
            logger.info(f"Processing {len(data)} records from {data_file}")
            
            # Analyze each record
            results = []
            for idx, record in data.iterrows():
                threat_assessment = self._analyze_single_record(record)
                results.append(threat_assessment)
                
                # Update baselines
                self.update_user_baseline(record.get('user', 'unknown'), record)
                
                # Store in threat history if threats detected
                if threat_assessment['threats_detected']:
                    self.threat_history.append(threat_assessment)
            
            # Generate summary
            total_threats = sum(1 for r in results if r['threats_detected'])
            threat_rate = (total_threats / len(results)) * 100
            
            logger.info(f"Batch processing completed: {total_threats} threats detected ({threat_rate:.1f}%)")
            
            return results
            
        except Exception as e:
            logger.error(f"Error processing batch: {e}")
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
        # Analyze sample data
        sample_data = '../lookups/usb_activity_sample.csv'
        if os.path.exists(sample_data):
            results = engine.process_batch(sample_data)
            print(f"Analyzed {len(results)} records")
            
            # Show top threats
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