#!/usr/bin/env python3
"""
Smart USB DLP System - Data Models
Database models and data structures for threat detection system
"""

import sqlite3
import json
import pandas as pd
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Any
import uuid
import hashlib

@dataclass
class USBDevice:
    """USB Device data model"""
    device_id: str
    device_type: str = "Unknown"
    manufacturer: str = "Unknown"
    model: str = "Unknown"
    serial_number: str = "Unknown"
    capacity_gb: float = 0.0
    first_seen: str = None
    last_seen: str = None
    risk_level: str = "MEDIUM"
    is_approved: bool = False
    
    def __post_init__(self):
        if self.first_seen is None:
            self.first_seen = datetime.now().isoformat()
        if self.last_seen is None:
            self.last_seen = datetime.now().isoformat()

@dataclass
class USBActivity:
    """USB Activity data model"""
    activity_id: str
    timestamp: str
    user: str
    device_id: str
    bytes_written: int = 0
    bytes_read: int = 0
    session_duration: int = 0
    files_transferred: int = 0
    file_types: str = "unknown"
    source_path: str = ""
    destination_path: str = ""
    hour: int = 12
    day_of_week: int = 1
    
    def __post_init__(self):
        if not self.activity_id:
            self.activity_id = str(uuid.uuid4())
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()
        
        # Extract hour and day_of_week from timestamp
        if self.timestamp:
            dt = pd.to_datetime(self.timestamp)
            self.hour = dt.hour
            self.day_of_week = dt.dayofweek

@dataclass
class ThreatDetection:
    """Threat Detection result data model"""
    detection_id: str
    timestamp: str
    user: str
    device_id: str
    activity_id: str
    threats_detected: List[Dict] = None
    risk_score: float = 0.0
    risk_level: str = "LOW"
    ml_anomaly_score: float = None
    recommended_actions: List[str] = None
    threat_details: Dict = None
    is_resolved: bool = False
    resolution_notes: str = ""
    
    def __post_init__(self):
        if not self.detection_id:
            self.detection_id = str(uuid.uuid4())
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()
        if self.threats_detected is None:
            self.threats_detected = []
        if self.recommended_actions is None:
            self.recommended_actions = []
        if self.threat_details is None:
            self.threat_details = {}

@dataclass
class UserProfile:
    """User behavior profile data model"""
    user: str
    total_activities: int = 0
    total_bytes_written: int = 0
    total_bytes_read: int = 0
    unique_devices: int = 0
    threat_count: int = 0
    avg_session_duration: float = 0.0
    last_activity: str = None
    risk_score: float = 0.0
    behavioral_baseline: Dict = None
    
    def __post_init__(self):
        if self.behavioral_baseline is None:
            self.behavioral_baseline = {}

class USBDatabase:
    """Database manager for USB threat detection system"""
    
    def __init__(self, db_path='tmp/usb_threats.db'):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # USB Devices table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS usb_devices (
                    device_id TEXT PRIMARY KEY,
                    device_type TEXT,
                    manufacturer TEXT,
                    model TEXT,
                    serial_number TEXT,
                    capacity_gb REAL,
                    first_seen TEXT,
                    last_seen TEXT,
                    risk_level TEXT,
                    is_approved BOOLEAN,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # USB Activities table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS usb_activities (
                    activity_id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    user TEXT,
                    device_id TEXT,
                    bytes_written INTEGER,
                    bytes_read INTEGER,
                    session_duration INTEGER,
                    files_transferred INTEGER,
                    file_types TEXT,
                    source_path TEXT,
                    destination_path TEXT,
                    hour INTEGER,
                    day_of_week INTEGER,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (device_id) REFERENCES usb_devices (device_id)
                )
            ''')
            
            # Threat Detections table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_detections (
                    detection_id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    user TEXT,
                    device_id TEXT,
                    activity_id TEXT,
                    threats_detected TEXT,
                    risk_score REAL,
                    risk_level TEXT,
                    ml_anomaly_score REAL,
                    recommended_actions TEXT,
                    threat_details TEXT,
                    is_resolved BOOLEAN,
                    resolution_notes TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (activity_id) REFERENCES usb_activities (activity_id),
                    FOREIGN KEY (device_id) REFERENCES usb_devices (device_id)
                )
            ''')
            
            # User Profiles table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_profiles (
                    user TEXT PRIMARY KEY,
                    total_activities INTEGER,
                    total_bytes_written INTEGER,
                    total_bytes_read INTEGER,
                    unique_devices INTEGER,
                    threat_count INTEGER,
                    avg_session_duration REAL,
                    last_activity TEXT,
                    risk_score REAL,
                    behavioral_baseline TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create indexes for better performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_activities_timestamp ON usb_activities(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_activities_user ON usb_activities(user)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threat_detections(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_threats_risk_level ON threat_detections(risk_level)')
            
            conn.commit()
    
    def insert_device(self, device: USBDevice):
        """Insert or update USB device"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO usb_devices 
                (device_id, device_type, manufacturer, model, serial_number, 
                 capacity_gb, first_seen, last_seen, risk_level, is_approved)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                device.device_id, device.device_type, device.manufacturer,
                device.model, device.serial_number, device.capacity_gb,
                device.first_seen, device.last_seen, device.risk_level,
                device.is_approved
            ))
            conn.commit()
    
    def insert_activity(self, activity: USBActivity):
        """Insert USB activity"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO usb_activities 
                (activity_id, timestamp, user, device_id, bytes_written, bytes_read,
                 session_duration, files_transferred, file_types, source_path,
                 destination_path, hour, day_of_week)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                activity.activity_id, activity.timestamp, activity.user,
                activity.device_id, activity.bytes_written, activity.bytes_read,
                activity.session_duration, activity.files_transferred,
                activity.file_types, activity.source_path, activity.destination_path,
                activity.hour, activity.day_of_week
            ))
            conn.commit()
    
    def insert_threat_detection(self, threat: ThreatDetection):
        """Insert threat detection"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO threat_detections 
                (detection_id, timestamp, user, device_id, activity_id,
                 threats_detected, risk_score, risk_level, ml_anomaly_score,
                 recommended_actions, threat_details, is_resolved, resolution_notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                threat.detection_id, threat.timestamp, threat.user,
                threat.device_id, threat.activity_id,
                json.dumps(threat.threats_detected),
                threat.risk_score, threat.risk_level, threat.ml_anomaly_score,
                json.dumps(threat.recommended_actions),
                json.dumps(threat.threat_details),
                threat.is_resolved, threat.resolution_notes
            ))
            conn.commit()
    
    def update_user_profile(self, profile: UserProfile):
        """Update user profile"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO user_profiles 
                (user, total_activities, total_bytes_written, total_bytes_read,
                 unique_devices, threat_count, avg_session_duration, last_activity,
                 risk_score, behavioral_baseline, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                profile.user, profile.total_activities, profile.total_bytes_written,
                profile.total_bytes_read, profile.unique_devices, profile.threat_count,
                profile.avg_session_duration, profile.last_activity,
                profile.risk_score, json.dumps(profile.behavioral_baseline),
                datetime.now().isoformat()
            ))
            conn.commit()
    
    def get_activities_by_user(self, user: str, days: int = 30) -> pd.DataFrame:
        """Get activities for a user within specified days"""
        with sqlite3.connect(self.db_path) as conn:
            since_date = (datetime.now() - timedelta(days=days)).isoformat()
            query = '''
                SELECT * FROM usb_activities 
                WHERE user = ? AND timestamp >= ?
                ORDER BY timestamp DESC
            '''
            return pd.read_sql_query(query, conn, params=(user, since_date))
    
    def get_threat_detections(self, days: int = 7, risk_level: str = None) -> pd.DataFrame:
        """Get threat detections"""
        with sqlite3.connect(self.db_path) as conn:
            since_date = (datetime.now() - timedelta(days=days)).isoformat()
            
            if risk_level:
                query = '''
                    SELECT * FROM threat_detections 
                    WHERE timestamp >= ? AND risk_level = ?
                    ORDER BY timestamp DESC
                '''
                params = (since_date, risk_level)
            else:
                query = '''
                    SELECT * FROM threat_detections 
                    WHERE timestamp >= ?
                    ORDER BY timestamp DESC
                '''
                params = (since_date,)
            
            return pd.read_sql_query(query, conn, params=params)
    
    def get_user_statistics(self) -> Dict:
        """Get user statistics"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Total users
            cursor.execute('SELECT COUNT(DISTINCT user) FROM usb_activities')
            total_users = cursor.fetchone()[0]
            
            # Users with threats
            cursor.execute('SELECT COUNT(DISTINCT user) FROM threat_detections')
            users_with_threats = cursor.fetchone()[0]
            
            # Top users by activity
            cursor.execute('''
                SELECT user, COUNT(*) as activity_count, SUM(bytes_written) as total_bytes
                FROM usb_activities 
                GROUP BY user 
                ORDER BY activity_count DESC 
                LIMIT 10
            ''')
            top_users = cursor.fetchall()
            
            return {
                'total_users': total_users,
                'users_with_threats': users_with_threats,
                'top_users': top_users
            }
    
    def get_device_statistics(self) -> Dict:
        """Get device statistics"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Total devices
            cursor.execute('SELECT COUNT(*) FROM usb_devices')
            total_devices = cursor.fetchone()[0]
            
            # Devices by type
            cursor.execute('''
                SELECT device_type, COUNT(*) as count
                FROM usb_devices 
                GROUP BY device_type
            ''')
            devices_by_type = cursor.fetchall()
            
            # Devices by risk level
            cursor.execute('''
                SELECT risk_level, COUNT(*) as count
                FROM usb_devices 
                GROUP BY risk_level
            ''')
            devices_by_risk = cursor.fetchall()
            
            return {
                'total_devices': total_devices,
                'devices_by_type': dict(devices_by_type),
                'devices_by_risk': dict(devices_by_risk)
            }
    
    def export_data(self, table_name: str, output_file: str):
        """Export table data to CSV"""
        with sqlite3.connect(self.db_path) as conn:
            df = pd.read_sql_query(f'SELECT * FROM {table_name}', conn)
            df.to_csv(output_file, index=False)
            return len(df)
    
    def cleanup_old_data(self, days: int = 90):
        """Clean up old data"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
            
            # Delete old activities
            cursor.execute('DELETE FROM usb_activities WHERE timestamp < ?', (cutoff_date,))
            activities_deleted = cursor.rowcount
            
            # Delete old threat detections
            cursor.execute('DELETE FROM threat_detections WHERE timestamp < ?', (cutoff_date,))
            threats_deleted = cursor.rowcount
            
            conn.commit()
            
            return {
                'activities_deleted': activities_deleted,
                'threats_deleted': threats_deleted
            }

def create_sample_data():
    """Create sample data for testing"""
    db = USBDatabase()
    
    # Sample devices
    devices = [
        USBDevice("DEV001", "USB_Flash", "SanDisk", "Ultra", "SN001", 32.0, risk_level="MEDIUM"),
        USBDevice("DEV002", "External_HDD", "Seagate", "Backup Plus", "SN002", 1000.0, risk_level="HIGH"),
        USBDevice("DEV003", "Unknown", "Unknown", "Unknown", "Unknown", 0.0, risk_level="CRITICAL")
    ]
    
    for device in devices:
        db.insert_device(device)
    
    # Sample activities
    activities = [
        USBActivity("ACT001", "2025-01-01T10:30:00", "john.doe", "DEV001", 1048576, 0, 300, 5, "documents"),
        USBActivity("ACT002", "2025-01-01T14:45:00", "jane.smith", "DEV002", 5368709120, 0, 600, 10, "backup"),
        USBActivity("ACT003", "2025-01-01T23:15:00", "bob.wilson", "DEV003", 10737418240, 0, 120, 1, "software")
    ]
    
    for activity in activities:
        db.insert_activity(activity)
    
    # Sample threat detections
    threats = [
        ThreatDetection(
            "THR001", "2025-01-01T23:15:00", "bob.wilson", "DEV003", "ACT003",
            [{"rule_id": "large_transfer", "severity": "HIGH"}],
            8.5, "CRITICAL", -0.8,
            ["block", "alert", "log"],
            {"analysis_time": "2025-01-01T23:15:30", "threat_count": 2}
        )
    ]
    
    for threat in threats:
        db.insert_threat_detection(threat)
    
    print("Sample data created successfully!")

if __name__ == "__main__":
    # Create sample data
    create_sample_data()
    
    # Test database operations
    db = USBDatabase()
    print("\nDatabase Statistics:")
    print(f"User stats: {db.get_user_statistics()}")
    print(f"Device stats: {db.get_device_statistics()}")