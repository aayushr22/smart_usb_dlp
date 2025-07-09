"""
Smart USB DLP System - Data Models
Database models and data structures for threat detection system with MTP support
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
    """USB Device data model with MTP support"""
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
    protocol_type: str = "USB_MASS_STORAGE"
    device_category: str = "STORAGE"
    mtp_device_friendly_name: str = ""
    mtp_device_version: str = ""
    supports_mtp: bool = False
    android_version: str = ""
    ios_version: str = ""
    
    def __post_init__(self):
        if self.first_seen is None:
            self.first_seen = datetime.now().isoformat()
        if self.last_seen is None:
            self.last_seen = datetime.now().isoformat()
        
        # Auto-detect
        if self.protocol_type == "MTP":
            self.supports_mtp = True
            if any(brand in self.manufacturer.lower() for brand in ['samsung', 'google', 'xiaomi', 'oneplus', 'huawei', 'oppo', 'vivo']):
                self.device_category = "SMARTPHONE"
            elif 'apple' in self.manufacturer.lower():
                self.device_category = "SMARTPHONE"  # Though Apple uses different protocol
            elif any(brand in self.manufacturer.lower() for brand in ['canon', 'nikon', 'sony']):
                self.device_category = "CAMERA"

@dataclass
class USBActivity:
    """USB Activity data model with MTP support"""
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
    protocol_used: str = "USB_MASS_STORAGE"
    transfer_method: str = "COPY"
    mtp_object_ids: List[str] = None
    folder_hierarchy: str = ""
    media_sync_detected: bool = False
    photo_transfer_detected: bool = False
    video_transfer_detected: bool = False
    app_data_transfer: bool = False
    
    def __post_init__(self):
        if not self.activity_id:
            self.activity_id = str(uuid.uuid4())
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()
        if self.mtp_object_ids is None:
            self.mtp_object_ids = []
        
        # hour and day_of_week
        if self.timestamp:
            dt = pd.to_datetime(self.timestamp)
            self.hour = dt.hour
            self.day_of_week = dt.dayofweek
            
        # media transfers 
        if self.file_types:
            file_types_lower = self.file_types.lower()
            if any(ext in file_types_lower for ext in ['jpg', 'jpeg', 'png', 'gif', 'heic', 'raw']):
                self.photo_transfer_detected = True
            if any(ext in file_types_lower for ext in ['mp4', 'avi', 'mov', 'mkv', '3gp', 'webm']):
                self.video_transfer_detected = True
            if any(ext in file_types_lower for ext in ['mp3', 'flac', 'wav', 'aac', 'm4a']):
                self.media_sync_detected = True

@dataclass
class ThreatDetection:
    """Threat Detection result data model with MTP-specific threats"""
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
    mtp_threat_indicators: List[str] = None
    smartphone_data_exfiltration: bool = False
    mass_media_extraction: bool = False
    unauthorized_app_data_access: bool = False
    
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
        if self.mtp_threat_indicators is None:
            self.mtp_threat_indicators = []

@dataclass
class UserProfile:
    """User behavior profile data model with MTP patterns"""
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
    mtp_device_count: int = 0
    smartphone_connections: int = 0
    photo_transfer_sessions: int = 0
    video_transfer_sessions: int = 0
    large_media_transfers: int = 0
    off_hours_mtp_activity: int = 0
    
    def __post_init__(self):
        if self.behavioral_baseline is None:
            self.behavioral_baseline = {}

@dataclass
class MTPTransferSession:
    """MTP Transfer Session tracking"""
    session_id: str
    device_id: str
    user: str
    start_time: str
    end_time: str = None
    session_duration: int = 0
    objects_transferred: int = 0
    total_bytes: int = 0
    transfer_type: str = "UNKNOWN" 
    folder_accessed: List[str] = None
    is_suspicious: bool = False
    
    def __post_init__(self):
        if not self.session_id:
            self.session_id = str(uuid.uuid4())
        if not self.start_time:
            self.start_time = datetime.now().isoformat()
        if self.folder_accessed is None:
            self.folder_accessed = []

class USBDatabase:
    """Database manager for USB threat detection system with MTP support"""
    
    def __init__(self, db_path='tmp/usb_threats.db'):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database tables with MTP support"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
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
                    protocol_type TEXT DEFAULT 'USB_MASS_STORAGE',
                    device_category TEXT DEFAULT 'STORAGE',
                    mtp_device_friendly_name TEXT,
                    mtp_device_version TEXT,
                    supports_mtp BOOLEAN DEFAULT 0,
                    android_version TEXT,
                    ios_version TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
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
                    protocol_used TEXT DEFAULT 'USB_MASS_STORAGE',
                    transfer_method TEXT DEFAULT 'COPY',
                    mtp_object_ids TEXT,
                    folder_hierarchy TEXT,
                    media_sync_detected BOOLEAN DEFAULT 0,
                    photo_transfer_detected BOOLEAN DEFAULT 0,
                    video_transfer_detected BOOLEAN DEFAULT 0,
                    app_data_transfer BOOLEAN DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (device_id) REFERENCES usb_devices (device_id)
                )
            ''')
            
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
                    mtp_threat_indicators TEXT,
                    smartphone_data_exfiltration BOOLEAN DEFAULT 0,
                    mass_media_extraction BOOLEAN DEFAULT 0,
                    unauthorized_app_data_access BOOLEAN DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (activity_id) REFERENCES usb_activities (activity_id),
                    FOREIGN KEY (device_id) REFERENCES usb_devices (device_id)
                )
            ''')
            
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
                    mtp_device_count INTEGER DEFAULT 0,
                    smartphone_connections INTEGER DEFAULT 0,
                    photo_transfer_sessions INTEGER DEFAULT 0,
                    video_transfer_sessions INTEGER DEFAULT 0,
                    large_media_transfers INTEGER DEFAULT 0,
                    off_hours_mtp_activity INTEGER DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS mtp_transfer_sessions (
                    session_id TEXT PRIMARY KEY,
                    device_id TEXT,
                    user TEXT,
                    start_time TEXT,
                    end_time TEXT,
                    session_duration INTEGER,
                    objects_transferred INTEGER,
                    total_bytes INTEGER,
                    transfer_type TEXT,
                    folder_accessed TEXT,
                    is_suspicious BOOLEAN DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (device_id) REFERENCES usb_devices (device_id)
                )
            ''')
            
            # Create indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_activities_timestamp ON usb_activities(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_activities_user ON usb_activities(user)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_activities_protocol ON usb_activities(protocol_used)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threat_detections(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_threats_risk_level ON threat_detections(risk_level)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_devices_protocol ON usb_devices(protocol_type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_devices_category ON usb_devices(device_category)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_mtp_sessions_user ON mtp_transfer_sessions(user)')
            
            conn.commit()
    
    def insert_device(self, device: USBDevice):
        """Insert or update USB device with MTP support"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO usb_devices 
                (device_id, device_type, manufacturer, model, serial_number, 
                 capacity_gb, first_seen, last_seen, risk_level, is_approved,
                 protocol_type, device_category, mtp_device_friendly_name,
                 mtp_device_version, supports_mtp, android_version, ios_version)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                device.device_id, device.device_type, device.manufacturer,
                device.model, device.serial_number, device.capacity_gb,
                device.first_seen, device.last_seen, device.risk_level,
                device.is_approved, device.protocol_type, device.device_category,
                device.mtp_device_friendly_name, device.mtp_device_version,
                device.supports_mtp, device.android_version, device.ios_version
            ))
            conn.commit()
    
    def insert_activity(self, activity: USBActivity):
        """Insert USB activity with MTP support"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute('''
                    INSERT INTO usb_activities 
                    (activity_id, timestamp, user, device_id, bytes_written, bytes_read,
                     session_duration, files_transferred, file_types, source_path,
                     destination_path, hour, day_of_week, protocol_used, transfer_method,
                     mtp_object_ids, folder_hierarchy, media_sync_detected,
                     photo_transfer_detected, video_transfer_detected, app_data_transfer)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    activity.activity_id, activity.timestamp, activity.user,
                    activity.device_id, activity.bytes_written, activity.bytes_read,
                    activity.session_duration, activity.files_transferred,
                    activity.file_types, activity.source_path, activity.destination_path,
                    activity.hour, activity.day_of_week, activity.protocol_used,
                    activity.transfer_method, json.dumps(activity.mtp_object_ids),
                    activity.folder_hierarchy, activity.media_sync_detected,
                    activity.photo_transfer_detected, activity.video_transfer_detected,
                    activity.app_data_transfer
                ))
            except sqlite3.IntegrityError:
                cursor.execute('''
                    UPDATE usb_activities SET
                        timestamp=?, user=?, device_id=?, bytes_written=?, bytes_read=?,
                        session_duration=?, files_transferred=?, file_types=?, source_path=?,
                        destination_path=?, hour=?, day_of_week=?, protocol_used=?, transfer_method=?,
                        mtp_object_ids=?, folder_hierarchy=?, media_sync_detected=?,
                        photo_transfer_detected=?, video_transfer_detected=?, app_data_transfer=?
                    WHERE activity_id=?
                ''', (
                    activity.timestamp, activity.user, activity.device_id, activity.bytes_written, activity.bytes_read,
                    activity.session_duration, activity.files_transferred, activity.file_types, activity.source_path,
                    activity.destination_path, activity.hour, activity.day_of_week, activity.protocol_used,
                    activity.transfer_method, json.dumps(activity.mtp_object_ids), activity.folder_hierarchy,
                    activity.media_sync_detected, activity.photo_transfer_detected, activity.video_transfer_detected,
                    activity.app_data_transfer, activity.activity_id
                ))
            conn.commit()
    
    def insert_threat_detection(self, threat: ThreatDetection):
        """Insert or update threat detection with MTP support (upsert)"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute('''
                    INSERT INTO threat_detections 
                    (detection_id, timestamp, user, device_id, activity_id,
                     threats_detected, risk_score, risk_level, ml_anomaly_score,
                     recommended_actions, threat_details, is_resolved, resolution_notes,
                     mtp_threat_indicators, smartphone_data_exfiltration,
                     mass_media_extraction, unauthorized_app_data_access)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    threat.detection_id, threat.timestamp, threat.user,
                    threat.device_id, threat.activity_id,
                    json.dumps(threat.threats_detected),
                    threat.risk_score, threat.risk_level, threat.ml_anomaly_score,
                    json.dumps(threat.recommended_actions),
                    json.dumps(threat.threat_details),
                    threat.is_resolved, threat.resolution_notes,
                    json.dumps(threat.mtp_threat_indicators),
                    threat.smartphone_data_exfiltration,
                    threat.mass_media_extraction,
                    threat.unauthorized_app_data_access
                ))
            except sqlite3.IntegrityError:
                cursor.execute('''
                    UPDATE threat_detections SET
                        timestamp=?, user=?, device_id=?, activity_id=?,
                        threats_detected=?, risk_score=?, risk_level=?, ml_anomaly_score=?,
                        recommended_actions=?, threat_details=?, is_resolved=?, resolution_notes=?,
                        mtp_threat_indicators=?, smartphone_data_exfiltration=?,
                        mass_media_extraction=?, unauthorized_app_data_access=?
                    WHERE detection_id=?
                ''', (
                    threat.timestamp, threat.user, threat.device_id, threat.activity_id,
                    json.dumps(threat.threats_detected), threat.risk_score, threat.risk_level, threat.ml_anomaly_score,
                    json.dumps(threat.recommended_actions), json.dumps(threat.threat_details),
                    threat.is_resolved, threat.resolution_notes, json.dumps(threat.mtp_threat_indicators),
                    threat.smartphone_data_exfiltration, threat.mass_media_extraction, threat.unauthorized_app_data_access,
                    threat.detection_id
                ))
            conn.commit()
    
    def insert_mtp_session(self, session: MTPTransferSession):
        """Insert or update MTP transfer session (upsert)"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute('''
                    INSERT INTO mtp_transfer_sessions 
                    (session_id, device_id, user, start_time, end_time, session_duration,
                     objects_transferred, total_bytes, transfer_type, folder_accessed, is_suspicious)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    session.session_id, session.device_id, session.user,
                    session.start_time, session.end_time, session.session_duration,
                    session.objects_transferred, session.total_bytes,
                    session.transfer_type, json.dumps(session.folder_accessed),
                    session.is_suspicious
                ))
            except sqlite3.IntegrityError:
                cursor.execute('''
                    UPDATE mtp_transfer_sessions SET
                        device_id=?, user=?, start_time=?, end_time=?, session_duration=?,
                        objects_transferred=?, total_bytes=?, transfer_type=?, folder_accessed=?, is_suspicious=?
                    WHERE session_id=?
                ''', (
                    session.device_id, session.user, session.start_time, session.end_time, session.session_duration,
                    session.objects_transferred, session.total_bytes, session.transfer_type, json.dumps(session.folder_accessed),
                    session.is_suspicious, session.session_id
                ))
            conn.commit()
    
    def update_user_profile(self, profile: UserProfile):
        """Update user profile with MTP support"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO user_profiles 
                (user, total_activities, total_bytes_written, total_bytes_read,
                 unique_devices, threat_count, avg_session_duration, last_activity,
                 risk_score, behavioral_baseline, mtp_device_count, smartphone_connections,
                 photo_transfer_sessions, video_transfer_sessions, large_media_transfers,
                 off_hours_mtp_activity, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                profile.user, profile.total_activities, profile.total_bytes_written,
                profile.total_bytes_read, profile.unique_devices, profile.threat_count,
                profile.avg_session_duration, profile.last_activity,
                profile.risk_score, json.dumps(profile.behavioral_baseline),
                profile.mtp_device_count, profile.smartphone_connections,
                profile.photo_transfer_sessions, profile.video_transfer_sessions,
                profile.large_media_transfers, profile.off_hours_mtp_activity,
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
    
    def get_mtp_activities(self, days: int = 7) -> pd.DataFrame:
        """Get MTP activities within specified days"""
        with sqlite3.connect(self.db_path) as conn:
            since_date = (datetime.now() - timedelta(days=days)).isoformat()
            query = '''
                SELECT a.*, d.device_category, d.manufacturer, d.model
                FROM usb_activities a
                JOIN usb_devices d ON a.device_id = d.device_id
                WHERE a.timestamp >= ? AND a.protocol_used = 'MTP'
                ORDER BY a.timestamp DESC
            '''
            return pd.read_sql_query(query, conn, params=(since_date,))
    
    def get_smartphone_connections(self, days: int = 30) -> pd.DataFrame:
        """Get smartphone connections within specified days"""
        with sqlite3.connect(self.db_path) as conn:
            since_date = (datetime.now() - timedelta(days=days)).isoformat()
            query = '''
                SELECT DISTINCT d.device_id, d.manufacturer, d.model, d.device_category,
                       COUNT(a.activity_id) as connection_count,
                       MAX(a.timestamp) as last_connection
                FROM usb_devices d
                LEFT JOIN usb_activities a ON d.device_id = a.device_id
                WHERE d.device_category = 'SMARTPHONE' AND a.timestamp >= ?
                GROUP BY d.device_id
                ORDER BY connection_count DESC
            '''
            return pd.read_sql_query(query, conn, params=(since_date,))
    
    def get_threat_detections(self, days: int = 7, risk_level: str = None) -> pd.DataFrame:
        """Get threat detections with MTP support"""
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
        """Get user statistics with MTP support"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Total users
            cursor.execute('SELECT COUNT(DISTINCT user) FROM usb_activities')
            total_users = cursor.fetchone()[0]
            
            # Users with threats
            cursor.execute('SELECT COUNT(DISTINCT user) FROM threat_detections')
            users_with_threats = cursor.fetchone()[0]
            
            # Users with MTP activities
            cursor.execute("SELECT COUNT(DISTINCT user) FROM usb_activities WHERE protocol_used = 'MTP'")
            users_with_mtp = cursor.fetchone()[0]
            
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
                'users_with_mtp': users_with_mtp,
                'top_users': top_users
            }
    
    def get_device_statistics(self) -> Dict:
        """Get device statistics with MTP support"""
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
            
            # Devices by category
            cursor.execute('''
                SELECT device_category, COUNT(*) as count
                FROM usb_devices 
                GROUP BY device_category
            ''')
            devices_by_category = cursor.fetchall()
            
            # Devices by protocol
            cursor.execute('''
                SELECT protocol_type, COUNT(*) as count
                FROM usb_devices 
                GROUP BY protocol_type
            ''')
            devices_by_protocol = cursor.fetchall()
            
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
                'devices_by_category': dict(devices_by_category),
                'devices_by_protocol': dict(devices_by_protocol),
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
            
            # Delete old MTP sessions
            cursor.execute('DELETE FROM mtp_transfer_sessions WHERE start_time < ?', (cutoff_date,))
            sessions_deleted = cursor.rowcount
            
            conn.commit()
            
            return {
                'activities_deleted': activities_deleted,
                'threats_deleted': threats_deleted,
                'sessions_deleted': sessions_deleted
            }

def create_sample_data():
    """Create sample data for testing with MTP support - CONTINUATION"""
    db = USBDatabase()
    
    # devices
    devices = [
        USBDevice("DEV001", "USB_Flash", "SanDisk", "Ultra", "SN001", 32.0, risk_level="MEDIUM"),
        USBDevice("DEV002", "External_HDD", "Seagate", "Backup Plus", "SN002", 1000.0, risk_level="HIGH"),
        USBDevice("DEV003", "Unknown", "Unknown", "Unknown", "Unknown", 0.0, risk_level="CRITICAL"),
        USBDevice("DEV004", "Android_Phone", "Samsung", "Galaxy S21", "SM-G991B", 128.0, 
                 risk_level="MEDIUM", protocol_type="MTP", device_category="SMARTPHONE", 
                 supports_mtp=True, mtp_device_friendly_name="Samsung Galaxy S21", 
                 android_version="Android 11"),
        USBDevice("DEV005", "iPhone", "Apple", "iPhone 13", "A2482", 256.0, 
                 risk_level="LOW", protocol_type="MTP", device_category="SMARTPHONE", 
                 supports_mtp=True, mtp_device_friendly_name="iPhone 13", 
                 ios_version="iOS 15.2")
    ]
    
    for device in devices:
        db.insert_device(device)
    
    # activities
    activities = [
        USBActivity("ACT001", "2025-01-01T10:30:00", "john.doe", "DEV001", 1048576, 0, 300, 5, "documents"),
        USBActivity("ACT002", "2025-01-01T14:45:00", "jane.smith", "DEV002", 5368709120, 0, 600, 10, "backup"),
        USBActivity("ACT003", "2025-01-01T23:15:00", "bob.wilson", "DEV003", 10737418240, 0, 120, 1, "software"),
        USBActivity("ACT004", "2025-01-02T09:20:00", "alice.brown", "DEV004", 52428800, 0, 180, 25, "jpg,mp4", 
                   protocol_used="MTP", transfer_method="COPY", 
                   folder_hierarchy="DCIM/Camera", photo_transfer_detected=True, video_transfer_detected=True),
        USBActivity("ACT005", "2025-01-02T16:30:00", "charlie.davis", "DEV005", 104857600, 0, 240, 50, "heic,mov", 
                   protocol_used="MTP", transfer_method="COPY", 
                   folder_hierarchy="Photos", photo_transfer_detected=True, video_transfer_detected=True)
    ]
    
    for activity in activities:
        db.insert_activity(activity)
    
    mtp_sessions = [
        MTPTransferSession("MTP001", "DEV004", "alice.brown", "2025-01-02T09:20:00", 
                          "2025-01-02T09:23:00", 180, 25, 52428800, "PHOTO_IMPORT", 
                          ["DCIM/Camera"]),
        MTPTransferSession("MTP002", "DEV005", "charlie.davis", "2025-01-02T16:30:00", 
                          "2025-01-02T16:34:00", 240, 50, 104857600, "PHOTO_IMPORT", 
                          ["Photos"]),
        MTPTransferSession("MTP003", "DEV004", "bob.wilson", "2025-01-02T22:45:00", 
                          "2025-01-02T22:50:00", 300, 100, 209715200, "BACKUP", 
                          ["Android/data", "WhatsApp"], is_suspicious=True)
    ]
    
    for session in mtp_sessions:
        db.insert_mtp_session(session)
    
    # threat detections
    threats = [
        ThreatDetection("THR001", "2025-01-01T23:15:00", "bob.wilson", "DEV003", "ACT003",
                       [{"type": "unknown_device", "severity": "HIGH"}], 8.5, "HIGH",
                       7.2, ["Block device", "Investigate user"], 
                       {"reason": "Unknown device with large data transfer"}),
        ThreatDetection("THR002", "2025-01-02T09:20:00", "alice.brown", "DEV004", "ACT004",
                       [{"type": "large_media_transfer", "severity": "MEDIUM"}], 6.0, "MEDIUM",
                       5.8, ["Monitor activity", "Review transfer"], 
                       {"reason": "Large media transfer from smartphone"},
                       mtp_threat_indicators=["mass_media_extraction"],
                       mass_media_extraction=True),
        ThreatDetection("THR003", "2025-01-02T22:45:00", "bob.wilson", "DEV004", "ACT004",
                       [{"type": "off_hours_mtp_access", "severity": "HIGH"}], 7.8, "HIGH",
                       8.1, ["Immediate investigation", "User notification"], 
                       {"reason": "MTP access during off-hours with app data"},
                       mtp_threat_indicators=["off_hours_access", "app_data_access"],
                       smartphone_data_exfiltration=True,
                       unauthorized_app_data_access=True)
    ]
    
    for threat in threats:
        db.insert_threat_detection(threat)
    
    # user profiles
    profiles = [
        UserProfile("john.doe", 15, 15728640, 0, 2, 0, 250.0, "2025-01-01T10:30:00", 3.2),
        UserProfile("jane.smith", 8, 42949672960, 0, 1, 0, 450.0, "2025-01-01T14:45:00", 2.8),
        UserProfile("bob.wilson", 3, 10737418240, 0, 2, 2, 200.0, "2025-01-02T22:45:00", 8.5,
                   mtp_device_count=1, smartphone_connections=2, off_hours_mtp_activity=1),
        UserProfile("alice.brown", 12, 629145600, 0, 3, 1, 180.0, "2025-01-02T09:20:00", 4.2,
                   mtp_device_count=2, smartphone_connections=5, photo_transfer_sessions=8,
                   video_transfer_sessions=4, large_media_transfers=2),
        UserProfile("charlie.davis", 6, 314572800, 0, 1, 0, 220.0, "2025-01-02T16:30:00", 2.5,
                   mtp_device_count=1, smartphone_connections=3, photo_transfer_sessions=4,
                   video_transfer_sessions=2)
    ]
    
    for profile in profiles:
        db.update_user_profile(profile)
    
    print("Sample data created successfully!")
    return db

class USBAnalytics:
    """Analytics engine for USB threat detection with MTP support"""
    
    def __init__(self, db: USBDatabase):
        self.db = db
    
    def calculate_user_risk_score(self, user: str) -> float:
        """Calculate comprehensive risk score for a user"""
        activities_df = self.db.get_activities_by_user(user, days=30)
        
        if activities_df.empty:
            return 0.0
        
        risk_factors = {
            'off_hours_activity': 0,
            'large_transfers': 0,
            'unknown_devices': 0,
            'mtp_activity': 0,
            'suspicious_file_types': 0,
            'rapid_transfers': 0
        }
        
        # Analyze activities
        for _, activity in activities_df.iterrows():
            # Off-hours activity (before 8 AM or after 6 PM)
            if activity['hour'] < 8 or activity['hour'] > 18:
                risk_factors['off_hours_activity'] += 1
            
            # Large transfers (>100MB)
            if activity['bytes_written'] > 104857600:
                risk_factors['large_transfers'] += 1
            
            # MTP activity
            if activity['protocol_used'] == 'MTP':
                risk_factors['mtp_activity'] += 1
            
            # Suspicious file types
            if activity['file_types'] and any(ext in activity['file_types'].lower() 
                                            for ext in ['exe', 'bat', 'cmd', 'scr', 'vbs']):
                risk_factors['suspicious_file_types'] += 1
            
            # Rapid transfers
            if activity['session_duration'] < 60 and activity['bytes_written'] > 52428800:
                risk_factors['rapid_transfers'] += 1
        
        # weighted risk score
        total_activities = len(activities_df)
        risk_score = (
            (risk_factors['off_hours_activity'] / total_activities) * 2.0 +
            (risk_factors['large_transfers'] / total_activities) * 1.5 +
            (risk_factors['unknown_devices'] / total_activities) * 3.0 +
            (risk_factors['mtp_activity'] / total_activities) * 1.2 +
            (risk_factors['suspicious_file_types'] / total_activities) * 2.5 +
            (risk_factors['rapid_transfers'] / total_activities) * 1.8
        ) * 10
        
        return min(risk_score, 10.0)
    
    def detect_mtp_anomalies(self, user: str = None, days: int = 7) -> List[Dict]:
        """Detect MTP-specific anomalies"""
        mtp_activities = self.db.get_mtp_activities(days)
        
        if user:
            mtp_activities = mtp_activities[mtp_activities['user'] == user]
        
        anomalies = []
        
        for _, activity in mtp_activities.iterrows():
            anomaly_score = 0
            anomaly_reasons = []
            
            # Large media transfers
            if activity['bytes_written'] > 524288000:  # >500MB
                anomaly_score += 3
                anomaly_reasons.append("Large media transfer detected")
            
            # Off-hours MTP access
            if activity['hour'] < 7 or activity['hour'] > 19:
                anomaly_score += 2
                anomaly_reasons.append("Off-hours MTP access")
            
            # App data transfer
            if activity['app_data_transfer']:
                anomaly_score += 4
                anomaly_reasons.append("App data transfer detected")
            
            # Rapid mass transfer
            if activity['session_duration'] < 120 and activity['files_transferred'] > 100:
                anomaly_score += 3
                anomaly_reasons.append("Rapid mass file transfer")
            
            # Weekend activity
            if activity['day_of_week'] in [5, 6]:  # Saturday, Sunday
                anomaly_score += 1
                anomaly_reasons.append("Weekend activity")
            
            if anomaly_score >= 3:
                anomalies.append({
                    'activity_id': activity['activity_id'],
                    'user': activity['user'],
                    'device_id': activity['device_id'],
                    'timestamp': activity['timestamp'],
                    'anomaly_score': anomaly_score,
                    'reasons': anomaly_reasons,
                    'device_info': f"{activity['manufacturer']} {activity['model']}"
                })
        
        return sorted(anomalies, key=lambda x: x['anomaly_score'], reverse=True)
    
    def generate_behavioral_baseline(self, user: str, days: int = 30) -> Dict:
        """Generate behavioral baseline for a user"""
        activities_df = self.db.get_activities_by_user(user, days)
        
        if activities_df.empty:
            return {}
        
        baseline = {
            'avg_session_duration': activities_df['session_duration'].mean(),
            'avg_bytes_written': activities_df['bytes_written'].mean(),
            'avg_files_transferred': activities_df['files_transferred'].mean(),
            'common_hours': activities_df['hour'].mode().tolist(),
            'common_days': activities_df['day_of_week'].mode().tolist(),
            'device_count': activities_df['device_id'].nunique(),
            'total_activities': len(activities_df),
            'protocols_used': activities_df['protocol_used'].value_counts().to_dict(),
            'file_types': activities_df['file_types'].value_counts().to_dict(),
            'mtp_usage': {
                'mtp_activities': len(activities_df[activities_df['protocol_used'] == 'MTP']),
                'photo_transfers': activities_df['photo_transfer_detected'].sum(),
                'video_transfers': activities_df['video_transfer_detected'].sum(),
                'media_syncs': activities_df['media_sync_detected'].sum()
            }
        }
        
        return baseline
    
    def compare_to_baseline(self, user: str, recent_activity: USBActivity, baseline: Dict) -> float:
        """Compare recent activity to user's baseline"""
        if not baseline:
            return 5.0 
        
        anomaly_score = 0
        
        # Session duration anomaly
        if baseline.get('avg_session_duration', 0) > 0:
            duration_ratio = recent_activity.session_duration / baseline['avg_session_duration']
            if duration_ratio > 3 or duration_ratio < 0.3:
                anomaly_score += 2
        
        # Bytes written anomaly
        if baseline.get('avg_bytes_written', 0) > 0:
            bytes_ratio = recent_activity.bytes_written / baseline['avg_bytes_written']
            if bytes_ratio > 5 or bytes_ratio < 0.1:
                anomaly_score += 2
        
        # Time-based anomaly
        if recent_activity.hour not in baseline.get('common_hours', []):
            anomaly_score += 1
        
        if recent_activity.day_of_week not in baseline.get('common_days', []):
            anomaly_score += 1
        
        # Protocol anomaly
        protocols = baseline.get('protocols_used', {})
        if recent_activity.protocol_used not in protocols:
            anomaly_score += 1
        
        return min(anomaly_score, 10.0)
    
    def get_threat_trends(self, days: int = 30) -> Dict:
        """Get threat detection trends"""
        threats_df = self.db.get_threat_detections(days)
        
        if threats_df.empty:
            return {'total_threats': 0, 'trends': {}}
        
        threats_df['timestamp'] = pd.to_datetime(threats_df['timestamp'])
        threats_df['date'] = threats_df['timestamp'].dt.date
        
        daily_counts = threats_df.groupby('date').size()
        risk_level_counts = threats_df['risk_level'].value_counts()
        
        mtp_threats = {
            'smartphone_data_exfiltration': threats_df['smartphone_data_exfiltration'].sum(),
            'mass_media_extraction': threats_df['mass_media_extraction'].sum(),
            'unauthorized_app_data_access': threats_df['unauthorized_app_data_access'].sum()
        }
        
        return {
            'total_threats': len(threats_df),
            'daily_average': daily_counts.mean(),
            'risk_level_distribution': risk_level_counts.to_dict(),
            'mtp_specific_threats': mtp_threats,
            'trend_direction': 'increasing' if daily_counts.tail(7).mean() > daily_counts.head(7).mean() else 'decreasing'
        }

class USBReporter:
    """Report generator for USB threat detection system"""
    
    def __init__(self, db: USBDatabase):
        self.db = db
        self.analytics = USBAnalytics(db)
    
    def generate_security_report(self, days: int = 7) -> Dict:
        """Generate comprehensive security report"""
        report = {
            'report_generated': datetime.now().isoformat(),
            'analysis_period': f"{days} days",
            'summary': {},
            'threats': {},
            'devices': {},
            'users': {},
            'mtp_analysis': {},
            'recommendations': []
        }
        
        # Summary
        user_stats = self.db.get_user_statistics()
        device_stats = self.db.get_device_statistics()
        threat_trends = self.analytics.get_threat_trends(days)
        
        report['summary'] = {
            'total_users': user_stats['total_users'],
            'total_devices': device_stats['total_devices'],
            'total_threats': threat_trends['total_threats'],
            'users_with_threats': user_stats['users_with_threats'],
            'threat_trend': threat_trends.get('trend_direction', 'stable')
        }
        
        # Threat analysis
        report['threats'] = {
            'risk_distribution': threat_trends.get('risk_level_distribution', {}),
            'mtp_threats': threat_trends.get('mtp_specific_threats', {}),
            'daily_average': threat_trends.get('daily_average', 0)
        }
        
        # Device analysis
        report['devices'] = {
            'by_category': device_stats.get('devices_by_category', {}),
            'by_protocol': device_stats.get('devices_by_protocol', {}),
            'by_risk_level': device_stats.get('devices_by_risk', {})
        }
        
        # MTP specific analysis
        mtp_activities = self.db.get_mtp_activities(days)
        smartphone_connections = self.db.get_smartphone_connections(days)
        
        report['mtp_analysis'] = {
            'total_mtp_activities': len(mtp_activities),
            'smartphone_connections': len(smartphone_connections),
            'photo_transfers': mtp_activities['photo_transfer_detected'].sum() if not mtp_activities.empty else 0,
            'video_transfers': mtp_activities['video_transfer_detected'].sum() if not mtp_activities.empty else 0,
            'media_syncs': mtp_activities['media_sync_detected'].sum() if not mtp_activities.empty else 0
        }
        
        # recommendations
        report['recommendations'] = self._generate_recommendations(report)
        
        return report
    
    def _generate_recommendations(self, report: Dict) -> List[str]:
        """Generate security recommendations based on report data"""
        recommendations = []

        # High-risk device
        if report['devices']['by_risk_level'].get('HIGH', 0) > 0:
            recommendations.append("Review and potentially block high-risk devices")

        if report['devices']['by_risk_level'].get('CRITICAL', 0) > 0:
            recommendations.append("Immediately investigate critical-risk devices")

        # MTP-specific
        if report['mtp_analysis']['smartphone_connections'] > 10:
            recommendations.append("Consider implementing stricter MTP policies for smartphone connections")

        # Defensive
        smartphone_exfil = report['threats']['mtp_threats'].get('smartphone_data_exfiltration', 0)
        if smartphone_exfil > 0:
            recommendations.append("Investigate potential smartphone data exfiltration incidents")

        # Threat trend
        if report['summary']['threat_trend'] == 'increasing':
            recommendations.append("Threat activity is increasing - consider enhanced monitoring")

        # User behavior
        if report['summary']['users_with_threats'] / max(report['summary']['total_users'], 1) > 0.1:
            recommendations.append("High percentage of users with threats - consider security training")

        return recommendations
    
    def export_report_to_json(self, report: Dict, filename: str):
        """Export report to JSON file"""
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)

def hash_device_id(device_info: str) -> str:
    """Generate consistent device ID from device information"""
    return hashlib.sha256(device_info.encode()).hexdigest()[:16]

def classify_file_risk(file_extension: str) -> str:
    """Classify file type risk level"""
    high_risk_extensions = ['exe', 'bat', 'cmd', 'scr', 'vbs', 'ps1', 'jar']
    medium_risk_extensions = ['zip', 'rar', '7z', 'tar', 'gz']
    low_risk_extensions = ['txt', 'doc', 'docx', 'pdf', 'jpg', 'png', 'mp4', 'mp3']
    
    ext = file_extension.lower().strip('.')
    
    if ext in high_risk_extensions:
        return 'HIGH'
    elif ext in medium_risk_extensions:
        return 'MEDIUM'
    elif ext in low_risk_extensions:
        return 'LOW'
    else:
        return 'UNKNOWN'

def detect_mtp_device_type(device_info: Dict) -> str:
    """Detect MTP device type from device information"""
    manufacturer = device_info.get('manufacturer', '').lower()
    model = device_info.get('model', '').lower()
    
    # Smartphone detection
    smartphone_indicators = ['phone', 'galaxy', 'pixel', 'iphone', 'oneplus', 'xiaomi']
    if any(indicator in manufacturer + model for indicator in smartphone_indicators):
        return 'SMARTPHONE'
    
    # Tablet detection
    tablet_indicators = ['tablet', 'ipad', 'tab', 'kindle']
    if any(indicator in manufacturer + model for indicator in tablet_indicators):
        return 'TABLET'
    
    # Camera detection
    camera_indicators = ['camera', 'canon', 'nikon', 'sony', 'fujifilm']
    if any(indicator in manufacturer + model for indicator in camera_indicators):
        return 'CAMERA'
    
    # Audio device detection
    audio_indicators = ['ipod', 'walkman', 'mp3', 'audio']
    if any(indicator in manufacturer + model for indicator in audio_indicators):
        return 'AUDIO'
    
    return 'STORAGE'

if __name__ == "__main__":
    print("Initializing USB DLP System...")
    db = create_sample_data()

    print("\nGenerating analytics...")
    analytics = USBAnalytics(db)
    
    mtp_anomalies = analytics.detect_mtp_anomalies()
    print(f"Found {len(mtp_anomalies)} MTP anomalies")
    
    print("\nGenerating security report...")
    reporter = USBReporter(db)
    report = reporter.generate_security_report(days=7)
    
    reporter.export_report_to_json(report, 'security_report.json')
    print("Security report exported to security_report.json")
    
    # Display summary
    print(f"\nSUMMARY:")
    print(f"Total Users: {report['summary']['total_users']}")
    print(f"Total Devices: {report['summary']['total_devices']}")
    print(f"Total Threats: {report['summary']['total_threats']}")
    print(f"MTP Activities: {report['mtp_analysis']['total_mtp_activities']}")
    print(f"Smartphone Connections: {report['mtp_analysis']['smartphone_connections']}")
    
    print(f"\nRECOMMENDATIONS:")
    for rec in report['recommendations']:
        print(f"- {rec}")
    
    print("\nUSB DLP System initialization complete!")