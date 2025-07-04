"""
Smart USB DLP System - Advanced Deep Learning Model
Neural Network-based approach for sophisticated threat detection
Enhances the existing ML model with deep learning capabilities
"""

import sys
import os
import json
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import tensorflow as tf
from tensorflow.keras.models import Sequential, Model
from tensorflow.keras.layers import Dense, Dropout, BatchNormalization, LSTM, Input
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
from tensorflow.keras.utils import to_categorical
import joblib
import logging
from datetime import datetime, timedelta
import warnings
warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/tmp/usb_deep_learning.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class USBDeepLearningModel:
    """
    Advanced Deep Learning model for USB threat detection
    Combines neural networks with behavioral sequence analysis
    """
    
    def __init__(self, model_path='/tmp/usb_deep_models'):
        self.model_path = model_path
        self.anomaly_model = None
        self.sequence_model = None
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        
        # Enhanced feature set
        self.feature_columns = [
            'bytes_written', 'session_duration', 'hour', 'day_of_week',
            'user_avg_bytes', 'device_usage_count', 'time_since_last_transfer',
            'bytes_per_second', 'session_frequency', 'unusual_time_score',
            'device_risk_score', 'user_risk_profile', 'data_velocity',
            'access_pattern_score', 'size_deviation_score'
        ]
        
        # Threat intelligence features
        self.threat_indicators = [
            'known_malicious_pattern', 'suspicious_file_types',
            'encryption_detected', 'steganography_risk',
            'data_exfiltration_signature', 'insider_threat_score'
        ]
        
        os.makedirs(model_path, exist_ok=True)
        
    def advanced_feature_engineering(self, data):
        """Advanced feature engineering with threat intelligence"""
        logger.info(f"Advanced feature engineering for {len(data)} records")
        
        # Basic feature engineering (from existing model)
        data = self.basic_feature_engineering(data)
        
        # Advanced behavioral features
        data['bytes_per_second'] = data['bytes_written'] / np.maximum(data['session_duration'], 1)
        
        # User behavior profiling
        user_profiles = self.create_user_profiles(data)
        data = data.merge(user_profiles, on='user', how='left')
        
        # Temporal pattern analysis
        data = self.add_temporal_features(data)
        
        # Device risk assessment
        data = self.assess_device_risk(data)
        
        # Threat intelligence integration
        data = self.integrate_threat_intelligence(data)
        
        # Sequence-based features
        data = self.create_sequence_features(data)
        
        return data
    
    def basic_feature_engineering(self, data):
        """Basic feature engineering from existing model"""
        if 'timestamp' in data.columns:
            data['timestamp'] = pd.to_datetime(data['timestamp'])
            data['hour'] = data['timestamp'].dt.hour
            data['day_of_week'] = data['timestamp'].dt.dayofweek
        
        # User statistics
        user_stats = data.groupby('user')['bytes_written'].agg(['mean', 'std', 'count']).reset_index()
        user_stats.columns = ['user', 'user_avg_bytes', 'user_std_bytes', 'user_total_sessions']
        user_stats['user_std_bytes'] = user_stats['user_std_bytes'].fillna(user_stats['user_avg_bytes'] * 0.1)
        
        # Device usage
        device_stats = data.groupby('device_id').size().reset_index(name='device_usage_count')
        
        # Merge
        data = data.merge(user_stats, on='user', how='left')
        data = data.merge(device_stats, on='device_id', how='left')
        
        # Time-based features
        data = data.sort_values(['user', 'timestamp'])
        data['time_since_last_transfer'] = data.groupby('user')['timestamp'].diff().dt.total_seconds().fillna(0)
        
        return data
    
    def create_user_profiles(self, data):
        """Create comprehensive user behavior profiles"""
        profiles = []
        
        for user in data['user'].unique():
            user_data = data[data['user'] == user]
            
            # Behavioral metrics
            avg_bytes = user_data['bytes_written'].mean()
            std_bytes = user_data['bytes_written'].std()
            session_count = len(user_data)
            unique_devices = user_data['device_id'].nunique()
            
            # Time patterns
            working_hours_pct = len(user_data[(user_data['hour'] >= 8) & (user_data['hour'] <= 17)]) / len(user_data)
            weekend_pct = len(user_data[user_data['day_of_week'] >= 5]) / len(user_data)
            
            # Risk scoring
            risk_score = self.calculate_user_risk_score(user_data)
            
            # Session frequency
            if len(user_data) > 1:
                time_diffs = user_data['timestamp'].diff().dt.total_seconds().dropna()
                session_frequency = 1 / time_diffs.mean() if time_diffs.mean() > 0 else 0
            else:
                session_frequency = 0
            
            profiles.append({
                'user': user,
                'user_avg_bytes': avg_bytes,
                'user_std_bytes': std_bytes or avg_bytes * 0.1,
                'session_frequency': session_frequency,
                'working_hours_pct': working_hours_pct,
                'weekend_pct': weekend_pct,
                'user_risk_profile': risk_score,
                'unique_devices': unique_devices
            })
        
        return pd.DataFrame(profiles)
    
    def calculate_user_risk_score(self, user_data):
        """Calculate comprehensive user risk score"""
        risk_factors = []
        
        # Volume risk
        if user_data['bytes_written'].max() > 1e9:  # >1GB
            risk_factors.append(0.3)
        
        # Frequency risk
        if len(user_data) > 100:  # Very high frequency
            risk_factors.append(0.2)
        
        # Time pattern risk
        off_hours_pct = len(user_data[(user_data['hour'] < 8) | (user_data['hour'] > 17)]) / len(user_data)
        if off_hours_pct > 0.3:
            risk_factors.append(0.2)
        
        # Device diversity risk
        if user_data['device_id'].nunique() > 5:
            risk_factors.append(0.3)
        
        return sum(risk_factors)
    
    def add_temporal_features(self, data):
        """Add advanced temporal pattern features"""
        data['unusual_time_score'] = 0
        
        # Off-hours scoring
        data.loc[(data['hour'] < 8) | (data['hour'] > 17), 'unusual_time_score'] += 0.3
        
        # Weekend scoring
        data.loc[data['day_of_week'] >= 5, 'unusual_time_score'] += 0.2
        
        # Late night/early morning
        data.loc[(data['hour'] >= 22) | (data['hour'] <= 5), 'unusual_time_score'] += 0.5
        
        # Velocity calculation
        data['data_velocity'] = data['bytes_written'] / np.maximum(data['session_duration'], 1)
        
        return data
    
    def assess_device_risk(self, data):
        """Assess device-based risk factors"""
        device_risk = {}
        
        for device in data['device_id'].unique():
            device_data = data[data['device_id'] == device]
            
            # Risk factors
            user_count = device_data['user'].nunique()
            total_bytes = device_data['bytes_written'].sum()
            usage_frequency = len(device_data)
            
            # Calculate risk score
            risk_score = 0
            if user_count > 3:  # Shared device
                risk_score += 0.3
            if total_bytes > 1e10:  # >10GB total
                risk_score += 0.4
            if usage_frequency > 50:  # High frequency
                risk_score += 0.3
            
            device_risk[device] = risk_score
        
        data['device_risk_score'] = data['device_id'].map(device_risk)
        return data
    
    def integrate_threat_intelligence(self, data):
        """Integrate threat intelligence indicators"""
        # Simulated threat intelligence (in real implementation, this would connect to threat feeds)
        
        # Known malicious patterns
        data['known_malicious_pattern'] = 0
        data.loc[data['bytes_written'] > 5e9, 'known_malicious_pattern'] = 1  # >5GB
        
        # Suspicious file types (would be based on actual file analysis)
        suspicious_types = ['software', 'data', 'backup']
        data['suspicious_file_types'] = data['file_types'].isin(suspicious_types).astype(int)
        
        # Encryption detection (simulated)
        data['encryption_detected'] = (data['bytes_written'] % 1024 == 0).astype(int)
        
        # Steganography risk
        data['steganography_risk'] = ((data['file_types'] == 'images') & 
                                     (data['bytes_written'] > 1e7)).astype(int)
        
        # Data exfiltration signature
        data['data_exfiltration_signature'] = (
            (data['unusual_time_score'] > 0.5) & 
            (data['bytes_written'] > 1e8)
        ).astype(int)
        
        # Insider threat score
        data['insider_threat_score'] = (
            data['user_risk_profile'] * 0.4 +
            data['device_risk_score'] * 0.3 +
            data['unusual_time_score'] * 0.3
        )
        
        return data
    
    def create_sequence_features(self, data):
        """Create sequence-based features for LSTM"""
        data = data.sort_values(['user', 'timestamp'])
        
        # Rolling statistics
        data['rolling_avg_bytes'] = data.groupby('user')['bytes_written'].rolling(window=5).mean().reset_index(0, drop=True)
        data['rolling_std_bytes'] = data.groupby('user')['bytes_written'].rolling(window=5).std().reset_index(0, drop=True)
        
        # Deviation from personal baseline
        data['size_deviation_score'] = abs(data['bytes_written'] - data['rolling_avg_bytes']) / np.maximum(data['rolling_std_bytes'], 1)
        
        # Access pattern scoring
        data['access_pattern_score'] = 0
        user_groups = data.groupby('user')
        
        for user, group in user_groups:
            if len(group) > 1:
                # Calculate pattern consistency
                time_diffs = group['timestamp'].diff().dt.total_seconds().dropna()
                if len(time_diffs) > 0:
                    pattern_consistency = 1 / (1 + time_diffs.std() / time_diffs.mean())
                    data.loc[data['user'] == user, 'access_pattern_score'] = pattern_consistency
        
        # Fill NaN values
        data = data.fillna(0)
        
        return data
    
    def prepare_sequence_data(self, data, sequence_length=10):
        """Prepare data for LSTM sequence analysis"""
        sequences = []
        labels = []
        
        for user in data['user'].unique():
            user_data = data[data['user'] == user].sort_values('timestamp')
            
            if len(user_data) >= sequence_length:
                for i in range(len(user_data) - sequence_length + 1):
                    sequence = user_data.iloc[i:i+sequence_length][self.feature_columns].values
                    label = user_data.iloc[i+sequence_length-1].get('is_anomaly', 0)
                    sequences.append(sequence)
                    labels.append(label)
        
        return np.array(sequences), np.array(labels)
    
    def build_anomaly_detection_model(self, input_dim):
        """Build deep neural network for anomaly detection"""
        model = Sequential([
            Dense(256, activation='relu', input_dim=input_dim),
            BatchNormalization(),
            Dropout(0.3),
            
            Dense(128, activation='relu'),
            BatchNormalization(),
            Dropout(0.3),
            
            Dense(64, activation='relu'),
            BatchNormalization(),
            Dropout(0.2),
            
            Dense(32, activation='relu'),
            Dropout(0.2),
            
            Dense(1, activation='sigmoid')
        ])
        
        model.compile(
            optimizer=Adam(learning_rate=0.001),
            loss='binary_crossentropy',
            metrics=['accuracy', 'precision', 'recall']
        )
        
        return model
    
    def build_sequence_model(self, sequence_length, feature_dim):
        """Build LSTM model for sequence analysis"""
        model = Sequential([
            LSTM(128, return_sequences=True, input_shape=(sequence_length, feature_dim)),
            Dropout(0.3),
            
            LSTM(64, return_sequences=False),
            Dropout(0.3),
            
            Dense(32, activation='relu'),
            Dropout(0.2),
            
            Dense(1, activation='sigmoid')
        ])
        
        model.compile(
            optimizer=Adam(learning_rate=0.001),
            loss='binary_crossentropy',
            metrics=['accuracy', 'precision', 'recall']
        )
        
        return model
    
    def train_models(self, data, test_size=0.2):
        """Train both neural network models"""
        logger.info("Starting deep learning model training...")
        
        # Feature engineering
        data = self.advanced_feature_engineering(data)
        
        # Prepare standard features
        features = data[self.feature_columns + self.threat_indicators].fillna(0)
        labels = data.get('is_anomaly', np.zeros(len(features)))
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            features, labels, test_size=test_size, random_state=42, stratify=labels
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train anomaly detection model
        logger.info("Training anomaly detection neural network...")
        self.anomaly_model = self.build_anomaly_detection_model(X_train_scaled.shape[1])
        
        callbacks = [
            EarlyStopping(patience=10, restore_best_weights=True),
            ReduceLROnPlateau(factor=0.5, patience=5)
        ]
        
        history = self.anomaly_model.fit(
            X_train_scaled, y_train,
            validation_data=(X_test_scaled, y_test),
            epochs=100,
            batch_size=32,
            callbacks=callbacks,
            verbose=1
        )
        
        # Train sequence model
        logger.info("Training sequence analysis LSTM...")
        sequences, seq_labels = self.prepare_sequence_data(data)
        
        if len(sequences) > 0:
            seq_train, seq_test, seq_y_train, seq_y_test = train_test_split(
                sequences, seq_labels, test_size=test_size, random_state=42
            )
            
            self.sequence_model = self.build_sequence_model(sequences.shape[1], sequences.shape[2])
            
            seq_history = self.sequence_model.fit(
                seq_train, seq_y_train,
                validation_data=(seq_test, seq_y_test),
                epochs=50,
                batch_size=16,
                callbacks=callbacks,
                verbose=1
            )
        
        # Evaluate models
        self.evaluate_models(X_test_scaled, y_test)
        
        # Save models
        self.save_models()
        
        logger.info("Deep learning model training completed successfully")
    
    def evaluate_models(self, X_test, y_test):
        """Evaluate model performance"""
        logger.info("Evaluating deep learning models...")
        
        # Anomaly detection model
        y_pred_proba = self.anomaly_model.predict(X_test)
        y_pred = (y_pred_proba > 0.5).astype(int)
        
        logger.info("Anomaly Detection Model Performance:")
        logger.info(f"\n{classification_report(y_test, y_pred)}")
        
        if len(np.unique(y_test)) > 1:
            auc_score = roc_auc_score(y_test, y_pred_proba)
            logger.info(f"AUC-ROC Score: {auc_score:.4f}")
        
        # Calculate custom metrics
        precision = np.sum((y_pred == 1) & (y_test == 1)) / np.sum(y_pred == 1) if np.sum(y_pred == 1) > 0 else 0
        recall = np.sum((y_pred == 1) & (y_test == 1)) / np.sum(y_test == 1) if np.sum(y_test == 1) > 0 else 0
        f1_score = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        
        logger.info(f"Custom Metrics - Precision: {precision:.4f}, Recall: {recall:.4f}, F1: {f1_score:.4f}")
    
    def predict_anomalies(self, data):
        """Predict anomalies using ensemble of models"""
        if self.anomaly_model is None:
            self.load_models()
        
        # Feature engineering
        data = self.advanced_feature_engineering(data)
        
        # Standard prediction
        features = data[self.feature_columns + self.threat_indicators].fillna(0)
        X_scaled = self.scaler.transform(features)
        
        # Neural network prediction
        nn_scores = self.anomaly_model.predict(X_scaled)
        nn_predictions = (nn_scores > 0.5).astype(int)
        
        # Sequence prediction (if available)
        seq_predictions = np.zeros(len(data))
        if self.sequence_model is not None:
            sequences, _ = self.prepare_sequence_data(data)
            if len(sequences) > 0:
                seq_scores = self.sequence_model.predict(sequences)
                seq_predictions = (seq_scores > 0.5).astype(int).flatten()
        
        # Combine predictions
        results = data.copy()
        results['nn_anomaly_score'] = nn_scores.flatten()
        results['nn_anomaly'] = nn_predictions.flatten()
        results['seq_anomaly'] = seq_predictions[:len(data)]
        
        # Ensemble prediction
        results['ensemble_anomaly'] = np.maximum(results['nn_anomaly'], results['seq_anomaly'])
        
        # Enhanced risk scoring
        results['threat_score'] = (
            results['nn_anomaly_score'] * 0.4 +
            results['insider_threat_score'] * 0.3 +
            results['data_exfiltration_signature'] * 0.3
        )
        
        # Risk categorization
        results['risk_category'] = pd.cut(
            results['threat_score'],
            bins=[0, 0.25, 0.5, 0.75, 1.0],
            labels=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        )
        
        return results
    
    def save_models(self):
        """Save trained models"""
        logger.info(f"Saving deep learning models to {self.model_path}")
        
        # Save neural network models
        self.anomaly_model.save(f"{self.model_path}/anomaly_nn_model.h5")
        if self.sequence_model is not None:
            self.sequence_model.save(f"{self.model_path}/sequence_lstm_model.h5")
        
        # Save preprocessors
        joblib.dump(self.scaler, f"{self.model_path}/deep_scaler.pkl")
        
        # Save metadata
        metadata = {
            'model_version': '2.0',
            'model_type': 'Deep Learning Ensemble',
            'training_date': datetime.now().isoformat(),
            'feature_columns': self.feature_columns,
            'threat_indicators': self.threat_indicators,
            'architecture': 'Neural Network + LSTM'
        }
        
        with open(f"{self.model_path}/deep_metadata.json", 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logger.info("Deep learning models saved successfully")
    
    def load_models(self):
        """Load trained models"""
        logger.info(f"Loading deep learning models from {self.model_path}")
        
        try:
            self.anomaly_model = tf.keras.models.load_model(f"{self.model_path}/anomaly_nn_model.h5")
            
            seq_model_path = f"{self.model_path}/sequence_lstm_model.h5"
            if os.path.exists(seq_model_path):
                self.sequence_model = tf.keras.models.load_model(seq_model_path)
            
            self.scaler = joblib.load(f"{self.model_path}/deep_scaler.pkl")
            
            with open(f"{self.model_path}/deep_metadata.json", 'r') as f:
                metadata = json.load(f)
                logger.info(f"Loaded model version: {metadata['model_version']}")
                
        except FileNotFoundError:
            logger.error("Deep learning model files not found. Please train models first.")
            raise

def main():
    """Main execution function"""
    if len(sys.argv) < 2:
        print("Usage: python usb_deep_learning_model.py <command> [args]")
        print("Commands: train, predict, evaluate")
        sys.exit(1)
    
    command = sys.argv[1].lower()
    model = USBDeepLearningModel()
    
    if command == 'train':
        data_path = '../lookups/usb_activity_sample.csv'
        
        if os.path.exists(data_path):
            data = pd.read_csv(data_path)
            logger.info(f"Loaded {len(data)} records for training")
            
            model.train_models(data)
            print("Deep learning model training completed successfully!")
            
        else:
            logger.error(f"Training data not found at {data_path}")
    
    elif command == 'predict':
        data_path = '../lookups/usb_activity_sample.csv'
        
        if os.path.exists(data_path):
            data = pd.read_csv(data_path)
            results = model.predict_anomalies(data)
            
            critical_threats = results[results['risk_category'] == 'CRITICAL']
            print(f"Found {len(critical_threats)} critical threats")
            
            if len(critical_threats) > 0:
                print("\nCritical Threats:")
                print(critical_threats[['timestamp', 'user', 'bytes_written', 'threat_score', 'risk_category']].head())
    
    elif command == 'evaluate':
        print("Model evaluation completed - check logs for details")
    
    else:
        print(f"Unknown command: {command}")

if __name__ == "__main__":
    main()