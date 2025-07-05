"""
Smart USB DLP System - ML Model Implementation
Real-time anomaly detection for USB data exfiltration
"""

import sys
import os
import json
import pandas as pd
import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
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
        logging.FileHandler('tmp/usb_ml_model.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class USBMLModel:
    """
    Machine Learning model for USB anomaly detection
    Combines DBSCAN clustering with Isolation Forest for robust anomaly detection
    """
    
    def __init__(self, model_path='tmp/usb_ml_models'):
        self.model_path = model_path
        self.dbscan_model = None
        self.isolation_forest = None
        self.scaler = StandardScaler()
        self.feature_columns = [
            'bytes_written', 'session_duration', 'hour', 'day_of_week',
            'user_avg_bytes', 'device_usage_count', 'time_since_last_transfer'
        ]
        
        # Ensure model directory exists
        os.makedirs(model_path, exist_ok=True)


    def _extract_features(self, event):
        """
        Extract features from a single event for ML model
        """
        try:
            # Handle both dict and object-like events
            if hasattr(event, 'get'):
                get_func = event.get
            elif isinstance(event, dict):
                get_func = event.get
            else:
                get_func = lambda key, default=None: getattr(event, key, default)
            
            # Import datetime if not already imported
            from datetime import datetime
            
            # Basic features
            features = [
                1.0 if get_func('action') == 'connect' else 0.0,
                1.0 if get_func('device_type') == 'unknown' else 0.0,
                min(get_func('size', 0) / 1000000.0, 1.0),  # Normalize size to MB
                1.0 if get_func('vendor_id') == 'unknown' else 0.0,
                len(str(get_func('file_path', ''))) / 100.0,  # Normalize path length
                get_func('hour', datetime.now().hour) / 24.0,  # Normalize hour
                get_func('day_of_week', datetime.now().weekday()) / 7.0,  # Normalize day
            ]
            
            # Add additional features to match feature_columns length
            # Check if we have feature_columns defined
            if hasattr(self, 'feature_columns'):
                target_length = len(self.feature_columns)
            else:
                target_length = 17  # Based on your test output showing 17 features
            
            # Add more features if needed
            while len(features) < target_length:
                # Add common USB monitoring features
                additional_features = [
                    get_func('bytes_written', 0) / 1000000.0,  # Normalize bytes written
                    get_func('bytes_read', 0) / 1000000.0,     # Normalize bytes read
                    1.0 if get_func('is_encrypted', False) else 0.0,
                    get_func('transfer_speed', 0) / 1000.0,    # Normalize speed
                    get_func('session_duration', 0) / 3600.0,  # Normalize duration to hours
                    1.0 if get_func('device_authorized', True) else 0.0,
                    get_func('file_count', 0) / 100.0,         # Normalize file count
                    1.0 if get_func('suspicious_activity', False) else 0.0,
                    get_func('access_frequency', 0) / 10.0,    # Normalize frequency
                    1.0 if get_func('after_hours', False) else 0.0,
                ]
                
                # Add features one by one until we reach target length
                for additional_feature in additional_features:
                    if len(features) < target_length:
                        features.append(additional_feature)
                    else:
                        break
                
                # If we still don't have enough features, pad with zeros
                if len(features) < target_length:
                    features.extend([0.0] * (target_length - len(features)))
            
            # Ensure we don't exceed the target length
            features = features[:target_length]
            
            return features
            
        except Exception as e:
            # Import logger if not already imported
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Feature extraction failed: {str(e)}")
            
            # Return default features
            default_length = getattr(self, 'feature_columns', 17)
            if hasattr(default_length, '__len__'):
                default_length = len(default_length)
            else:
                default_length = 17
                
            return [0.0] * default_length




    def predict_event(self, event):
        """
        Predict threat level for a USB event
        Returns: prediction score (float)
        """
        try:
            # Convert event to feature vector for ML model
            features = self._extract_features(event)
            
            # If model is trained, use it for prediction
            if hasattr(self, 'isolation_forest') and self.isolation_forest is not None:
                # Convert to numpy array and reshape
                feature_vector = np.array(features).reshape(1, -1)
                
                # Ensure we have the right number of features
                if feature_vector.shape[1] < len(self.feature_columns):
                    # Pad with zeros if needed
                    padding = np.zeros((1, len(self.feature_columns) - feature_vector.shape[1]))
                    feature_vector = np.hstack([feature_vector, padding])
                elif feature_vector.shape[1] > len(self.feature_columns):
                    # Truncate if too many features
                    feature_vector = feature_vector[:, :len(self.feature_columns)]
                
                # Scale features
                try:
                    scaled_features = self.scaler.transform(feature_vector)
                    prediction = self.isolation_forest.predict(scaled_features)[0]
                    
                    # Get anomaly score
                    anomaly_score = self.isolation_forest.decision_function(scaled_features)[0]
                    
                    # Convert to probability score (0-1)
                    if prediction == -1:  # Anomaly
                        return min(0.8 + abs(anomaly_score) * 0.2, 1.0)
                    else:  # Normal
                        return max(0.2 - abs(anomaly_score) * 0.2, 0.0)
                        
                except Exception as e:
                    logger.warning(f"Model prediction failed, using fallback: {str(e)}")
                    return self._fallback_prediction(event)
            else:
                # Fallback to rule-based scoring if model not trained
                return self._fallback_prediction(event)
                
        except Exception as e:
            logger.error(f"Event prediction failed: {str(e)}")
            return 0.0

    def _fallback_prediction(self, event):
        """Fallback rule-based prediction when model is not available"""
        try:
            # Handle both dict and object-like events
            if hasattr(event, 'get'):
                get_func = event.get
            else:
                get_func = lambda key, default=None: getattr(event, key, default)
            
            score = 0.0
            
            # Connection events are suspicious
            if get_func('action') == 'connect':
                score += 0.3
            
            # Unknown devices are suspicious
            if get_func('device_type') == 'unknown':
                score += 0.5
            
            # Large transfers are suspicious
            size = get_func('size', 0)
            if size > 100000000:  # >100MB
                score += 0.4
            elif size > 10000000:  # >10MB
                score += 0.2
            
            # Off-hours activity
            hour = get_func('hour', datetime.now().hour)
            if hour < 6 or hour > 22:
                score += 0.3
            
            # Unknown vendor
            if get_func('vendor_id') == 'unknown':
                score += 0.2
            
            return min(score, 1.0)
            
        except Exception as e:
            logger.error(f"Fallback prediction failed: {str(e)}")
            return 0.0
        
    def extract_features(self, data):
        """Extract and engineer features for ML model"""
        logger.info(f"Extracting features from {len(data)} records")
        
        # Convert timestamp to datetime
        if 'timestamp' in data.columns:
            data['timestamp'] = pd.to_datetime(data['timestamp'])
            data['hour'] = data['timestamp'].dt.hour
            data['day_of_week'] = data['timestamp'].dt.dayofweek
        
        # User behavior features
        user_stats = data.groupby('user')['bytes_written'].agg(['mean', 'std', 'count']).reset_index()
        user_stats.columns = ['user', 'user_avg_bytes', 'user_std_bytes', 'user_total_sessions']
        user_stats['user_std_bytes'] = user_stats['user_std_bytes'].fillna(user_stats['user_avg_bytes'] * 0.1)
        
        # Device usage frequency
        device_stats = data.groupby('device_id').size().reset_index(name='device_usage_count')
        
        # Merge features
        data = data.merge(user_stats, on='user', how='left')
        data = data.merge(device_stats, on='device_id', how='left')
        
        # Time-based features
        data = data.sort_values(['user', 'timestamp'])
        data['time_since_last_transfer'] = data.groupby('user')['timestamp'].diff().dt.total_seconds().fillna(0)
        
        # Anomaly indicators
        data['bytes_z_score'] = (data['bytes_written'] - data['user_avg_bytes']) / data['user_std_bytes']
        data['is_off_hours'] = ((data['hour'] < 8) | (data['hour'] > 17)).astype(int)
        data['is_weekend'] = (data['day_of_week'] >= 5).astype(int)
        
        # Risk scoring
        data['size_category'] = pd.cut(data['bytes_written'], 
                                     bins=[0, 1024**2, 100*1024**2, 1024**3, float('inf')],
                                     labels=['Small', 'Medium', 'Large', 'Huge'])
        
        logger.info(f"Feature extraction completed. Shape: {data.shape}")
        return data

    def train_models(self, data, test_size=0.2):
        """Train both DBSCAN and Isolation Forest models"""
        logger.info("Starting model training...")
        
        # Prepare features
        features = data[self.feature_columns].fillna(0)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            features, data.get('is_anomaly', np.zeros(len(features))), 
            test_size=test_size, random_state=42
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train DBSCAN
        logger.info("Training DBSCAN model...")
        self.dbscan_model = DBSCAN(eps=0.5, min_samples=5)
        dbscan_labels = self.dbscan_model.fit_predict(X_train_scaled)
        
        # Train Isolation Forest
        logger.info("Training Isolation Forest model...")
        self.isolation_forest = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        self.isolation_forest.fit(X_train_scaled)
        
        # Evaluate models
        self.evaluate_models(X_test_scaled, y_test)
        
        # Save models
        self.save_models()
        
        logger.info("Model training completed successfully")
        
    def evaluate_models(self, X_test, y_test):
        """Evaluate model performance"""
        logger.info("Evaluating model performance...")
        
        # DBSCAN predictions
        dbscan_pred = self.dbscan_model.fit_predict(X_test)
        dbscan_anomalies = (dbscan_pred == -1).astype(int)
        
        # Isolation Forest predictions
        isolation_pred = self.isolation_forest.predict(X_test)
        isolation_anomalies = (isolation_pred == -1).astype(int)
        
        # Combined predictions (either model flags as anomaly)
        combined_pred = np.logical_or(dbscan_anomalies, isolation_anomalies).astype(int)
        
        # Calculate metrics if ground truth available
        if len(np.unique(y_test)) > 1:
            logger.info("DBSCAN Performance:")
            logger.info(f"\n{classification_report(y_test, dbscan_anomalies)}")
            
            logger.info("Isolation Forest Performance:")
            logger.info(f"\n{classification_report(y_test, isolation_anomalies)}")
            
            logger.info("Combined Model Performance:")
            logger.info(f"\n{classification_report(y_test, combined_pred)}")
        
        # Log anomaly rates
        dbscan_rate = np.mean(dbscan_anomalies) * 100
        isolation_rate = np.mean(isolation_anomalies) * 100
        combined_rate = np.mean(combined_pred) * 100
        
        logger.info(f"Anomaly Detection Rates:")
        logger.info(f"  DBSCAN: {dbscan_rate:.2f}%")
        logger.info(f"  Isolation Forest: {isolation_rate:.2f}%")
        logger.info(f"  Combined: {combined_rate:.2f}%")
        
    def predict_anomalies(self, data):
        """Predict anomalies in new data"""
        if self.dbscan_model is None or self.isolation_forest is None:
            try:
                self.load_models()
            except FileNotFoundError:
                logger.warning("No trained models found. Using fallback predictions.")
                # Create fallback predictions
                results = data.copy()
                results['dbscan_anomaly'] = 0
                results['isolation_anomaly'] = 0
                results['combined_anomaly'] = 0
                results['anomaly_score'] = 0.0
                results['risk_level'] = 'LOW'
                return results
        
        features = data[self.feature_columns].fillna(0)
        X_scaled = self.scaler.transform(features)
        
        # Get predictions from both models
        dbscan_pred = self.dbscan_model.fit_predict(X_scaled)
        isolation_pred = self.isolation_forest.predict(X_scaled)
        
        # Convert to anomaly flags
        dbscan_anomalies = (dbscan_pred == -1).astype(int)
        isolation_anomalies = (isolation_pred == -1).astype(int)
        
        # Combined decision
        combined_anomalies = np.logical_or(dbscan_anomalies, isolation_anomalies).astype(int)
        
        # Calculate anomaly scores
        anomaly_scores = self.isolation_forest.decision_function(X_scaled)
        
        # Add results to data
        results = data.copy()
        results['dbscan_anomaly'] = dbscan_anomalies
        results['isolation_anomaly'] = isolation_anomalies
        results['combined_anomaly'] = combined_anomalies
        results['anomaly_score'] = anomaly_scores
        
        # Risk categorization
        results['risk_level'] = pd.cut(
            -anomaly_scores,  # Negative because lower scores = more anomalous
            bins=[-float('inf'), -0.5, -0.1, 0.1, float('inf')],
            labels=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        )
        
        return results
    
    def save_models(self):
        """Save trained models to disk"""
        logger.info(f"Saving models to {self.model_path}")
        
        joblib.dump(self.dbscan_model, f"{self.model_path}/dbscan_model.pkl")
        joblib.dump(self.isolation_forest, f"{self.model_path}/isolation_forest.pkl")
        joblib.dump(self.scaler, f"{self.model_path}/scaler.pkl")
        
        # Save metadata
        metadata = {
            'model_version': '1.0',
            'training_date': datetime.now().isoformat(),
            'feature_columns': self.feature_columns,
            'model_type': 'DBSCAN + Isolation Forest'
        }
        
        with open(f"{self.model_path}/metadata.json", 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logger.info("Models saved successfully")
    
    def load_models(self):
        """Load trained models from disk"""
        logger.info(f"Loading models from {self.model_path}")
        
        try:
            self.dbscan_model = joblib.load(f"{self.model_path}/dbscan_model.pkl")
            self.isolation_forest = joblib.load(f"{self.model_path}/isolation_forest.pkl")
            self.scaler = joblib.load(f"{self.model_path}/scaler.pkl")
            
            with open(f"{self.model_path}/metadata.json", 'r') as f:
                metadata = json.load(f)
                logger.info(f"Loaded model version: {metadata['model_version']}")
        except Exception as e:
            logger.error(f"Failed to load models: {str(e)}")
            raise

def main():
    """Example usage of the USBMLModel class"""
    logger.info("Starting Smart USB DLP System")
    
    # Initialize model
    model = USBMLModel()
    
    # Example usage would go here
    logger.info("Model initialized successfully")
    
    # In a real implementation, you would:
    # 1. Load your training data
    # 2. Call model.extract_features()
    # 3. Call model.train_models()
    # 4. Use model.predict_event() or model.predict_anomalies() on new data

if __name__ == "__main__":
    main()
    def get_model_stats(self):
        """Return model statistics"""
        if not hasattr(self, 'dbscan_model') or not hasattr(self, 'isolation_forest'):
            return {"error": "Models not trained yet"}
        
        return {
            "dbscan_clusters": getattr(self.dbscan_model, 'n_clusters_', 0),
            "isolation_forest_contamination": getattr(self.isolation_forest, 'contamination', 0.1),
            "features_count": len(self.feature_columns) if hasattr(self, 'feature_columns') else 0,
            "model_version": "1.0"
        }

