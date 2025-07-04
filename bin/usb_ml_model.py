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
        logging.FileHandler('/tmp/usb_ml_model.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class USBMLModel:
    """
    Machine Learning model for USB anomaly detection
    Combines DBSCAN clustering with Isolation Forest for robust anomaly detection
    """
    
    def __init__(self, model_path='/tmp/usb_ml_models'):
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
            self.load_models()
        
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
                logger.info(f"Training date: {metadata['training_date']}")
            
        except FileNotFoundError:
            logger.error("Model files not found. Please train models first.")
            raise
    
    def get_model_stats(self):
        """Get model statistics and performance metrics"""
        try:
            with open(f"{self.model_path}/metadata.json", 'r') as f:
                metadata = json.load(f)
            
            return {
                'model_version': metadata['model_version'],
                'training_date': metadata['training_date'],
                'feature_count': len(self.feature_columns),
                'model_status': 'Loaded and Ready'
            }
        except:
            return {
                'model_status': 'Not Available - Train First'
            }

def main():
    """Main execution function"""
    if len(sys.argv) < 2:
        print("Usage: python usb_ml_model.py <command> [args]")
        print("Commands: train, predict, stats")
        sys.exit(1)
    
    command = sys.argv[1].lower()
    model = USBMLModel()
    
    if command == 'train':
        # Train models using sample data
        try:
            # Load sample data
            import pandas as pd
            data_path = '../lookups/usb_activity_sample.csv'
            
            if os.path.exists(data_path):
                data = pd.read_csv(data_path)
                logger.info(f"Loaded {len(data)} records for training")
                
                # Extract features
                data = model.extract_features(data)
                
                # Train models
                model.train_models(data)
                
                print("Model training completed successfully!")
                print(f"Model stats: {model.get_model_stats()}")
                
            else:
                logger.error(f"Training data not found at {data_path}")
                print("Please generate sample data first")
                
        except Exception as e:
            logger.error(f"Training failed: {str(e)}")
            print(f"Training failed: {str(e)}")
    
    elif command == 'predict':
        # Predict anomalies in new data
        try:
            # This would typically receive data from Splunk
            # For demo, use sample data
            data_path = '../lookups/usb_activity_sample.csv'
            
            if os.path.exists(data_path):
                data = pd.read_csv(data_path)
                data = model.extract_features(data)
                
                # Get predictions
                results = model.predict_anomalies(data)
                
                # Show anomalies
                anomalies = results[results['combined_anomaly'] == 1]
                print(f"Found {len(anomalies)} anomalies out of {len(results)} records")
                
                if len(anomalies) > 0:
                    print("\nTop 5 Anomalies:")
                    print(anomalies[['timestamp', 'user', 'bytes_written', 'risk_level', 'anomaly_score']].head())
                
        except Exception as e:
            logger.error(f"Prediction failed: {str(e)}")
            print(f"Prediction failed: {str(e)}")
    
    elif command == 'stats':
        # Show model statistics
        stats = model.get_model_stats()
        print("Model Statistics:")
        for key, value in stats.items():
            print(f"   {key}: {value}")
    
    else:
        print(f"Unknown command: {command}")
        print("Available commands: train, predict, stats")

if __name__ == "__main__":
    main()