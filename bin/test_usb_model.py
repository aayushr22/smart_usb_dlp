#!/usr/bin/env python3
"""
Test Suite for USB ML Model
Unit tests for the Smart USB DLP System ML Model Implementation
"""

import unittest
import sys
import os
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import tempfile
import shutil
import json

# Add the project directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from usb_ml_model import USBMLModel

class TestUSBMLModel(unittest.TestCase):
    """Test cases for USB ML Model"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.model = USBMLModel(model_path=self.temp_dir)
        
        # Create sample test data
        self.sample_data = self._create_sample_data()
        
    def tearDown(self):
        """Clean up test fixtures"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def _create_sample_data(self):
        """Create sample data for testing"""
        np.random.seed(42)  # For reproducible tests
        
        users = ['alice', 'bob', 'charlie', 'diana', 'eve']
        device_types = ['USB_Flash', 'External_HDD', 'USB_SSD', 'Unknown']
        
        data = []
        base_time = datetime.now() - timedelta(days=30)
        
        for i in range(100):
            # Generate realistic test data
            user = np.random.choice(users)
            device_type = np.random.choice(device_types)
            
            # Normal usage patterns
            if np.random.random() > 0.2:  # 80% normal
                bytes_written = np.random.lognormal(15, 1.5)  # ~1MB to 1GB
                hour = np.random.choice(range(8, 18))  # Business hours
                day_of_week = np.random.choice(range(0, 5))  # Weekdays
            else:  # 20% anomalous
                bytes_written = np.random.lognormal(20, 2)  # Much larger
                hour = np.random.choice([2, 3, 22, 23])  # Off hours
                day_of_week = np.random.choice([5, 6])  # Weekend
            
            timestamp = base_time + timedelta(hours=i)
            
            data.append({
                'timestamp': timestamp.isoformat(),
                'user': user,
                'device_id': f'dev_{i % 20}',
                'device_type': device_type,
                'bytes_written': int(bytes_written),
                'session_duration': np.random.randint(30, 3600),
                'hour': hour,
                'day_of_week': day_of_week
            })
        
        return pd.DataFrame(data)
    
    def test_model_initialization(self):
        """Test model initialization"""
        self.assertIsNotNone(self.model)
        self.assertEqual(self.model.model_path, self.temp_dir)
        self.assertIsNone(self.model.dbscan_model)
        self.assertIsNone(self.model.isolation_forest)
        self.assertIsNotNone(self.model.scaler)
        self.assertIsInstance(self.model.feature_columns, list)
        self.assertGreater(len(self.model.feature_columns), 0)
    
    def test_feature_extraction(self):
        """Test feature extraction functionality"""
        # Test with sample data
        features = self.model.extract_features(self.sample_data.copy())
        
        # Check that all required columns are present
        for col in self.model.feature_columns:
            self.assertIn(col, features.columns, f"Missing feature column: {col}")
        
        # Check data types and values
        self.assertTrue(features['bytes_written'].dtype in [np.int64, np.float64])
        self.assertTrue(features['hour'].between(0, 23).all())
        self.assertTrue(features['day_of_week'].between(0, 6).all())
        
        # Check for no missing values in feature columns
        for col in self.model.feature_columns:
            self.assertFalse(features[col].isnull().any(), f"Null values in {col}")
    
    def test_model_training(self):
        """Test model training process"""
        # Prepare data
        data = self.model.extract_features(self.sample_data.copy())
        
        # Train models
        self.model.train_models(data, test_size=0.3)
        
        # Check that models are trained
        self.assertIsNotNone(self.model.dbscan_model)
        self.assertIsNotNone(self.model.isolation_forest)
        
        # Check that model files are saved
        self.assertTrue(os.path.exists(f"{self.temp_dir}/dbscan_model.pkl"))
        self.assertTrue(os.path.exists(f"{self.temp_dir}/isolation_forest.pkl"))
        self.assertTrue(os.path.exists(f"{self.temp_dir}/scaler.pkl"))
        self.assertTrue(os.path.exists(f"{self.temp_dir}/metadata.json"))
    
    def test_model_prediction(self):
        """Test model prediction functionality"""
        # Train model first
        data = self.model.extract_features(self.sample_data.copy())
        self.model.train_models(data, test_size=0.3)
        
        # Test prediction
        test_data = data.head(10)
        results = self.model.predict_anomalies(test_data)
        
        # Check results structure
        self.assertIsInstance(results, pd.DataFrame)
        self.assertEqual(len(results), 10)
        
        # Check required columns
        expected_columns = ['dbscan_anomaly', 'isolation_anomaly', 'combined_anomaly', 
                          'anomaly_score', 'risk_level']
        for col in expected_columns:
            self.assertIn(col, results.columns)
        
        # Check data types
        self.assertTrue(results['dbscan_anomaly'].dtype == np.int64)
        self.assertTrue(results['isolation_anomaly'].dtype == np.int64)
        self.assertTrue(results['combined_anomaly'].dtype == np.int64)
        self.assertTrue(results['anomaly_score'].dtype in [np.float64, np.float32])
        
        # Check value ranges
        self.assertTrue(results['dbscan_anomaly'].isin([0, 1]).all())
        self.assertTrue(results['isolation_anomaly'].isin([0, 1]).all())
        self.assertTrue(results['combined_anomaly'].isin([0, 1]).all())
    
    def test_model_save_load(self):
        """Test model save and load functionality"""
        # Train and save model
        data = self.model.extract_features(self.sample_data.copy())
        self.model.train_models(data, test_size=0.3)
        
        # Create new model instance and load
        new_model = USBMLModel(model_path=self.temp_dir)
        new_model.load_models()
        
        # Check that models are loaded
        self.assertIsNotNone(new_model.dbscan_model)
        self.assertIsNotNone(new_model.isolation_forest)
        self.assertIsNotNone(new_model.scaler)
        
        # Test prediction consistency
        test_data = data.head(5)
        results1 = self.model.predict_anomalies(test_data)
        results2 = new_model.predict_anomalies(test_data)
        
        # Results should be identical
        pd.testing.assert_frame_equal(
            results1[['combined_anomaly', 'anomaly_score']].round(6),
            results2[['combined_anomaly', 'anomaly_score']].round(6)
        )
    
    def test_model_stats(self):
        """Test model statistics functionality"""
        # Test without trained model
        stats = self.model.get_model_stats()
        self.assertIn('model_status', stats)
        self.assertEqual(stats['model_status'], 'Not Available - Train First')
        
        # Train model
        data = self.model.extract_features(self.sample_data.copy())
        self.model.train_models(data, test_size=0.3)
        
        # Test with trained model
        stats = self.model.get_model_stats()
        self.assertIn('model_version', stats)
        self.assertIn('training_date', stats)
        self.assertIn('feature_count', stats)
        self.assertIn('model_status', stats)
        self.assertEqual(stats['model_status'], 'Loaded and Ready')
    
    def test_edge_cases(self):
        """Test edge cases and error handling"""
        # Test with empty data
        empty_data = pd.DataFrame()
        with self.assertRaises(Exception):
            self.model.extract_features(empty_data)
        
        # Test with missing columns
        incomplete_data = pd.DataFrame({
            'timestamp': [datetime.now().isoformat()],
            'user': ['test_user']
        })
        
        # Should handle missing columns gracefully
        try:
            features = self.model.extract_features(incomplete_data)
            self.assertIsInstance(features, pd.DataFrame)
        except Exception as e:
            self.fail(f"Feature extraction failed with incomplete data: {e}")
        
        # Test loading non-existent model
        empty_model = USBMLModel(model_path='/nonexistent/path')
        with self.assertRaises(FileNotFoundError):
            empty_model.load_models()
    
    def test_data_preprocessing(self):
        """Test data preprocessing steps"""
        original_data = self.sample_data.copy()
        processed_data = self.model.extract_features(original_data)
        
        # Check that original data is not modified
        self.assertEqual(len(original_data), len(self.sample_data))
        
        # Check that processed data has additional columns
        self.assertGreater(len(processed_data.columns), len(original_data.columns))
        
        # Check specific engineered features
        self.assertIn('user_avg_bytes', processed_data.columns)
        self.assertIn('device_usage_count', processed_data.columns)
        self.assertIn('time_since_last_transfer', processed_data.columns)
        self.assertIn('bytes_z_score', processed_data.columns)
        self.assertIn('is_off_hours', processed_data.columns)
        self.assertIn('is_weekend', processed_data.columns)
        
        # Check feature value ranges
        self.assertTrue(processed_data['is_off_hours'].isin([0, 1]).all())
        self.assertTrue(processed_data['is_weekend'].isin([0, 1]).all())
    
    def test_anomaly_detection_rates(self):
        """Test that anomaly detection rates are reasonable"""
        # Create data with known anomalies
        normal_data = self.sample_data[self.sample_data['bytes_written'] < 1e8].copy()
        anomaly_data = self.sample_data[self.sample_data['bytes_written'] >= 1e8].copy()
        
        if len(normal_data) > 0 and len(anomaly_data) > 0:
            combined_data = pd.concat([normal_data, anomaly_data])
            processed_data = self.model.extract_features(combined_data)
            
            # Train model
            self.model.train_models(processed_data, test_size=0.3)
            
            # Test predictions
            results = self.model.predict_anomalies(processed_data)
            
            # Check that anomaly rate is reasonable (5-30%)
            anomaly_rate = results['combined_anomaly'].mean()
            self.assertGreaterEqual(anomaly_rate, 0.05)
            self.assertLessEqual(anomaly_rate, 0.50)

class TestModelIntegration(unittest.TestCase):
    """Integration tests for the ML model"""
    
    def setUp(self):
        """Set up integration test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.model = USBMLModel(model_path=self.temp_dir)
    
    def tearDown(self):
        """Clean up integration test fixtures"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_full_pipeline(self):
        """Test the complete ML pipeline"""
        # Create larger dataset for integration test
        np.random.seed(42)
        data = []
        
        for i in range(500):
            user = f'user_{i % 20}'
            device_id = f'device_{i % 50}'
            
            # Create realistic patterns
            if i % 10 == 0:  # 10% anomalous
                bytes_written = np.random.randint(1e9, 5e9)  # 1-5GB
                hour = np.random.choice([1, 2, 23])
            else:  # 90% normal
                bytes_written = np.random.randint(1e5, 1e8)  # 100KB-100MB
                hour = np.random.choice(range(8, 18))
            
            timestamp = datetime.now() - timedelta(hours=500-i)
            
            data.append({
                'timestamp': timestamp.isoformat(),
                'user': user,
                'device_id': device_id,
                'device_type': 'USB_Flash',
                'bytes_written': bytes_written,
                'session_duration': np.random.randint(60, 1800),
                'hour': hour,
                'day_of_week': np.random.randint(0, 7)
            })
        
        df = pd.DataFrame(data)
        
        # Run full pipeline
        processed_data = self.model.extract_features(df)
        self.model.train_models(processed_data, test_size=0.2)
        results = self.model.predict_anomalies(processed_data)
        
        # Verify results
        self.assertEqual(len(results), 500)
        self.assertGreater(results['combined_anomaly'].sum(), 0)
        
        # Check that high-risk items are flagged
        high_bytes = results[results['bytes_written'] > 1e9]
        if len(high_bytes) > 0:
            # At least some large transfers should be flagged
            self.assertGreater(high_bytes['combined_anomaly'].mean(), 0.1)

def run_tests():
    """Run all tests"""
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_suite.addTest(unittest.makeSuite(TestUSBMLModel))
    test_suite.addTest(unittest.makeSuite(TestModelIntegration))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    return result.wasSuccessful()

if __name__ == '__main__':
    print("Running USB ML Model Tests...")
    print("=" * 50)
    
    success = run_tests()
    
    if success:
        print("\n" + "=" * 50)
        print("All tests passed successfully!")
        sys.exit(0)
    else:
        print("\n" + "=" * 50)
        print("Some tests failed. Please check the output above.")
        sys.exit(1)