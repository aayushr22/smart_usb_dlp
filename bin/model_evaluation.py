#!/usr/bin/env python3
"""
Model Evaluation Suite for USB ML Model
Comprehensive evaluation and performance analysis for the Smart USB DLP System
"""

import sys
import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime, timedelta
import json
import warnings
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, roc_curve
from sklearn.metrics import precision_recall_curve, average_precision_score
import logging

warnings.filterwarnings('ignore')

# Add project directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from usb_ml_model import USBMLModel
    from usb_threat_engine import USBThreatEngine
    ML_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Could not import required modules: {e}")
    ML_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ModelEvaluator:
    """
    Comprehensive model evaluation suite for USB anomaly detection
    """
    
    def __init__(self, model_path='/tmp/usb_ml_models', output_dir='/tmp/evaluation_results'):
        self.model_path = model_path
        self.output_dir = output_dir
        self.ml_model = None
        self.threat_engine = None
        self.evaluation_results = {}
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Initialize models if available
        if ML_AVAILABLE:
            try:
                self.ml_model = USBMLModel(model_path=model_path)
                self.threat_engine = USBThreatEngine()
            except Exception as e:
                logger.error(f"Failed to initialize models: {e}")
    
    def generate_evaluation_data(self, num_samples=1000):
        """Generate synthetic evaluation data with known anomalies"""
        logger.info(f"Generating {num_samples} samples for evaluation")
        
        np.random.seed(42)  # For reproducible results
        
        users = ['alice', 'bob', 'charlie', 'diana', 'eve', 'frank', 'grace', 'henry']
        device_types = ['USB_Flash', 'External_HDD', 'USB_SSD', 'Unknown']
        manufacturers = ['SanDisk', 'Kingston', 'Western Digital', 'Seagate', 'Unknown']
        
        data = []
        labels = []  # True labels for evaluation
        
        base_time = datetime.now() - timedelta(days=30)
        
        for i in range(num_samples):
            user = np.random.choice(users)
            device_type = np.random.choice(device_types)
            manufacturer = np.random.choice(manufacturers)
            
            # Determine if this should be an anomaly
            is_anomaly = np.random.random() < 0.15  # 15% anomalies
            
            if is_anomaly:
                # Create anomalous patterns
                anomaly_type = np.random.choice(['large_transfer', 'off_hours', 'weekend', 'unknown_device'])
                
                if anomaly_type == 'large_transfer':
                    bytes_written = np.random.randint(1e9, 10e9)  # 1-10GB
                    hour = np.random.randint(8, 18)
                    day_of_week = np.random.randint(0, 5)
                elif anomaly_type == 'off_hours':
                    bytes_written = np.random.randint(1e6, 500e6)  # 1-500MB
                    hour = np.random.choice([1, 2, 3, 22, 23])
                    day_of_week = np.random.randint(0, 5)
                elif anomaly_type == 'weekend':
                    bytes_written = np.random.randint(100e6, 1e9)  # 100MB-1GB
                    hour = np.random.randint(0, 24)
                    day_of_week = np.random.choice([5, 6])
                else:  # unknown_device
                    bytes_written = np.random.randint(1e6, 100e6)  # 1-100MB
                    hour = np.random.randint(8, 18)
                    day_of_week = np.random.randint(0, 5)
                    device_type = 'Unknown'
                    manufacturer = 'Unknown'
                
                labels.append(1)  # Anomaly
                
            else:
                # Create normal patterns
                bytes_written = np.random.lognormal(15, 1.2)  # Normal distribution
                hour = np.random.choice(range(8, 18))  # Business hours
                day_of_week = np.random.randint(0, 5)  # Weekdays
                labels.append(0)  # Normal
            
            timestamp = base_time + timedelta(hours=i*0.5)
            
            data.append({
                'timestamp': timestamp.isoformat(),
                'user': user,
                'device_id': f'dev_{i % 100}',
                'device_type': device_type,
                'manufacturer': manufacturer,
                'bytes_written': int(bytes_written),
                'session_duration': np.random.randint(60, 3600),
                'hour': hour,
                'day_of_week': day_of_week,
                'is_anomaly': labels[-1]  # Ground truth
            })
        
        df = pd.DataFrame(data)
        logger.info(f"Generated data: {len(df)} samples, {sum(labels)} anomalies ({sum(labels)/len(labels)*100:.1f}%)")
        
        return df
    
    def evaluate_ml_model(self, data):
        """Evaluate the ML model performance"""
        logger.info("Evaluating ML model performance")
        
        if not self.ml_model:
            logger.error("ML model not available")
            return None
        
        try:
            # Load or train model
            if not os.path.exists(f"{self.model_path}/isolation_forest.pkl"):
                logger.info("Training ML model for evaluation")
                processed_data = self.ml_model.extract_features(data.copy())
                self.ml_model.train_models(processed_data, test_size=0.2)
            else:
                logger.info("Loading existing ML model")
                self.ml_model.load_models()
            
            # Prepare data for evaluation
            eval_data = self.ml_model.extract_features(data.copy())
            
            # Get predictions
            results = self.ml_model.predict_anomalies(eval_data)
            
            # Extract ground truth and predictions
            y_true = data['is_anomaly'].values
            y_pred = results['combined_anomaly'].values
            y_scores = -results['anomaly_score'].values  # Convert to positive scores
            
            # Calculate metrics
            metrics = self._calculate_metrics(y_true, y_pred, y_scores)
            
            # Generate plots
            self._generate_ml_plots(y_true, y_pred, y_scores, results)
            
            return metrics
            
        except Exception as e:
            logger.error(f"ML model evaluation failed: {e}")
            return None
    
    def evaluate_threat_engine(self, data):
        """Evaluate the threat detection engine"""
        logger.info("Evaluating threat detection engine")
        
        if not self.threat_engine:
            logger.error("Threat engine not available")
            return None
        
        try:
            # Analyze data with threat engine
            threat_results = []
            
            for _, record in data.iterrows():
                result = self.threat_engine.analyze_activity(record.to_dict())
                threat_results.extend(result)
            
            # Extract predictions
            y_true = data['is_anomaly'].values
            y_pred = [1 if len(result['threats_detected']) > 0 else 0 for result in threat_results]
            y_scores = [result['risk_score'] for result in threat_results]
            
            # Calculate metrics
            metrics = self._calculate_metrics(y_true, y_pred, y_scores)
            
            # Generate plots
            self._generate_threat_plots(y_true, y_pred, y_scores, threat_results)
            
            return metrics
            
        except Exception as e:
            logger.error(f"Threat engine evaluation failed: {e}")
            return None
    
    def _calculate_metrics(self, y_true, y_pred, y_scores):
        """Calculate comprehensive evaluation metrics"""
        from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score
        
        metrics = {
            'accuracy': accuracy_score(y_true, y_pred),
            'precision': precision_score(y_true, y_pred, zero_division=0),
            'recall': recall_score(y_true, y_pred, zero_division=0),
            'f1_score': f1_score(y_true, y_pred, zero_division=0),
            'true_positives': np.sum((y_true == 1) & (y_pred == 1)),
            'false_positives': np.sum((y_true == 0) & (y_pred == 1)),
            'true_negatives': np.sum((y_true == 0) & (y_pred == 0)),
            'false_negatives': np.sum((y_true == 1) & (y_pred == 0))
        }
        
        # Calculate AUC if scores are available
        if len(set(y_scores)) > 1:
            try:
                metrics['auc_roc'] = roc_auc_score(y_true, y_scores)
                metrics['auc_pr'] = average_precision_score(y_true, y_scores)
            except:
                metrics['auc_roc'] = 0.0
                metrics['auc_pr'] = 0.0
        
        return metrics
    
    def _generate_ml_plots(self, y_true, y_pred, y_scores, results):
        """Generate evaluation plots for ML model"""
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        fig.suptitle('ML Model Evaluation Results', fontsize=16)
        
        # Confusion Matrix
        cm = confusion_matrix(y_true, y_pred)
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=axes[0,0])
        axes[0,0].set_title('Confusion Matrix')
        axes[0,0].set_xlabel('Predicted')
        axes[0,0].set_ylabel('Actual')
        
        # ROC Curve
        if len(set(y_scores)) > 1:
            fpr, tpr, _ = roc_curve(y_true, y_scores)
            auc_score = roc_auc_score(y_true, y_scores)
            axes[0,1].plot(fpr, tpr, label=f'ROC (AUC = {auc_score:.3f})')
            axes[0,1].plot([0, 1], [0, 1], 'k--', label='Random')
            axes[0,1].set_xlabel('False Positive Rate')
            axes[0,1].set_ylabel('True Positive Rate')
            axes[0,1].set_title('ROC Curve')
            axes[0,1].legend()
        
        # Precision-Recall Curve
        if len(set(y_scores)) > 1:
            precision, recall, _ = precision_recall_curve(y_true, y_scores)
            ap_score = average_precision_score(y_true, y_scores)
            axes[1,0].plot(recall, precision, label=f'PR (AP = {ap_score:.3f})')
            axes[1,0].set_xlabel('Recall')
            axes[1,0].set_ylabel('Precision')
            axes[1,0].set_title('Precision-Recall Curve')
            axes[1,0].legend()
        
        # Score Distribution
        normal_scores = y_scores[y_true == 0]
        anomaly_scores = y_scores[y_true == 1]
        axes[1,1].hist(normal_scores, bins=20, alpha=0.7, label='Normal', density=True)
        axes[1,1].hist(anomaly_scores, bins=20, alpha=0.7, label='Anomaly', density=True)
        axes[1,1].set_xlabel('Anomaly Score')
        axes[1,1].set_ylabel('Density')
        axes[1,1].set_title('Score Distribution')
        axes[1,1].legend()
        
        plt.tight_layout()
        plt.savefig(f'{self.output_dir}/ml_model_evaluation.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def _generate_threat_plots(self, y_true, y_pred, y_scores, threat_results):
        """Generate evaluation plots for threat engine"""
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        fig.suptitle('Threat Engine Evaluation Results', fontsize=16)
        
        # Confusion Matrix
        cm = confusion_matrix(y_true, y_pred)
        sns.heatmap(cm, annot=True, fmt='d', cmap='Reds', ax=axes[0,0])
        axes[0,0].set_title('Confusion Matrix')
        axes[0,0].set_xlabel('Predicted')
        axes[0,0].set_ylabel('Actual')
        
        # Risk Score Distribution
        risk_levels = [result['risk_level'] for result in threat_results]
        risk_counts = pd.Series(risk_levels).value_counts()
        axes[0,1].bar(risk_counts.index, risk_counts.values)
        axes[0,1].set_title('Risk Level Distribution')
        axes[0,1].set_xlabel('Risk Level')
        axes[0,1].set_ylabel('Count')
        
        # Threat Type Analysis
        threat_types = {}
        for result in threat_results:
            for threat in result['threats_detected']:
                threat_name = threat['name']
                threat_types[threat_name] = threat_types.get(threat_name, 0) + 1
        
        if threat_types:
            axes[1,0].barh(list(threat_types.keys()), list(threat_types.values()))
            axes[1,0].set_title('Detected Threat Types')
            axes[1,0].set_xlabel('Count')
        
            # Risk Score vs Ground Truth
            normal_scores = [y_scores[i] for i in range(len(y_true)) if y_true[i] == 0]
            anomaly_scores = [y_scores[i] for i in range(len(y_true)) if y_true[i] == 1]
            
            axes[1,1].boxplot([normal_scores, anomaly_scores], 
                             labels=['Normal', 'Anomaly'])
            axes[1,1].set_title('Risk Score Distribution by Ground Truth')
            axes[1,1].set_ylabel('Risk Score')
            
            plt.tight_layout()
            plt.savefig(f'{self.output_dir}/threat_engine_evaluation.png', dpi=300, bbox_inches='tight')
            plt.close()
    
    def run_comprehensive_evaluation(self, num_samples=5000):
        """
        Run comprehensive evaluation of both ML model and threat engine
        Returns combined evaluation results
        """
        logger.info("Starting comprehensive evaluation")
        
        # Generate evaluation data
        data = self.generate_evaluation_data(num_samples)
        
        # Evaluate ML model
        ml_metrics = self.evaluate_ml_model(data)
        if ml_metrics:
            self.evaluation_results['ml_model'] = ml_metrics
            logger.info(f"ML Model Metrics: {json.dumps(ml_metrics, indent=2)}")
        
        # Evaluate threat engine
        threat_metrics = self.evaluate_threat_engine(data)
        if threat_metrics:
            self.evaluation_results['threat_engine'] = threat_metrics
            logger.info(f"Threat Engine Metrics: {json.dumps(threat_metrics, indent=2)}")
        
        # Save combined results
        self._save_evaluation_results()
        
        return self.evaluation_results
    
    def _save_evaluation_results(self):
        """Save evaluation results to JSON file"""
        if not self.evaluation_results:
            logger.warning("No evaluation results to save")
            return
        
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{self.output_dir}/evaluation_results_{timestamp}.json"
            
            with open(filename, 'w') as f:
                json.dump(self.evaluation_results, f, indent=2)
            
            logger.info(f"Saved evaluation results to {filename}")
        except Exception as e:
            logger.error(f"Failed to save evaluation results: {e}")
    
    def compare_models(self):
        """
        Compare performance of ML model vs threat engine
        Generates comparison plots and summary statistics
        """
        if not self.evaluation_results:
            logger.warning("No evaluation results to compare. Run evaluation first.")
            return None
        
        try:
            # Extract metrics for comparison
            ml_metrics = self.evaluation_results.get('ml_model', {})
            threat_metrics = self.evaluation_results.get('threat_engine', {})
            
            if not ml_metrics or not threat_metrics:
                logger.warning("Incomplete evaluation results for comparison")
                return None
            
            # Create comparison plot
            fig, ax = plt.subplots(figsize=(10, 6))
            
            metrics_to_compare = ['accuracy', 'precision', 'recall', 'f1_score', 'auc_roc']
            x = np.arange(len(metrics_to_compare))
            width = 0.35
            
            ml_values = [ml_metrics.get(m, 0) for m in metrics_to_compare]
            threat_values = [threat_metrics.get(m, 0) for m in metrics_to_compare]
            
            rects1 = ax.bar(x - width/2, ml_values, width, label='ML Model')
            rects2 = ax.bar(x + width/2, threat_values, width, label='Threat Engine')
            
            ax.set_ylabel('Score')
            ax.set_title('Model Comparison by Evaluation Metric')
            ax.set_xticks(x)
            ax.set_xticklabels(metrics_to_compare)
            ax.legend()
            
            fig.tight_layout()
            plt.savefig(f'{self.output_dir}/model_comparison.png', dpi=300, bbox_inches='tight')
            plt.close()
            
            # Create comparison summary
            comparison = {
                'ml_model': {k: ml_metrics.get(k, 0) for k in metrics_to_compare},
                'threat_engine': {k: threat_metrics.get(k, 0) for k in metrics_to_compare},
                'comparison_timestamp': datetime.now().isoformat()
            }
            
            return comparison
            
        except Exception as e:
            logger.error(f"Model comparison failed: {e}")
            return None

def main():
    """Main execution function for model evaluation"""
    import argparse
    
    parser = argparse.ArgumentParser(description='USB ML Model Evaluation Suite')
    parser.add_argument('--samples', type=int, default=5000,
                       help='Number of samples to generate for evaluation')
    parser.add_argument('--output', type=str, default='/tmp/evaluation_results',
                       help='Output directory for evaluation results')
    parser.add_argument('--compare', action='store_true',
                       help='Run model comparison after evaluation')
    
    args = parser.parse_args()
    
    # Initialize evaluator
    evaluator = ModelEvaluator(output_dir=args.output)
    
    # Run evaluation
    results = evaluator.run_comprehensive_evaluation(num_samples=args.samples)
    
    # Optionally compare models
    if args.compare:
        comparison = evaluator.compare_models()
        if comparison:
            print("\nModel Comparison Results:")
            print("=" * 50)
            print("ML Model Performance:")
            for metric, value in comparison['ml_model'].items():
                print(f"{metric:>12}: {value:.4f}")
            
            print("\nThreat Engine Performance:")
            for metric, value in comparison['threat_engine'].items():
                print(f"{metric:>12}: {value:.4f}")
    
    print("\nEvaluation completed. Results saved to:", args.output)

if __name__ == '__main__':
    main()