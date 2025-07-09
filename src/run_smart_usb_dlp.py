"""
Smart USB DLP Project Runner
Main execution script for the USB security monitoring system
"""

import os
import sys
import time
import subprocess
import logging
from pathlib import Path
import argparse
import json
from datetime import datetime

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Import modules
try:
    from src.usb.usb_monitor import USBMonitor
    from src.usb.usb_threat_engine import USBThreatEngine
    from src.usb.usb_ml_model import USBMLModel
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Make sure all required modules are in the src/usb/ directory")
    sys.exit(1)

# logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('usb_dlp.log', encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)

class SmartUSBDLPRunner:
    """Main runner class for the Smart USB DLP system"""
    
    def __init__(self, config_file=None):
        self.project_root = project_root
        self.config = self.load_config(config_file)
        self.components = {}
        
        self.data_path = self.config.get('data_path', 'tmp/usb_monitor_data')
        self.log_path = self.config.get('log_path', 'tmp/usb_dlp_logs')
        
        os.makedirs(self.data_path, exist_ok=True)
        os.makedirs(self.log_path, exist_ok=True)
        
        logger.info(f"Smart USB DLP initialized with data path: {self.data_path}")
    
    def load_config(self, config_file):
        """Load configuration from file or use defaults"""
        default_config = {
            'data_path': 'tmp/usb_monitor_data',
            'log_path': 'tmp/usb_dlp_logs',
            'monitor_interval': 30,
            'threat_detection': True,
            'ml_enabled': True,
            'deep_learning_enabled': True,
            'splunk_export': True,
            'alert_threshold': 0.8,
            'max_transfer_size': 1073741824, 
            'allowed_hours': list(range(8, 18)),
            'allowed_days': list(range(0, 5))
        }
        
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    user_config = json.load(f)
                default_config.update(user_config)
                logger.info(f"Configuration loaded from file")
            except Exception as e:
                logger.warning(f"Failed to load config file: {e}. Using defaults.")
        
        return default_config
    
    def initialize_components(self):
        """Initialize all system components"""
        logger.info("Initializing Smart USB DLP components...")
        
        try:
            self.components['monitor'] = USBMonitor(data_path=self.data_path)
            logger.info("USB Monitor initialized successfully")
            
            if self.config['threat_detection']:
                self.components['threat_engine'] = USBThreatEngine()
                logger.info("Threat Engine initialized successfully")
            
            if self.config['ml_enabled']:
                self.components['ml_model'] = USBMLModel()
                logger.info("ML model loaded successfully")
            
            logger.info("All components initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Component initialization failed: {e}")
            return False
    
    def generate_sample_data(self, num_samples=1000):
        """Generate sample data for testing"""
        logger.info(f"Generating {num_samples} sample records...")
        
        try:
            monitor = self.components.get('monitor')
            if monitor:
                df = monitor.generate_sample_data(num_samples)
                logger.info(f"Generated {len(df)} sample records successfully")
                return df
            else:
                logger.error("Monitor component not initialized")
                return None
        except Exception as e:
            logger.error(f"Sample data generation failed: {e}")
            return None
    
    def start_monitoring(self):
        """Start real-time USB monitoring"""
        logger.info("Starting real-time USB monitoring...")
        
        try:
            monitor = self.components.get('monitor')
            if not monitor:
                logger.error("Monitor component not initialized")
                return False
            
            monitor.monitoring_active = True
            logger.info("USB monitoring started successfully")
            
            while monitor.monitoring_active:
                try:
                    events = monitor.get_recent_events(limit=10)
                    
                    if events:
                        self.process_events(events)
                        
                        if self.config['splunk_export']:
                            self.export_to_splunk(events)
                    
                    time.sleep(self.config['monitor_interval'])
                    
                except KeyboardInterrupt:
                    logger.info("Monitoring stopped by user")
                    break
                except Exception as e:
                    logger.error(f"Monitoring error: {e}")
                    time.sleep(5)
            
            return True
            
        except Exception as e:
            logger.error(f"Monitoring startup failed: {e}")
            return False
    
    def process_events(self, events):
        """Process events through threat detection and ML models"""
        try:
            threat_engine = self.components.get('threat_engine')
            ml_model = self.components.get('ml_model')
            dl_model = self.components.get('dl_model')
            
            for event in events:
                if threat_engine:
                    threat_score = threat_engine.analyze_event(event)
                    event['threat_score'] = threat_score
                    
                    if threat_score > self.config['alert_threshold']:
                        self.trigger_alert(event, threat_score)
                
                # ML analysis
                if ml_model:
                    ml_prediction = ml_model.predict_event(event)
                    event['ml_prediction'] = ml_prediction
                
                if dl_model:
                    dl_prediction = dl_model.predict_event(event)
                    event['dl_prediction'] = dl_prediction
                
                self.log_processed_event(event)
                
        except Exception as e:
            logger.error(f"Event processing failed: {e}")
    
    def trigger_alert(self, event, threat_score):
        """Trigger security alert"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'SECURITY_ALERT',
            'threat_score': threat_score,
            'original_event': event,
            'severity': 'HIGH' if threat_score > 0.9 else 'MEDIUM'
        }
        
        # Save
        alert_file = os.path.join(self.log_path, 'security_alerts.json')
        with open(alert_file, 'a') as f:
            f.write(json.dumps(alert) + '\n')
        
        logger.warning(f"SECURITY ALERT: Threat score {threat_score:.2f} for {event.get('device_id', 'unknown')}")
    
    def log_processed_event(self, event):
        """Log processed event to file"""
        try:
            log_file = os.path.join(self.log_path, 'processed_events.json')
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(event) + '\n')
        except Exception as e:
            logger.error(f"Event logging failed: {e}")
    
    def export_to_splunk(self, events):
        """Export events to Splunk format"""
        try:
            monitor = self.components.get('monitor')
            if monitor:
                output_file = monitor.export_to_splunk('json')
                if output_file:
                    logger.debug(f"Exported {len(events)} events to Splunk format")
        except Exception as e:
            logger.error(f"Splunk export failed: {e}")
    
    def run_health_check(self):
        """Run system health check"""
        logger.info("Running system health check...")
        
        health_status = {
            'timestamp': datetime.now().isoformat(),
            'components': {},
            'overall_status': 'HEALTHY'
        }
        
        for name, component in self.components.items():
            try:
                if hasattr(component, 'health_check'):
                    status = component.health_check()
                else:
                    status = 'HEALTHY' if component else 'FAILED'
                
                health_status['components'][name] = status
                
                if status != 'HEALTHY':
                    health_status['overall_status'] = 'DEGRADED'
                    
            except Exception as e:
                health_status['components'][name] = f'ERROR: {e}'
                health_status['overall_status'] = 'DEGRADED'
        
        health_file = os.path.join(self.log_path, 'health_status.json')
        with open(health_file, 'w', encoding='utf-8') as f:
            json.dump(health_status, f, indent=2)
        
        logger.info(f"Health check completed: {health_status['overall_status']}")
        return health_status
    
    def run_batch_analysis(self, data_file):
        """Run batch analysis on existing data"""
        logger.info(f"Running batch analysis on {data_file}")
        
        try:
            import pandas as pd
            
            if data_file.endswith('.csv'):
                df = pd.read_csv(data_file)
            elif data_file.endswith('.json'):
                df = pd.read_json(data_file, lines=True)
            else:
                logger.error("Unsupported file format")
                return False
            
            logger.info(f"Loaded {len(df)} records for analysis")
            
            results = []
            for _, row in df.iterrows():
                event = row.to_dict()
                self.process_events([event])
                results.append(event)
            
            # results
            results_file = os.path.join(self.log_path, f'batch_analysis_results_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json')
            with open(results_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2)
            
            logger.info(f"Batch analysis completed. Results saved to {results_file}")
            return True
            
        except Exception as e:
            logger.error(f"Batch analysis failed: {e}")
            return False
    
    def stop_monitoring(self):
        """Stop monitoring and cleanup"""
        logger.info("Stopping Smart USB DLP system...")
        
        try:
            monitor = self.components.get('monitor')
            if monitor:
                monitor.monitoring_active = False
                monitor.save_events()
            
            logger.info("Smart USB DLP system stopped successfully")
            
        except Exception as e:
            logger.error(f"Shutdown error: {e}")

def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='Smart USB DLP System')
    parser.add_argument('--mode', choices=['monitor', 'generate', 'batch', 'health'], 
                       default='monitor', help='Operation mode')
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--samples', type=int, default=1000,
                       help='Number of samples to generate')
    parser.add_argument('--data-file', help='Data file for batch analysis')
    parser.add_argument('--daemon', action='store_true',
                       help='Run as daemon process')
    
    args = parser.parse_args()
    
    runner = SmartUSBDLPRunner(config_file=args.config)
    
    if not runner.initialize_components():
        logger.error("Failed to initialize components")
        sys.exit(1)
    
    try:
        if args.mode == 'monitor':
            logger.info("Starting Smart USB DLP monitoring system...")
            runner.start_monitoring()
            
        elif args.mode == 'generate':
            # Generate data
            runner.generate_sample_data(args.samples)
            
        elif args.mode == 'batch':
            if not args.data_file:
                logger.error("Data file required for batch mode")
                sys.exit(1)
            runner.run_batch_analysis(args.data_file)
            
        elif args.mode == 'health':
            health_status = runner.run_health_check()
            print(json.dumps(health_status, indent=2))
    
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.error(f"Runtime error: {e}")
        sys.exit(1)
    finally:
        runner.stop_monitoring()

if __name__ == '__main__':
    main()