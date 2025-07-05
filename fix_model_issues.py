# Run this script to fix the main issues

import re

def fix_numpy_overflow():
    """Fix numpy int32 overflow in test files"""
    files_to_fix = [
        'bin/model_evaluation.py',
        'bin/test_usb_model.py'
    ]
    
    for file_path in files_to_fix:
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Fix the overflow issue
            content = re.sub(
                r'np\.random\.randint\(1e9, 10e9\)',
                'np.random.randint(1000000000, 2000000000)',
                content
            )
            content = re.sub(
                r'np\.random\.randint\(1e9, 5e9\)',
                'np.random.randint(1000000000, 2000000000)',
                content
            )
            
            with open(file_path, 'w') as f:
                f.write(content)
            
            print(f"Fixed {file_path}")
            
        except FileNotFoundError:
            print(f"File not found: {file_path}")
        except Exception as e:
            print(f"Error fixing {file_path}: {e}")

def add_missing_method():
    """Add the missing get_model_stats method"""
    method_code = '''
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
'''
    
    try:
        with open('bin/usb_ml_model.py', 'r') as f:
            content = f.read()
        
        # Add the method before the last line of the class
        if 'def get_model_stats(self):' not in content:
            # Find the end of the class and add the method
            content = content.rstrip() + method_code + '\n'
            
            with open('bin/usb_ml_model.py', 'w') as f:
                f.write(content)
            
            print("Added get_model_stats method")
        else:
            print("get_model_stats method already exists")
            
    except Exception as e:
        print(f"Error adding method: {e}")

if __name__ == "__main__":
    print("Fixing model issues...")
    fix_numpy_overflow()
    add_missing_method()
    print("Done! Now run the tests again.")