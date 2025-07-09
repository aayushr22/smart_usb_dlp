"""
Splunk setup script for USB Security Monitor
"""

import requests
import os
import time
from pathlib import Path
from urllib3.exceptions import InsecureRequestWarning
from getpass import getpass
import urllib.parse

# Disable warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class SplunkSetup:
    def __init__(self):
        self.splunk_host = os.getenv('SPLUNK_HOST', 'localhost')
        self.splunk_mgmt_port = os.getenv('SPLUNK_MGMT_PORT', '8089')
        self.splunk_username = os.getenv('SPLUNK_USERNAME', 'aayushr2201@gmail.com') #my username
        self.splunk_password = os.getenv('SPLUNK_PASSWORD', 'Aayush@22') #my passsword
        self.index_name = os.getenv('SPLUNK_INDEX', 'usb_security')
        
        self.base_url = f"https://{self.splunk_host}:{self.splunk_mgmt_port}"
        self.session = requests.Session()
        self.session.verify = False  # Disable SSL verification
        
        # Set up basic authentication
        self.session.auth = (self.splunk_username, self.splunk_password)
        
    def get_session_key(self):
        """Get Splunk session key for authentication"""
        auth_url = f"{self.base_url}/services/auth/login"
        auth_data = {
            'username': self.splunk_username,
            'password': self.splunk_password
        }
        
        try:
            # Basic auth for the login request
            response = requests.post(auth_url, data=auth_data, verify=False, 
                                   auth=(self.splunk_username, self.splunk_password))
            
            if response.status_code == 200:
                # Extract session key
                import xml.etree.ElementTree as ET
                root = ET.fromstring(response.content)
                session_key_elem = root.find('.//sessionKey')
                if session_key_elem is not None:
                    session_key = session_key_elem.text
                    return session_key
                else:
                    print("Could not find session key in response")
                    print(f"Response: {response.text}")
                    raise Exception("Session key not found in response")
            else:
                print(f"Authentication failed with status: {response.status_code}")
                print(f"Response: {response.text}")
                raise Exception(f"Failed to authenticate: {response.status_code}")
        except Exception as e:
            print(f"Error during authentication: {str(e)}")
            raise

    def create_index(self):
        """Create the USB security index"""
        try:
            session_key = self.get_session_key()
            
            url = f"{self.base_url}/services/data/indexes"
            headers = {
                'Authorization': f'Splunk {session_key}',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            data = {
                'name': self.index_name,
                'maxDataSize': 'auto',
                'maxHotBuckets': 3,
                'maxWarmDBCount': 300
            }
            
            response = requests.post(url, headers=headers, data=data, verify=False)
            
            if response.status_code == 201:
                print(f"Index '{self.index_name}' created successfully")
                return True
            elif response.status_code == 409:
                print(f"Index '{self.index_name}' already exists")
                return True
            else:
                print(f"Failed to create index: {response.status_code}")
                print(f"Response: {response.text}")
                return False
                
        except Exception as e:
            print(f"Error creating index: {str(e)}")
            return False
    
    def create_hec_token(self):
        """Create HTTP Event Collector token"""
        try:
            session_key = self.get_session_key()
            
            url = f"{self.base_url}/services/data/inputs/http"
            headers = {
                'Authorization': f'Splunk {session_key}',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            data = {
                'name': 'usb_security_token',
                'description': 'Token for USB Security Monitor',
                'index': self.index_name,
                'sourcetype': 'usb_security_json',
                'disabled': 0
            }
            
            response = requests.post(url, headers=headers, data=data, verify=False)
            
            if response.status_code == 201:
                print("HEC token created successfully")
                # Extract token 
                import xml.etree.ElementTree as ET
                try:
                    root = ET.fromstring(response.content)
                    token_elem = root.find('.//token') or root.find('.//name')
                    if token_elem is not None:
                        token = token_elem.text
                        print(f"Your HEC token: {token}")
                        print(f"Update your .env file with: SPLUNK_TOKEN={token}")
                        return token
                    else:
                        print("Could not find token in response, using your existing token")
                        print("Using existing HEC token: 2b32ea42-8e5c-4dba-88b5-06998e6b3868")
                        return "2b32ea42-8e5c-4dba-88b5-06998e6b3868"
                except Exception as parse_error:
                    print(f"Could not parse response: {parse_error}")
                    print("Using existing HEC token: 2b32ea42-8e5c-4dba-88b5-06998e6b3868")
                    return "2b32ea42-8e5c-4dba-88b5-06998e6b3868"
            elif response.status_code == 409:
                print("HEC token already exists")
                # using existing token
                print("Using existing HEC token: 2b32ea42-8e5c-4dba-88b5-06998e6b3868")
                return "2b32ea42-8e5c-4dba-88b5-06998e6b3868"
            else:
                print(f"Failed to create HEC token: {response.status_code}")
                print(f"Response: {response.text}")
                return None
                
        except Exception as e:
            print(f"Error creating HEC token: {str(e)}")
            return None
    
    def upload_dashboard(self):
        """Upload USB Security Dashboard"""
        try:
            session_key = self.get_session_key()
            
            dashboard_paths = [
                Path('splunk_app/default/views/usb_security_dashboard.xml'),
                Path('./splunk_app/default/views/usb_security_dashboard.xml'),
                Path('default/views/usb_security_dashboard.xml'),
                Path('./default/views/usb_security_dashboard.xml'),
                Path('views/usb_security_dashboard.xml'),
                Path('./views/usb_security_dashboard.xml'),
                Path('usb_security_dashboard.xml'),
                Path('./usb_security_dashboard.xml')
            ]
            
            dashboard_path = None
            for path in dashboard_paths:
                if path.exists():
                    dashboard_path = path
                    break
            
            if not dashboard_path:
                print("Dashboard XML file not found in any of these locations:")
                for path in dashboard_paths:
                    print(f"  - {path.absolute()}")
                print("Please check the file exists and try again")
                return False
            
            print(f"Found dashboard file at: {dashboard_path}")
            
            with open(dashboard_path, 'r') as f:
                dashboard_xml = f.read()
            
            url = f"{self.base_url}/services/data/ui/views"
            headers = {
                'Authorization': f'Splunk {session_key}',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            data = {
                'name': 'usb_security_dashboard',
                'eai:data': dashboard_xml
            }
            
            response = requests.post(url, headers=headers, data=data, verify=False)
            
            if response.status_code == 201:
                print("Dashboard uploaded successfully")
                return True
            elif response.status_code == 409:
                print("Dashboard already exists")
                return True
            else:
                print(f"Failed to upload dashboard: {response.status_code}")
                print(f"Response: {response.text}")
                return False
                
        except Exception as e:
            print(f"Error uploading dashboard: {str(e)}")
            return False
    
    def setup_saved_searches(self):
        """Create saved searches for alerts"""
        searches = [
            {
                'name': 'USB_High_Threat_Alert',
                'search': f'index={self.index_name} threat_level="HIGH" OR threat_level="CRITICAL"',
                'description': 'Alert on high threat USB devices',
                'cron_schedule': '*/5 * * * *'  # Every 5 minutes
            },
            {
                'name': 'USB_Activity_Report',
                'search': f'index={self.index_name} | stats count by event_type',
                'description': 'Daily USB activity report',
                'cron_schedule': '0 8 * * *'  # Daily at 8 AM
            }
        ]
        
        try:
            session_key = self.get_session_key()
            
            for search_config in searches:
                url = f"{self.base_url}/services/saved/searches"
                headers = {
                    'Authorization': f'Splunk {session_key}',
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
                
                data = {
                    'name': search_config['name'],
                    'search': search_config['search'],
                    'description': search_config['description'],
                    'cron_schedule': search_config['cron_schedule'],
                    'is_scheduled': 1,
                    'actions': 'rss' 
                }
                
                response = requests.post(url, headers=headers, data=data, verify=False)
                
                if response.status_code == 201:
                    print(f"Saved search '{search_config['name']}' created")
                elif response.status_code == 409:
                    print(f"Saved search '{search_config['name']}' already exists")
                else:
                    print(f"Failed to create saved search '{search_config['name']}': {response.status_code}")
                    print(f"Response: {response.text}")
                    
        except Exception as e:
            print(f"Error creating saved searches: {str(e)}")
    
    def run_setup(self):
        """Run complete Splunk setup"""
        print("🚀 Starting Splunk setup for USB Security Monitor...")
        print("=" * 50)
        
        # Test authentication
        print("\n0. Testing authentication...")
        try:
            session_key = self.get_session_key()
            print(f"Authentication successful")
        except Exception as e:
            print(f"Authentication failed: {str(e)}")
            return False
        
        # Create index
        print("\n1. Creating Splunk index...")
        if not self.create_index():
            print("Setup failed at index creation")
            return False
        
        # Create HEC token
        print("\n2. Creating HTTP Event Collector token...")
        token = self.create_hec_token()
        
        # Upload dashboard
        print("\n3. Uploading dashboard...")
        if not self.upload_dashboard():
            print("Dashboard upload failed, continuing...")
        
        # Create saved searches
        print("\n4. Creating saved searches...")
        self.setup_saved_searches()
        
        print("\n" + "=" * 50)
        print("Splunk setup completed!")
        print("\nNext steps:")
        print("1. Enable HTTP Event Collector in Splunk (Settings > Data Inputs > HTTP Event Collector)")
        print("2. Update your .env file with the HEC token")
        print("3. Run your USB monitoring application")
        print("4. Access the dashboard at: http://localhost:8000/en-US/app/search/usb_security_dashboard")
        
        return True

def main():
    """Main setup function"""
    # environment variables loading
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        print("python-dotenv not installed. Using default values.")
    
    setup = SplunkSetup()
    
    try:
        print("Splunk Enterprise Setup for USB Security Monitor")
        print("Make sure Splunk Enterprise is running on localhost:8089")
        input("Press Enter to continue...")
        
        setup.run_setup()
        
    except Exception as e:
        print(f"Setup failed: {str(e)}")
        print("Please check your Splunk configuration and try again.")

if __name__ == "__main__":
    main()