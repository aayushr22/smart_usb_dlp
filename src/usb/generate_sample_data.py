"""
Smart USB DLP System - Sample Data Generator
Generates realistic USB activity data for testing and demonstration purposes
"""

import csv
import random
import datetime
from pathlib import Path
import os

# Configuration
DAYS_TO_GENERATE = 30
USERS = ['rajesh.sharma', 'priya.patel', 'arjun.singh', 'kavya.reddy', 'amit.kumar', 
         'sneha.agarwal', 'rohit.gupta', 'ananya.nair', 'vikram.joshi', 'ravi.mehta']

DEVICE_TYPES = ['USB_Flash_Drive', 'External_HDD', 'USB_SSD', 'SD_Card', 'Portable_Drive']

DEVICE_MANUFACTURERS = ['SanDisk', 'Kingston', 'Samsung', 'Western_Digital', 'Seagate', 'Lexar', 'PNY']

NORMAL_PATTERNS = {
    'USB_Flash_Drive': {'min': 1048576, 'max': 104857600},      # 1MB - 100MB
    'External_HDD': {'min': 104857600, 'max': 2147483648},      # 100MB - 2GB
    'USB_SSD': {'min': 52428800, 'max': 1073741824},            # 50MB - 1GB
    'SD_Card': {'min': 1048576, 'max': 209715200},              # 1MB - 200MB
    'Portable_Drive': {'min': 209715200, 'max': 3221225472}     # 200MB - 3GB
}

# File types 
FILE_TYPES = ['documents', 'images', 'videos', 'software', 'data', 'backup', 'mixed']

# Working hours
WORKING_HOURS = list(range(8, 18))  # 8 AM to 6 PM
OFF_HOURS = list(range(0, 8)) + list(range(18, 24))

def generate_device_id(device_type, manufacturer):
    """Generate realistic device ID"""
    serial = ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=8))
    return f"{manufacturer}_{device_type}_{serial}"

def generate_realistic_bytes(device_type, is_anomaly=False, anomaly_type='normal'):
    """Generate realistic byte counts based on device type and anomaly flags"""
    base_range = NORMAL_PATTERNS[device_type]
    
    if not is_anomaly:
        return random.randint(base_range['min'], base_range['max'])
    else:
        if anomaly_type == 'high_volume':
            return random.randint(base_range['max'] * 2, base_range['max'] * 10)
        elif anomaly_type == 'frequent_small':
            return random.randint(base_range['min'] // 10, base_range['min'])
        else:
            return random.randint(base_range['max'], base_range['max'] * 2)

def get_user_behavior_profile(user):
    """Assign behavior profiles to users for realistic patterns"""
    profiles = {
        'rajesh.sharma': 'heavy',
        'priya.patel': 'normal',
        'arjun.singh': 'light',
        'kavya.reddy': 'suspicious',
        'amit.kumar': 'normal',
        'sneha.agarwal': 'heavy',
        'rohit.gupta': 'light',
        'ananya.nair': 'normal',
        'vikram.joshi': 'normal',
        'ravi.mehta': 'suspicious'
    }
    return profiles.get(user, 'normal')

def generate_session_duration(bytes_written):
    """Generate realistic session duration based on data size"""
    base_duration = bytes_written / (50 * 1048576)
    multiplier = random.uniform(0.2, 2.0)
    return max(1, int(base_duration * multiplier))

def should_generate_anomaly(user, hour, day_of_week):
    """Determine if this event should be an anomaly based on user profile and context"""
    profile = get_user_behavior_profile(user)
    anomaly_rates = {
        'normal': 0.02,      
        'light': 0.01, 
        'heavy': 0.03,       
        'suspicious': 0.15   
    }
    
    base_rate = anomaly_rates.get(profile, 0.02)
    
    if hour in OFF_HOURS:
        base_rate *= 3
    
    if day_of_week in [0, 6]:
        base_rate *= 2
    
    return random.random() < base_rate

def generate_source_ip():
    """Generate realistic internal IP addresses"""
    return f"192.168.{random.randint(1, 10)}.{random.randint(10, 200)}"

def generate_usb_activity_data():
    """Generate comprehensive USB activity dataset"""
    
    # Create output
    output_dir = Path(__file__).parent.parent / 'lookups'
    output_dir.mkdir(exist_ok=True)
    
    data = []
    device_registry = {} 
    
    # Generate data
    for day_offset in range(DAYS_TO_GENERATE):
        current_date = datetime.datetime.now() - datetime.timedelta(days=day_offset)
        daily_events = random.randint(50, 200)
        
        for _ in range(daily_events):
            # Select random user
            user = random.choice(USERS)
            
            if random.random() < 0.7: 
                hour = random.choice(WORKING_HOURS)
            else:
                hour = random.choice(OFF_HOURS)
            
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            
            timestamp = current_date.replace(hour=hour, minute=minute, second=second)
            day_of_week = timestamp.weekday()

            if user not in device_registry:
                device_registry[user] = []
            
            if len(device_registry[user]) == 0 or random.random() < 0.3:
                device_type = random.choice(DEVICE_TYPES)
                manufacturer = random.choice(DEVICE_MANUFACTURERS)
                device_id = generate_device_id(device_type, manufacturer)
                device_registry[user].append({
                    'device_id': device_id,
                    'device_type': device_type,
                    'manufacturer': manufacturer
                })
            
            device_info = random.choice(device_registry[user])
            
            is_anomaly = should_generate_anomaly(user, hour, day_of_week)
            
            anomaly_type = 'normal'
            if is_anomaly:
                anomaly_type = random.choices(
                    ['high_volume', 'frequent_small', 'moderate'],
                    weights=[40, 30, 30]
                )[0]
            
            bytes_written = generate_realistic_bytes(
                device_info['device_type'], 
                is_anomaly, 
                anomaly_type
            )
            
            session_duration = generate_session_duration(bytes_written)
            file_types = random.choice(FILE_TYPES)
            src_ip = generate_source_ip()
            action = random.choices(['write', 'read'], weights=[80, 20])[0]  # 80% writes
            result = random.choices(['success', 'failure'], weights=[95, 5])[0]  # 95% success
            
            # Create record
            record = {
                'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'user': user,
                'device_id': device_info['device_id'],
                'device_type': device_info['device_type'],
                'manufacturer': device_info['manufacturer'],
                'bytes_written': bytes_written,
                'session_duration': session_duration,
                'file_types': file_types,
                'src_ip': src_ip,
                'action': action,
                'result': result,
                'hour': hour,
                'day_of_week': day_of_week,
                'is_anomaly': 1 if is_anomaly else 0,
                'anomaly_type': anomaly_type if is_anomaly else 'normal'
            }
            
            data.append(record)
    
    # Sort
    data.sort(key=lambda x: x['timestamp'])
    
    output_file = output_dir / 'usb_activity_sample.csv'
    
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = [
            'timestamp', 'user', 'device_id', 'device_type', 'manufacturer',
            'bytes_written', 'session_duration', 'file_types', 'src_ip',
            'action', 'result', 'hour', 'day_of_week', 'is_anomaly', 'anomaly_type'
        ]
        
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)
    
    print(f"\nGenerated {len(data)} USB activity records")
    print(f" Output file: {output_file}")
    
    # summary statistics
    total_anomalies = sum(1 for record in data if record['is_anomaly'] == 1)
    anomaly_rate = (total_anomalies / len(data)) * 100
    
    print(f"\n Dataset Summary:")
    print(f"   • Total Records: {len(data):,}")
    print(f"   • Date Range: {data[0]['timestamp']} to {data[-1]['timestamp']}")
    print(f"   • Total Anomalies: {total_anomalies:,} ({anomaly_rate:.1f}%)")
    print(f"   • Unique Users: {len(set(record['user'] for record in data))}")
    print(f"   • Unique Devices: {len(set(record['device_id'] for record in data))}")
    
    # User-wise
    print(f"\n User Anomaly Breakdown:")
    user_stats = {}
    for record in data:
        user = record['user']
        if user not in user_stats:
            user_stats[user] = {'total': 0, 'anomalies': 0}
        user_stats[user]['total'] += 1
        if record['is_anomaly'] == 1:
            user_stats[user]['anomalies'] += 1
    
    for user, stats in sorted(user_stats.items()):
        anomaly_pct = (stats['anomalies'] / stats['total']) * 100
        profile = get_user_behavior_profile(user)
        print(f"   • {user:<20} | {stats['anomalies']:>3} anomalies ({anomaly_pct:>5.1f}%) | Profile: {profile}")

def generate_device_lookup():
    """Generate device type lookup table"""
    output_dir = Path(__file__).parent.parent / 'lookups'
    output_dir.mkdir(exist_ok=True)
    
    device_data = []
    for device_type in DEVICE_TYPES:
        for manufacturer in DEVICE_MANUFACTURERS:
            capacity_ranges = {
                'USB_Flash_Drive': ['8GB', '16GB', '32GB', '64GB', '128GB'],
                'External_HDD': ['500GB', '1TB', '2TB', '4TB', '8TB'],
                'USB_SSD': ['120GB', '240GB', '480GB', '1TB', '2TB'],
                'SD_Card': ['16GB', '32GB', '64GB', '128GB', '256GB'],
                'Portable_Drive': ['1TB', '2TB', '4TB', '5TB', '8TB']
            }
            
            for capacity in capacity_ranges[device_type]:
                device_data.append({
                    'device_type': device_type,
                    'manufacturer': manufacturer,
                    'typical_capacity': capacity,
                    'risk_level': random.choice(['Low', 'Medium', 'High']),
                    'common_use': random.choice(['Business', 'Personal', 'Backup', 'Transfer'])
                })
    
    output_file = output_dir / 'usb_device_types.csv'
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['device_type', 'manufacturer', 'typical_capacity', 'risk_level', 'common_use']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(device_data)
    
    print(f"Generated device lookup table: {output_file}")

if __name__ == "__main__":
    print("Smart USB DLP - Sample Data Generator")
    print("=" * 50)
    
    try:
        generate_usb_activity_data()
        generate_device_lookup()
        
        print(f"\n Sample data generation completed successfully!")
        print(f"\n Next steps:")
        print(f"   1. Copy the generated CSV files to your Splunk instance")
        print(f"   2. Index the data using the provided SPL commands in README")
        print(f"   3. Run the ML model training search")
        print(f"   4. Test anomaly detection")
        
    except Exception as e:
        print(f"Error generating sample data: {str(e)}")
        raise