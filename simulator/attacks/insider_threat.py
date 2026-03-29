import pandas as pd
import random
import uuid
import yaml
import os
import glob
from datetime import datetime, timedelta

def load_config():
    """Loads the attack configurations from YAML."""
    with open('configs/attack_configs.yaml', 'r') as f:
        return yaml.safe_load(f)['insider_threat']

def get_latest_normal_log():
    """Finds the most recent normal log CSV file."""
    files = glob.glob('data/normal_logs/*.csv')
    if not files:
        raise FileNotFoundError("No normal log files found.")
    return max(files, key=os.path.getctime)

def generate_insider_threat_events(normal_df, config):
    """
    Simulates an insider threat attack by rapidly accessing files in a different department
    after hours, and possibly performing a large USB transfer.
    """
    events = []
    
    valid_users = normal_df['user_id'].dropna().unique()
    target_user = random.choice(valid_users) if len(valid_users) > 0 else 'johndoe'
    
    hostnames = normal_df[normal_df['user_id'] == target_user]['hostname'].values
    target_host = hostnames[0] if len(hostnames) > 0 else 'WS-UNKNOWN'
    
    sources_ip = normal_df[normal_df['user_id'] == target_user]['source_ip'].values
    target_ip = sources_ip[0] if len(sources_ip) > 0 else '127.0.0.1'
    
    real_dept = random.choice(['Engineering', 'Marketing', 'Sales', 'HR'])
    other_depts = [d for d in ['Engineering', 'Marketing', 'Sales', 'HR', 'Finance'] if d != real_dept]
    target_dept = random.choice(other_depts) if random.random() < config.get('cross_department_probability', 1.0) else real_dept
    
    # Attack timing
    attack_date = datetime.now()
    unusual_hour_start = config.get('unusual_hour_start', 20)
    unusual_hour_end = config.get('unusual_hour_end', 6)
    
    if unusual_hour_start > unusual_hour_end:
        hour = random.choice(list(range(unusual_hour_start, 24)) + list(range(0, unusual_hour_end)))
    else:
        hour = random.randint(unusual_hour_start, unusual_hour_end)
        
    start_time = attack_date.replace(hour=hour, minute=random.randint(0, 50))
    current_time = start_time
    
    num_files = config.get('num_files_accessed', 100)
    interval = (config.get('attack_duration_minutes', 15) * 60) / num_files
    bytes_per_transfer = config.get('bytes_per_transfer', 50000000)
    
    for i in range(num_files):
        events.append({
            'timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S'),
            'event_id': str(uuid.uuid4()),
            'event_type': 'FILE_ACCESS',
            'user_id': target_user,
            'source_ip': target_ip,
            'hostname': target_host,
            'label': 1,
            'attack_type': 'insider_threat',
            'department': real_dept,
            'file_path': f"/{target_dept.lower()}/reports/secret_{i}.pdf",
            'bytes_transferred': bytes_per_transfer + random.randint(-10000, 10000)
        })
        current_time += timedelta(seconds=interval)
        
    # USB connection event mapping bulk transfer
    events.append({
        'timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S'),
        'event_id': str(uuid.uuid4()),
        'event_type': 'USB_CONNECT',
        'user_id': target_user,
        'source_ip': target_ip,
        'hostname': target_host,
        'label': 1,
        'attack_type': 'insider_threat',
        'department': real_dept,
        'device_id': 'USB-SANDISK-128GB'
    })
    
    return events

def main():
    """Main execution block for insider threat attack injection."""
    config = load_config()
    input_csv = get_latest_normal_log()
    
    df_normal = pd.read_csv(input_csv)
    normal_events = df_normal.to_dict('records')
    
    attack_events = generate_insider_threat_events(df_normal, config)
    
    combined = normal_events + attack_events
    random.shuffle(combined)
    
    df_combined = pd.DataFrame(combined)
    
    os.makedirs('data/attack_logs', exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = f"data/attack_logs/insider_threat_logs_{timestamp}.csv"
    
    df_combined.to_csv(out_file, index=False)
    
    total = len(df_combined)
    attack_count = len(attack_events)
    pct = (attack_count / total) * 100
    print(f"Injected {attack_count} insider_threat events into {total - attack_count} normal events ({pct:.2f}% attack rate)")

if __name__ == "__main__":
    main()
