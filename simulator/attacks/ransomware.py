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
        return yaml.safe_load(f)['ransomware']

def get_latest_normal_log():
    """Finds the most recent normal log CSV file."""
    files = glob.glob('data/normal_logs/*.csv')
    if not files:
        raise FileNotFoundError("No normal log files found.")
    return max(files, key=os.path.getctime)

def generate_ransomware_events(normal_df, config):
    """
    Simulates a ransomware attack by generating rapid FILE_ACCESS and FILE_WRITE events,
    renaming some files with a .locked extension, and starting a malicious process.
    """
    events = []
    
    valid_users = normal_df['user_id'].dropna().unique()
    target_user = random.choice(valid_users) if len(valid_users) > 0 else 'johndoe'
    
    hostnames = normal_df[normal_df['user_id'] == target_user]['hostname'].values
    target_host = hostnames[0] if len(hostnames) > 0 else 'WS-UNKNOWN'
    
    source_ip = normal_df[normal_df['user_id'] == target_user]['source_ip'].values
    target_ip = source_ip[0] if len(source_ip) > 0 else '127.0.0.1'
    
    # Process start
    attack_date = datetime.now()
    current_time = attack_date.replace(hour=random.randint(9, 17), minute=random.randint(0, 50))
    
    events.append({
        'timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S'),
        'event_id': str(uuid.uuid4()),
        'event_type': 'PROCESS_START',
        'user_id': target_user,
        'source_ip': target_ip,
        'hostname': target_host,
        'label': 1,
        'attack_type': 'ransomware',
        'process_name': 'svchost_fake.exe'
    })
    
    current_time += timedelta(seconds=1)
    
    num_files = config.get('num_file_events', 500)
    interval = config.get('burst_duration_seconds', 60) / (num_files * 2)
    exts = config.get('target_extensions', ['.docx', '.pdf'])
    
    for i in range(num_files):
        ext = random.choice(exts)
        filename = f"document_{i}{ext}"
        filepath = f"C:\\Users\\{target_user}\\Documents\\{filename}"
        
        # Access (READ)
        events.append({
            'timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S'),
            'event_id': str(uuid.uuid4()),
            'event_type': 'FILE_ACCESS',
            'user_id': target_user,
            'source_ip': target_ip,
            'hostname': target_host,
            'label': 1,
            'attack_type': 'ransomware',
            'file_path': filepath,
            'bytes_transferred': random.randint(1024, 102400)
        })
        current_time += timedelta(seconds=interval)
        
        # Write / Encrypt
        write_filepath = filepath
        if random.random() < config.get('file_rename_probability', 0.2):
            write_filepath += ".locked"
            
        events.append({
            'timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S'),
            'event_id': str(uuid.uuid4()),
            'event_type': 'FILE_WRITE',
            'user_id': target_user,
            'source_ip': target_ip,
            'hostname': target_host,
            'label': 1,
            'attack_type': 'ransomware',
            'file_path': write_filepath,
            'bytes_transferred': random.randint(1024, 102400)
        })
        current_time += timedelta(seconds=interval)
        
    return events

def main():
    """Main execution block for ransomware attack injection."""
    config = load_config()
    input_csv = get_latest_normal_log()
    
    df_normal = pd.read_csv(input_csv)
    normal_events = df_normal.to_dict('records')
    
    attack_events = generate_ransomware_events(df_normal, config)
    
    combined = normal_events + attack_events
    random.shuffle(combined)
    
    df_combined = pd.DataFrame(combined)
    
    os.makedirs('data/attack_logs', exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = f"data/attack_logs/ransomware_logs_{timestamp}.csv"
    
    df_combined.to_csv(out_file, index=False)
    
    total = len(df_combined)
    attack_count = len(attack_events)
    pct = (attack_count / total) * 100
    print(f"Injected {attack_count} ransomware events into {total - attack_count} normal events ({pct:.2f}% attack rate)")

if __name__ == "__main__":
    main()
