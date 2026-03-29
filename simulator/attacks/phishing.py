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
        return yaml.safe_load(f)['phishing']

def get_latest_normal_log():
    """Finds the most recent normal log CSV file."""
    files = glob.glob('data/normal_logs/*.csv')
    if not files:
        raise FileNotFoundError("No normal log files found in data/normal_logs/")
    return max(files, key=os.path.getctime)

def generate_phishing_events(normal_df, config):
    """
    Simulates a phishing attack by generating failed logins,
    one successful login from a new location, and a password reset.
    """
    events = []
    
    # Select a random user from existing logs
    valid_users = normal_df['user_id'].dropna().unique()
    target_user = random.choice(valid_users) if len(valid_users) > 0 else 'johndoe'
    
    hostnames = normal_df[normal_df['user_id'] == target_user]['hostname'].values
    target_host = hostnames[0] if len(hostnames) > 0 else 'WS-UNKNOWN'
    
    # Attack timing
    attack_date = datetime.now()
    unusual_hour = random.randint(
        config.get('unusual_hour_start', 2), 
        config.get('unusual_hour_end', 5)
    )
    start_time = attack_date.replace(hour=unusual_hour, minute=random.randint(0, 50), second=random.randint(0, 59))
    
    # Failed logins
    num_failures = config.get('num_failed_logins', 10)
    interval = (config.get('attack_duration_minutes', 5) * 60) / (num_failures + 2)
    attacker_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
    
    current_time = start_time
    for _ in range(num_failures):
        events.append({
            'timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S'),
            'event_id': str(uuid.uuid4()),
            'event_type': 'AUTH_FAIL',
            'user_id': target_user,
            'source_ip': attacker_ip,
            'hostname': target_host,
            'label': 1,
            'attack_type': 'phishing',
            'success': 0,
            'location': 'Unknown'
        })
        current_time += timedelta(seconds=interval)
        
    # Successful login
    new_location = 'Russia' if random.random() < config.get('new_location_probability', 1.0) else 'Unknown'
    events.append({
        'timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S'),
        'event_id': str(uuid.uuid4()),
        'event_type': 'LOGIN',
        'user_id': target_user,
        'source_ip': attacker_ip,
        'hostname': target_host,
        'label': 1,
        'attack_type': 'phishing',
        'success': 1,
        'location': new_location
    })
    
    # Password reset
    current_time += timedelta(seconds=15)
    events.append({
        'timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S'),
        'event_id': str(uuid.uuid4()),
        'event_type': 'PASSWORD_RESET',
        'user_id': target_user,
        'source_ip': attacker_ip,
        'hostname': target_host,
        'label': 1,
        'attack_type': 'phishing',
        'success': 1,
        'location': new_location
    })
    
    return events

def main():
    """Main execution block for phishing attack injection."""
    config = load_config()
    input_csv = get_latest_normal_log()
    
    df_normal = pd.read_csv(input_csv)
    normal_events = df_normal.to_dict('records')
    
    attack_events = generate_phishing_events(df_normal, config)
    
    combined = normal_events + attack_events
    random.shuffle(combined)
    
    df_combined = pd.DataFrame(combined)
    
    os.makedirs('data/attack_logs', exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = f"data/attack_logs/phishing_logs_{timestamp}.csv"
    
    df_combined.to_csv(out_file, index=False)
    
    total = len(df_combined)
    attack_count = len(attack_events)
    pct = (attack_count / total) * 100
    print(f"Injected {attack_count} phishing events into {total - attack_count} normal events ({pct:.2f}% attack rate)")

if __name__ == "__main__":
    main()
