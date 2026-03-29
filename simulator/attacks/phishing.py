import pandas as pd
import random
import uuid
import yaml
import os
import glob
from faker import Faker
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

class PhishingScenario:
    def __init__(self, config, users_df):
        """
        Load attack parameters from configs/attack_configs.yaml.
        Accept the list of users from the normal logs so we can
        pick real usernames, IPs and departments to target.
        """
        self.config = config
        self.users_df = users_df.dropna(subset=['user_id'])
        self.valid_users = self.users_df['user_id'].unique()
        self.fake = Faker()
        
        # Pick our targets
        num_targets = min(self.config.get('num_targets', 3), len(self.valid_users))
        self.targets = random.sample(list(self.valid_users), num_targets) if len(self.valid_users) > 0 else ['johndoe']
        
        # Base timing for the campaign
        today = datetime.now().replace(microsecond=0)
        unusual_hour_start = self.config.get('unusual_hour_start', 0)
        unusual_hour_end = self.config.get('unusual_hour_end', 6)
        
        # Start time of the entire scenario
        self.campaign_start = today.replace(
            hour=random.randint(unusual_hour_start, unusual_hour_end - 1),
            minute=random.randint(0, 30),
            second=random.randint(0, 59)
        )
        
        # Variables to track state between stages
        self.attacker_ips = [self.fake.ipv4_public() for _ in range(num_targets)]
        self.recon_end_time = self.campaign_start
        self.harvest_end_time = self.campaign_start
        self.takeover_end_time = self.campaign_start
        self.lateral_end_time = self.campaign_start
        
        self.compromised_accounts = []
        
        # Extracted sets for random lateral movement
        self.all_hostnames = self.users_df['hostname'].unique()

        self.stats = {
            'recon': 0, 'harvest': 0, 'takeover': 0, 'lateral': 0, 'cleanup': 0
        }
        
    def _get_user_info(self, user_id):
        user_rows = self.users_df[self.users_df['user_id'] == user_id]
        if len(user_rows) == 0:
            return 'WS-UNKNOWN', 'Unknown', 'Engineering'
            
        host = user_rows['hostname'].values[0]
        ip = user_rows['source_ip'].values[0]
        dept = user_rows['department'].values[0] if 'department' in user_rows.columns else 'Engineering'
        return host, ip, dept

    def run(self, normal_events):
        """
        Execute all 5 stages in order.
        Return the full list of attack events across all stages.
        """
        events = []
        events += self.generate_recon_events()
        events += self.generate_credential_harvest()
        events += self.generate_account_takeover()
        events += self.generate_lateral_movement()
        events += self.generate_cleanup()
        return events

    def generate_recon_events(self):
        """Stage 1: Attacker maps internal domains via DNS."""
        events = []
        num_recon = self.config.get('recon_events', 5)
        recon_duration = self.config.get('recon_duration_minutes', 30)
        
        current_time = self.campaign_start
        interval_seconds = (recon_duration * 60) / max(num_recon, 1)
        recon_ip = self.fake.ipv4_public()
        
        for _ in range(num_recon):
            target_host = random.choice(self.all_hostnames) if len(self.all_hostnames) > 0 else 'WS-TARGET'
            events.append({
                'timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S'),
                'event_id': str(uuid.uuid4()),
                'event_type': 'DNS_LOOKUP',
                'user_id': '-',
                'source_ip': recon_ip,
                'hostname': target_host,
                'department': '-',
                'label': 1,
                'attack_type': 'phishing'
            })
            current_time += timedelta(seconds=interval_seconds + random.randint(-10, 10))
            
        self.recon_end_time = current_time
        self.stats['recon'] = len(events)
        return events

    def generate_credential_harvest(self):
        """Stage 2: Target users receive phishing links and attacker brute forces or harvests."""
        events = []
        
        num_fails = self.config.get('num_failed_logins', 10)
        duration_mins = self.config.get('attack_duration_minutes', 30)
        
        # Starts near the end of recon
        stage_start = self.recon_end_time + timedelta(minutes=random.randint(1, 5))
        
        # Harvesting might be concurrent across targets
        global_max_time = stage_start
        
        for i, target in enumerate(self.targets):
            host, _, dept = self._get_user_info(target)
            attacker_ip = self.attacker_ips[i]
            
            # offset each user's harvest window slightly
            current_time = stage_start + timedelta(minutes=random.randint(0, duration_mins))
            interval = (5 * 60) / max(num_fails, 1) # tight 5 minute window for the brute force
            
            for _ in range(random.randint(max(5, num_fails-2), num_fails+2)):
                events.append({
                    'timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'event_id': str(uuid.uuid4()),
                    'event_type': 'AUTH_FAIL',
                    'user_id': target,
                    'source_ip': attacker_ip,
                    'hostname': host,
                    'department': dept,
                    'label': 1,
                    'attack_type': 'phishing',
                    'success': 0,
                    'location': 'Russia'
                })
                current_time += timedelta(seconds=interval + random.randint(-5, 5))
                
            # ONE successful login at the end
            events.append({
                'timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S'),
                'event_id': str(uuid.uuid4()),
                'event_type': 'LOGIN',
                'user_id': target,
                'source_ip': attacker_ip,
                'hostname': host,
                'department': dept,
                'label': 1,
                'attack_type': 'phishing',
                'success': 1,
                'location': 'Russia'
            })
            
            # Record compromise state for next stages
            self.compromised_accounts.append({
                'user': target,
                'host': host,
                'dept': dept,
                'ip': attacker_ip,
                'time': current_time
            })
            
            if current_time > global_max_time:
                global_max_time = current_time
                
        self.harvest_end_time = global_max_time
        self.stats['harvest'] = len(events)
        return events

    def generate_account_takeover(self):
        """Stage 3: Attacker accesses systems off-limits to user, and resets passwords."""
        events = []
        takeover_duration = self.config.get('takeover_duration_minutes', 20)
        
        all_depts = ['Engineering', 'Marketing', 'Sales', 'HR', 'Finance']
        global_max_time = self.harvest_end_time
        
        for account in self.compromised_accounts:
            current_time = account['time'] + timedelta(minutes=random.randint(1, takeover_duration))
            
            other_depts = [d for d in all_depts if d != account['dept']]
            target_dept = random.choice(other_depts) if other_depts else 'Finance'
            
            # File access across departments
            num_files = random.randint(2, 4)
            for _ in range(num_files):
                events.append({
                    'timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'event_id': str(uuid.uuid4()),
                    'event_type': 'FILE_ACCESS',
                    'user_id': account['user'],
                    'source_ip': account['ip'],
                    'hostname': account['host'],
                    'department': account['dept'],
                    'label': 1,
                    'attack_type': 'phishing',
                    'file_path': f"/{target_dept.lower()}/confidential_{random.randint(1, 99)}.pdf",
                    'bytes_transferred': random.randint(500000, 5000000)
                })
                current_time += timedelta(minutes=random.randint(1, 3))
                
            # Password reset
            events.append({
                'timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S'),
                'event_id': str(uuid.uuid4()),
                'event_type': 'PASSWORD_RESET',
                'user_id': account['user'],
                'source_ip': account['ip'],
                'hostname': account['host'],
                'department': account['dept'],
                'label': 1,
                'attack_type': 'phishing',
                'success': 1,
                'location': 'Russia'
            })
            
            # update tracking time
            account['time'] = current_time
            if current_time > global_max_time:
                global_max_time = current_time
                
        self.takeover_end_time = global_max_time
        self.stats['takeover'] = len(events)
        return events

    def generate_lateral_movement(self):
        """Stage 4: Attacker pivots to other machines using compromised user."""
        events = []
        lateral_attempts = self.config.get('lateral_attempts', 4)
        global_max_time = self.takeover_end_time
        
        for account in self.compromised_accounts:
            current_time = account['time'] + timedelta(minutes=random.randint(5, 15))
            
            attempts = random.randint(max(1, lateral_attempts - 2), lateral_attempts + 2)
            
            for _ in range(attempts):
                target_host = random.choice(self.all_hostnames) if len(self.all_hostnames) > 0 else 'WS-LATERAL'
                success = random.choice([0, 0, 1]) # more fails than successes
                event_type = 'LOGIN' if success else 'AUTH_FAIL'
                
                events.append({
                    'timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'event_id': str(uuid.uuid4()),
                    'event_type': event_type,
                    'user_id': account['user'],
                    'source_ip': account['ip'], # Same attacker IP
                    'hostname': target_host,    # DIFFERENT host
                    'department': account['dept'],
                    'label': 1,
                    'attack_type': 'phishing',
                    'success': success,
                    'location': 'Russia'
                })
                current_time += timedelta(minutes=random.randint(1, 5))
                
            account['time'] = current_time
            if current_time > global_max_time:
                global_max_time = current_time

        self.lateral_end_time = global_max_time
        self.stats['lateral'] = len(events)
        return events

    def generate_cleanup(self):
        """Stage 5: Implants backdoors and connects to C2 infrastructure."""
        events = []
        suspicious_procs = self.config.get('suspicious_processes', ["svchost32.exe"])
        c2_ports = self.config.get('c2_ports', [4444])
        
        global_max_time = self.lateral_end_time
        
        for account in self.compromised_accounts:
            current_time = account['time'] + timedelta(minutes=random.randint(5, 20))
            
            # Spawn persistent backdoor
            num_procs = random.randint(1, 3)
            for _ in range(num_procs):
                events.append({
                    'timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'event_id': str(uuid.uuid4()),
                    'event_type': 'PROCESS_START',
                    'user_id': account['user'],
                    'source_ip': account['ip'],
                    'hostname': account['host'],
                    'department': account['dept'],
                    'label': 1,
                    'attack_type': 'phishing',
                    'process_name': random.choice(suspicious_procs),
                    'file_path': random.choice(['C:\\Temp\\', 'C:\\Users\\Public\\']) + random.choice(suspicious_procs)
                })
                current_time += timedelta(seconds=random.randint(10, 60))
                
            # Connect out to C2
            num_net = random.randint(1, 2)
            for _ in range(num_net):
                events.append({
                    'timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'event_id': str(uuid.uuid4()),
                    'event_type': 'NETWORK_CONNECTION',
                    'user_id': account['user'],
                    'source_ip': account['ip'],
                    'hostname': account['host'],
                    'department': account['dept'],
                    'label': 1,
                    'attack_type': 'phishing',
                    'destination_ip': self.fake.ipv4_public(),
                    'destination_port': random.choice(c2_ports)
                })
                current_time += timedelta(minutes=random.randint(1, 5))
                
            if current_time > global_max_time:
                global_max_time = current_time
                
        self.stats['cleanup'] = len(events)
        return events

def main():
    """Main execution block for full phishing scenario injection."""
    config = load_config()
    input_csv = get_latest_normal_log()
    
    df_normal = pd.read_csv(input_csv)
    normal_events = df_normal.to_dict('records')
    
    scenario = PhishingScenario(config, df_normal)
    attack_events = scenario.run(df_normal)
    
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
    
    print("\n[Phishing Scenario]")
    print(f"  Stage 1 Recon:              {scenario.stats['recon']} events")
    print(f"  Stage 2 Credential harvest: {scenario.stats['harvest']} events  (targeting {len(scenario.targets)} users)")
    print(f"  Stage 3 Account takeover:   {scenario.stats['takeover']} events")
    print(f"  Stage 4 Lateral movement:   {scenario.stats['lateral']} events")
    print(f"  Stage 5 Cleanup:            {scenario.stats['cleanup']} events")
    print("  " + "─"*37)
    print(f"  Total injected:             {attack_count} events into {total - attack_count} normal ({pct:.2f}% rate)\n")

if __name__ == "__main__":
    main()
