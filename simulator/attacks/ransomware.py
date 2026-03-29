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
        return yaml.safe_load(f)['ransomware']

def get_latest_normal_log():
    """Finds the most recent normal log CSV file."""
    files = glob.glob('data/normal_logs/*.csv')
    if not files:
        raise FileNotFoundError("No normal log files found.")
    return max(files, key=os.path.getctime)

class RansomwareScenario:
    def __init__(self, config, users_df):
        """
        Load parameters from configs/attack_configs.yaml.
        Pick one victim user and machine to be the infection point.
        """
        self.config = config
        self.users_df = users_df.dropna(subset=['user_id'])
        self.valid_users = self.users_df['user_id'].unique()
        self.fake = Faker()
        
        # Pick our victim
        self.victim = random.choice(list(self.valid_users)) if len(self.valid_users) > 0 else 'johndoe'
        user_rows = self.users_df[self.users_df['user_id'] == self.victim]
        self.victim_host = user_rows['hostname'].values[0] if len(user_rows) > 0 else 'WS-UNKNOWN'
        self.victim_ip = user_rows['source_ip'].values[0] if len(user_rows) > 0 else '127.0.0.1'
        self.victim_dept = user_rows['department'].values[0] if len(user_rows) > 0 and 'department' in user_rows.columns else 'Engineering'
        
        # Attack timing (random hour)
        today = datetime.now().replace(microsecond=0)
        self.attack_start = today.replace(
            hour=random.randint(0, 23),
            minute=random.randint(0, 50),
            second=random.randint(0, 59)
        )
        
        # Time trackers
        self.discovery_time_end = self.attack_start
        self.encryption_time_end = self.attack_start
        
        # Shared context
        self.discovered_files = []
        self.all_hostnames = self.users_df['hostname'].unique()
        
        self.stats = {
            'delivery': 0, 'discovery': 0, 'encryption': 0, 'impact': 0
        }

    def _build_event(self, **kwargs):
        """Helper to ensure a consistent schema for all ransomware events (Bug A)."""
        return {
            'timestamp': kwargs.get('timestamp', ''),
            'event_id': kwargs.get('event_id', str(uuid.uuid4())),
            'event_type': kwargs.get('event_type', ''),
            'user_id': self.victim,
            'source_ip': self.victim_ip,
            'hostname': self.victim_host,
            'department': self.victim_dept,
            'label': 1,
            'attack_type': 'ransomware',
            'file_path': kwargs.get('file_path', ''),
            'bytes_transferred': kwargs.get('bytes_transferred', ''),
            'process_name': kwargs.get('process_name', ''),
            'dest_ip': kwargs.get('dest_ip', ''),
            'dest_port': kwargs.get('dest_port', '')
        }

    def run(self, normal_events):
        """
        Execute all 4 stages in order.
        Return full list of attack events.
        """
        events = []
        events += self.generate_delivery()
        events += self.generate_discovery()
        events += self.generate_encryption()
        events += self.generate_impact()
        return events

    def generate_delivery(self):
        """Stage 1: Delivery
        Malware payload arrives and initiates execution.
        """
        events = []
        current_time = self.attack_start
        
        # Payload download
        events.append(self._build_event(
            timestamp=current_time.strftime('%Y-%m-%d %H:%M:%S'),
            event_type='NETWORK_CONNECTION',
            dest_ip=self.fake.ipv4_public(),
            dest_port=random.choice([80, 443]),
            bytes_transferred=random.randint(50000, 2000000)
        ))
        
        current_time += timedelta(seconds=random.randint(2, 10))
        
        # Execution - Correct key: 'delivery_processes' (Bug B)
        procs = self.config.get('delivery_processes', ["update.exe", "installer.tmp", "flash_update.exe", "java_patch.exe"])
        proc_name = random.choice(procs)
        path = random.choice(['C:\\Users\\Public\\', 'C:\\Temp\\']) + proc_name
        
        events.append(self._build_event(
            timestamp=current_time.strftime('%Y-%m-%d %H:%M:%S'),
            event_type='PROCESS_START',
            process_name=proc_name,
            file_path=path
        ))
        
        self.discovery_time_end = current_time # stage end base
        self.stats['delivery'] = len(events)
        return events

    def generate_discovery(self):
        """Stage 2: Discovery
        Silently scan for files prior to encryption.
        """
        events = []
        current_time = self.discovery_time_end + timedelta(seconds=random.randint(5, 15))
        
        min_files = self.config.get('discovery_min_files', 50)
        max_files = self.config.get('discovery_max_files', 150)
        num_files = random.randint(min_files, max_files)
        
        window_secs = self.config.get('discovery_window_seconds', 90)
        interval = window_secs / max(num_files, 1)
        
        exts = self.config.get('target_extensions', ['.docx', '.xlsx', '.pdf', '.jpg', '.py', '.csv', '.db'])
        depts = ['Engineering', 'Marketing', 'Sales', 'HR', 'Finance', 'Legal']
        
        for i in range(num_files):
            dept = random.choice(depts)
            ext = random.choice(exts)
            
            filepath = f"/{dept.lower()}/shared/file_{i}_{random.randint(100, 999)}{ext}"
            self.discovered_files.append(filepath)
            
            events.append(self._build_event(
                timestamp=current_time.strftime('%Y-%m-%d %H:%M:%S'),
                event_type='FILE_ACCESS',
                file_path=filepath,
                bytes_transferred=random.randint(1024, 10240)
            ))
            current_time += timedelta(seconds=interval + random.uniform(-0.1, 0.1))
            
        self.encryption_time_end = current_time
        self.stats['discovery'] = len(events)
        return events

    def generate_encryption(self):
        """Stage 3: Encryption
        Encrypt all discovered files extremely quickly. 
        """
        events = []
        current_time = self.encryption_time_end + timedelta(seconds=random.randint(2, 5))
        
        window_secs = self.config.get('encryption_window_seconds', 120)
        # 1 read + 1 write per file
        events_to_generate = len(self.discovered_files) * 2
        interval = window_secs / max(events_to_generate, 1)
        
        for filepath in self.discovered_files:
            file_size = random.randint(10240, 50000000)
            
            # Read original
            events.append(self._build_event(
                timestamp=current_time.strftime('%Y-%m-%d %H:%M:%S'),
                event_type='FILE_ACCESS',
                file_path=filepath,
                bytes_transferred=file_size
            ))
            current_time += timedelta(seconds=interval + random.uniform(-0.05, 0.05))
            
            # Write locked
            events.append(self._build_event(
                timestamp=current_time.strftime('%Y-%m-%d %H:%M:%S'),
                event_type='FILE_WRITE',
                file_path=filepath + ".locked",
                bytes_transferred=file_size + random.randint(16, 64)
            ))
            current_time += timedelta(seconds=interval + random.uniform(-0.05, 0.05))
            
        # Ransom note dropper
        events.append(self._build_event(
            timestamp=current_time.strftime('%Y-%m-%d %H:%M:%S'),
            event_type='PROCESS_START',
            process_name=random.choice(['README_DECRYPT.exe', 'HOW_TO_PAY.bat']),
            file_path='C:\\Users\\Public\\Desktop\\'
        ))
        current_time += timedelta(seconds=1)
            
        self.impact_time_end = current_time
        self.stats['encryption'] = len(events)
        return events

    def generate_impact(self):
        """Stage 4: Impact
        Drop ransom note, phone home, and attempt basic spread.
        """
        events = []
        current_time = self.impact_time_end + timedelta(seconds=random.randint(1, 4))
        
        # Ransom Note write
        events.append(self._build_event(
            timestamp=current_time.strftime('%Y-%m-%d %H:%M:%S'),
            event_type='FILE_WRITE',
            file_path='/README_YOUR_FILES_ARE_ENCRYPTED.txt',
            bytes_transferred=random.randint(2000, 5000)
        ))
        current_time += timedelta(seconds=random.randint(2, 5))
        
        # Phone home
        c2_ports = self.config.get('c2_ports', [4444, 8443, 443])
        num_c2 = random.randint(2, 4)
        c2_ip = self.fake.ipv4_public()
        
        for _ in range(num_c2):
            events.append(self._build_event(
                timestamp=current_time.strftime('%Y-%m-%d %H:%M:%S'),
                event_type='NETWORK_CONNECTION',
                dest_ip=c2_ip,
                dest_port=random.choice(c2_ports),
                bytes_transferred=random.randint(100, 500)
            ))
            current_time += timedelta(seconds=random.randint(1, 3))
            
        # Cleanup/backdoor process - Correct key: 'suspicious_processes' (Bug B)
        susp_procs = self.config.get('suspicious_processes', ["svchost_fake.exe", "winlogon_helper.exe"])
        events.append(self._build_event(
            timestamp=current_time.strftime('%Y-%m-%d %H:%M:%S'),
            event_type='PROCESS_START',
            process_name=random.choice(susp_procs)
        ))
        current_time += timedelta(seconds=2)
            
        # Spreading (AUTH_FAIL against others)
        num_spread = random.randint(1, 3)
        other_hosts = [h for h in self.all_hostnames if h != self.victim_host]
        
        for _ in range(num_spread):
            target_host = random.choice(other_hosts) if other_hosts else 'WS-UNKNOWN-TARGET'
            events.append(self._build_event(
                timestamp=current_time.strftime('%Y-%m-%d %H:%M:%S'),
                event_type='AUTH_FAIL',
                hostname=target_host,
                bytes_transferred=0 # Added to hostname as positional or keyword
            ))
            # Wait, my build_event has hostname as keyword.
            # I must use keyword arguments properly.
            current_time += timedelta(seconds=random.randint(1, 3))

        self.stats['impact'] = len(events)
        return events

def main():
    """Main execution block for full ransomware scenario injection."""
    config = load_config()
    input_csv = get_latest_normal_log()
    
    df_normal = pd.read_csv(input_csv)
    normal_events = df_normal.to_dict('records')
    
    scenario = RansomwareScenario(config, df_normal)
    attack_events = scenario.run(df_normal)
    
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
    
    print("\n[Ransomware Scenario]")
    print(f"  Stage 1 Delivery:    {scenario.stats['delivery']} events")
    print(f"  Stage 2 Discovery:   {scenario.stats['discovery']} events")
    print(f"  Stage 3 Encryption:  {scenario.stats['encryption']} events  ({len(scenario.discovered_files)} files × 2 events each + 1 note dropper)")
    print(f"  Stage 4 Impact:      {scenario.stats['impact']} events")
    print("  " + "─"*37)
    print(f"  Total injected:      {attack_count} events into {total - attack_count} normal ({pct:.2f}% rate)\n")

if __name__ == "__main__":
    main()
