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
        return yaml.safe_load(f)['insider_threat']

def get_latest_normal_log():
    """Finds the most recent normal log CSV file."""
    files = glob.glob('data/normal_logs/*.csv')
    if not files:
        raise FileNotFoundError("No normal log files found.")
    return max(files, key=os.path.getctime)

class InsiderThreatScenario:
    def __init__(self, config, users_df):
        """
        Load parameters from configs/attack_configs.yaml.
        Pick exactly ONE insider user for the entire scenario (Bug C).
        """
        self.config = config
        self.users_df = users_df.dropna(subset=['user_id'])
        self.valid_users = list(self.users_df['user_id'].unique())
        self.fake = Faker()
        
        # Pick our insider - Exactly ONE user picked once at init
        if len(self.valid_users) > 0:
            insider_id = random.choice(self.valid_users)
            user_info = self.users_df[self.users_df['user_id'] == insider_id].iloc[0]
            self.insider = insider_id
            self.host = user_info['hostname']
            self.ip = user_info['source_ip']
            self.dept = user_info['department']
        else:
            self.insider = 'johndoe'
            self.host = 'WS-ENT-01'
            self.ip = '10.0.0.50'
            self.dept = 'Engineering'
        
        # Target Department (different from their own)
        all_depts = ['Engineering', 'Marketing', 'Sales', 'HR', 'Finance', 'Legal']
        other_depts = [d for d in all_depts if d != self.dept]
        self.target_dept = random.choice(other_depts) if other_depts else 'Finance'
        
        # Initial timing
        today = datetime.now().replace(microsecond=0)
        self.timeline_time = today.replace(
            hour=random.randint(9, 16),
            minute=random.randint(0, 50),
            second=random.randint(0, 59)
        )
        
        self.staged_files = []
        self.stats = {'preparation': 0, 'staging': 0, 'exfiltration': 0, 'cover': 0}

    def _build_event(self, **kwargs):
        """Helper to ensure a consistent schema for all insider threat events (Bug D)."""
        return {
            'timestamp': kwargs.get('timestamp', ''),
            'event_id': kwargs.get('event_id', str(uuid.uuid4())),
            'event_type': kwargs.get('event_type', 'INFO'),
            'user_id': self.insider,
            'source_ip': self.ip,
            'hostname': self.host,
            'department': self.dept,
            'label': 1,
            'attack_type': 'insider_threat',
            'file_path': kwargs.get('file_path', ''),
            'bytes_transferred': kwargs.get('bytes_transferred', ''),
            'device_id': kwargs.get('device_id', ''),
            'action': kwargs.get('action', ''),
            'process_name': kwargs.get('process_name', '')
        }

    def run(self, normal_events):
        """
        Execute all 4 stages in order.
        Return full list of attack events.
        """
        events = []
        events += self.generate_preparation()
        events += self.generate_staging()
        events += self.generate_exfiltration()
        events += self.generate_cover()
        return events

    def generate_preparation(self):
        """Stage 1: Preparation
        The insider browses documents outside of their department during normal hours.
        """
        events = []
        current_time = self.timeline_time
        
        num_prep = self.config.get('preparation_files', 5)
        for i in range(num_prep):
            path = f"/{self.target_dept.lower()}/overview_doc_{i}.pdf"
            events.append(self._build_event(
                timestamp=current_time.strftime('%Y-%m-%d %H:%M:%S'),
                event_type='FILE_ACCESS',
                file_path=path,
                bytes_transferred=random.randint(5000, 50000)
            ))
            current_time += timedelta(minutes=random.randint(1, 10))
            
        # Optional cloud recon ping
        for _ in range(random.randint(1, 2)):
            events.append(self._build_event(
                timestamp=current_time.strftime('%Y-%m-%d %H:%M:%S'),
                event_type='NETWORK_CONNECTION',
                bytes_transferred=random.randint(500, 2000)
            ))
            current_time += timedelta(minutes=random.randint(2, 5))
            
        self.timeline_time = current_time
        self.stats['preparation'] = len(events)
        return events

    def generate_staging(self):
        """Stage 2: Staging
        Insider rapidly searches targets and copies multiple files into a staging directory.
        """
        events = []
        # Move forward an unpredictable amount of time, still in regular business hours basically
        current_time = self.timeline_time + timedelta(hours=random.randint(1, 4))
        
        min_files = self.config.get('staging_min_files', 20)
        max_files = self.config.get('staging_max_files', 60)
        num_files = random.randint(min_files, max_files)
        
        # 10 to 20 minute tight window
        window_secs = random.randint(600, 1200)
        interval = window_secs / max(num_files, 1)
        
        # Base accesses
        accessed_paths = []
        for i in range(num_files):
            path = f"/{self.target_dept.lower()}/confidential_report_{i}.pdf"
            accessed_paths.append(path)
            events.append(self._build_event(
                timestamp=current_time.strftime('%Y-%m-%d %H:%M:%S'),
                event_type='FILE_ACCESS',
                file_path=path,
                bytes_transferred=random.randint(100000, 1000000)
            ))
            current_time += timedelta(seconds=interval)
            
        # Copy to staging
        num_staging = random.randint(5, 15)
        staging_dir = random.choice(['C:\\Users\\Public\\', '/temp/staging/', 'C:\\Temp\\'])
        
        for _ in range(num_staging):
            target_path = random.choice(accessed_paths)
            file_name = target_path.split("/")[-1]
            staged_path = staging_dir + file_name
            self.staged_files.append(staged_path)
            
            events.append(self._build_event(
                timestamp=current_time.strftime('%Y-%m-%d %H:%M:%S'),
                event_type='FILE_WRITE',
                file_path=staged_path,
                bytes_transferred=random.randint(100000, 1000000)
            ))
            current_time += timedelta(seconds=random.randint(15, 60))
            
        self.timeline_time = current_time
        self.stats['staging'] = len(events)
        return events

    def generate_exfiltration(self):
        """Stage 3: Exfiltration
        Insider removes data using USB or Cloud, usually after hours.
        """
        events = []
        # Move forward to after-hours
        current_time = self.timeline_time
        unusual_start = self.config.get('unusual_hour_start', 20)
        unusual_end = self.config.get('unusual_hour_end', 6)
        
        hour = random.choice(list(range(unusual_start, 24)) + list(range(0, unusual_end)))
        current_time = current_time.replace(hour=hour, minute=random.randint(0, 50))
        
        # Advance 1 day if we looped backward in time
        if current_time < self.timeline_time:
            current_time += timedelta(days=1)
            
        exfil_method = self.config.get('exfil_method', 'usb')
        
        if exfil_method == 'usb':
            events.append(self._build_event(
                timestamp=current_time.strftime('%Y-%m-%d %H:%M:%S'),
                event_type='USB_CONNECT',
                device_id=f"USB-SAN-{str(uuid.uuid4())[:8]}"
            ))
            current_time += timedelta(seconds=random.randint(5, 30))
            
            num_exfil = random.randint(self.config.get('usb_min_files', 10), self.config.get('usb_max_files', 30))
            for _ in range(num_exfil):
                events.append(self._build_event(
                    timestamp=current_time.strftime('%Y-%m-%d %H:%M:%S'),
                    event_type='FILE_WRITE',
                    file_path=f"/usb/archive_{random.randint(1, 999)}.zip",
                    bytes_transferred=random.randint(5000000, 100000000)
                ))
                current_time += timedelta(seconds=random.randint(10, 60))
        else:
            # Cloud
            num_conn = random.randint(5, 10)
            for _ in range(num_conn):
                events.append(self._build_event(
                    timestamp=current_time.strftime('%Y-%m-%d %H:%M:%S'),
                    event_type='NETWORK_CONNECTION',
                    bytes_transferred=random.randint(10000000, 500000000)
                ))
                current_time += timedelta(minutes=random.randint(1, 5))
                
        self.timeline_time = current_time
        self.stats['exfiltration'] = len(events)
        self.stats['method'] = exfil_method
        return events

    def generate_cover(self):
        """Stage 4: Cover Tracks
        Delete staged files and attempt log clearance (Bug E).
        """
        events = []
        current_time = self.timeline_time + timedelta(minutes=random.randint(2, 5))
        
        num_deletes = random.randint(self.config.get('cover_min_deletes', 3), self.config.get('cover_max_deletes', 8))
        
        for _ in range(num_deletes):
            target_delete = self.staged_files.pop() if self.staged_files else "C:\\Temp\\cleanup.tmp"
                
            events.append(self._build_event(
                timestamp=current_time.strftime('%Y-%m-%d %H:%M:%S'),
                event_type='FILE_WRITE',
                file_path=target_delete,
                bytes_transferred=0
            ))
            current_time += timedelta(seconds=random.randint(1, 5))
            
        # Confirming stage logic and keys for Bug E
        procs = self.config.get('cover_processes', ["wevtutil.exe", "clearlog.bat", "powershell.exe"])
        for _ in range(random.randint(1, 2)):
            events.append(self._build_event(
                timestamp=current_time.strftime('%Y-%m-%d %H:%M:%S'),
                event_type='PROCESS_START',
                process_name=random.choice(procs) # Uses key 'process_name'
            ))
            current_time += timedelta(seconds=random.randint(1, 5))

        self.stats['cover'] = len(events)
        return events

def main():
    """Main execution block for full insider threat scenario injection."""
    config = load_config()
    input_csv = get_latest_normal_log()
    
    df_normal = pd.read_csv(input_csv)
    normal_events = df_normal.to_dict('records')
    
    scenario = InsiderThreatScenario(config, df_normal)
    attack_events = scenario.run(df_normal)
    
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
    
    print("\n[Insider Threat Scenario]")
    print(f"  Stage 1 Preparation:   {scenario.stats['preparation']} events")
    print(f"  Stage 2 Data staging:  {scenario.stats['staging']} events")
    print(f"  Stage 3 Exfiltration:  {scenario.stats['exfiltration']} events  ({scenario.stats['method'].upper()} method)")
    print(f"  Stage 4 Cover tracks:  {scenario.stats['cover']} events")
    print("  " + "─"*37)
    print(f"  Total injected:        {attack_count} events into {total - attack_count} normal ({pct:.2f}% rate)\n")

if __name__ == "__main__":
    main()
