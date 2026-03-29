import pandas as pd
import random
from faker import Faker
from datetime import datetime, timedelta
import uuid
import os

# Initialize Faker for realistic fake data
fake = Faker()

# Define the log format standard fields according to REQUIREMENTS.md
BASE_FIELDS = [
    'timestamp', 'event_id', 'event_type', 
    'user_id', 'source_ip', 'hostname', 
    'department',
    'label', 'attack_type'
]

# Common event types for benign (normal) activity
EVENT_TYPES = ['LOGIN', 'FILE_ACCESS', 'NETWORK', 'PROCESS', 'LOGOUT']

def generate_users(num_users=20):
    """
    Creates a list of realistic usernames to reuse throughout the simulation.
    
    Args:
        num_users (int): How many unique users to generate.
    Returns:
        list: A list of strings containing usernames.
    """
    return [fake.user_name() for _ in range(num_users)]

def generate_hostnames(num_hosts=10):
    """
    Creates a list of realistic enterprise-style hostnames.
    
    Args:
        num_hosts (int): How many unique hostnames to generate.
    Returns:
        list: A list of strings containing hostnames (e.g., WS-AB-01).
    """
    return [f"WS-{fake.lexify(text='??').upper()}{fake.numerify(text='-##')}" for _ in range(num_hosts)]

def create_event(timestamp, user_id, source_ip, hostname):
    """
    Generates a single log row representing a normal (benign) event.
    
    Args:
        timestamp (datetime): The time the event occurred.
        user_id (str): The username responsible for the event.
        source_ip (str): The IP address where the event originated.
        hostname (str): The machine name where the activity happened.
    Returns:
        dict: A single log entry with all required base fields.
    """
    event_type = random.choice(EVENT_TYPES)
    department = random.choice(['Engineering', 'Marketing', 'Sales', 'HR', 'Finance'])
    
    return {
        'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        'event_id': str(uuid.uuid4()),
        'event_type': event_type,
        'user_id': user_id,
        'source_ip': source_ip,
        'hostname': hostname,
        'department': department,
        'label': 0,              # 0 means normal activity
        'attack_type': 'none'    # No attack for this week
    }

def generate_normal_logs(output_path, num_events=1000, days_back=7):
    """
    Generates a full CSV file of benign log activity across a specified timeframe.
    
    Args:
        output_path (str): The file path where the CSV will be saved.
        num_events (int): Total number of log rows to generate.
        days_back (int): How far back into the past the timestamps should start.
    """
    # Pre-generate some entities for consistency (realistic behavior)
    # This prevents users from switching computers/IPs every single event
    users = generate_users(num_users=10)
    hosts = generate_hostnames(num_hosts=5)
    
    # Map users to specific IPs and hostnames (as in a real office)
    user_profiles = {
        u: {'ip': fake.ipv4(), 'host': random.choice(hosts)} 
        for u in users
    }
    
    events = []
    # Start time
    current_time = datetime.now() - timedelta(days=days_back)
    
    # Generate events incrementally
    for i in range(num_events):
        # Move time forward randomly by seconds/minutes to simulate gaps between actions
        delta_seconds = random.randint(10, 600)
        current_time += timedelta(seconds=delta_seconds)
        
        # Pick a random user from our "employees" list
        user = random.choice(users)
        profile = user_profiles[user]
        
        # Create and append the event dictionary
        event = create_event(current_time, user, profile['ip'], profile['host'])
        events.append(event)
    
    # Convert list of dicts to a Pandas DataFrame
    df = pd.DataFrame(events)
    # Ensure columns are in the correct standard order
    df = df[BASE_FIELDS]
    
    # Create the output directory if it doesn't already exist
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # Save the data to a CSV file (without the index column)
    df.to_csv(output_path, index=False)
    print(f"\n[SUCCESS]")
    print(f"Generated {num_events} logs to: {output_path}")
    print(f"Sample data head:")
    print(df.head(3))

if __name__ == "__main__":
    # Define the output file path according to REQUIREMENTS.md
    output_file = os.path.join('data', 'normal_logs', 'normal_activity.csv')
    
    # Run the generator with 1000 events
    generate_normal_logs(output_file, num_events=1000)
