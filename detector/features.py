import pandas as pd
import numpy as np
import os
import glob
from sklearn.preprocessing import StandardScaler

def get_latest_file(pattern):
    """Return path to the most recently created file matching pattern."""
    files = glob.glob(pattern)
    if not files:
        return None
    return max(files, key=os.path.getctime)

def load_logs(data_dir="data/attack_logs"):
    """
    Load only the LATEST normal log and latest attack log from each
    attack type. Handles mismatched columns by using pd.concat + fillna.
    Returns a single combined DataFrame sorted by timestamp.
    """
    dfs = []
    
    # Latest normal log
    normal = get_latest_file("data/normal_logs/*.csv")
    if normal:
        dfs.append(pd.read_csv(normal))
            
    # Latest of each attack type
    for attack_type in ["phishing", "ransomware", "insider_threat"]:
        path = get_latest_file(f"{data_dir}/{attack_type}_logs_*.csv")
        if path:
            dfs.append(pd.read_csv(path))
            
    if not dfs:
        print("No log files found.")
        return pd.DataFrame()
        
    combined_df = pd.concat(dfs, ignore_index=True)
    
    # Handle missing columns gracefully
    string_cols = combined_df.select_dtypes(include=['object', 'string']).columns
    numeric_cols = combined_df.select_dtypes(include=[np.number]).columns
    
    combined_df[string_cols] = combined_df[string_cols].fillna('')
    combined_df[numeric_cols] = combined_df[numeric_cols].fillna(0)
    
    # Parse timestamp and sort
    combined_df['timestamp'] = pd.to_datetime(combined_df['timestamp'])
    combined_df['bytes_transferred'] = pd.to_numeric(combined_df.get('bytes_transferred', 0), errors='coerce').fillna(0)
    
    return combined_df.sort_values('timestamp').reset_index(drop=True)

def extract_features(df, window_minutes=5):
    """
    Slide a time window over the log DataFrame.
    For each user in each window, compute the 9 features.
    Returns a new DataFrame where each row = one user-window.
    """
    if df.empty:
        return pd.DataFrame()
        
    # BUG 2 FIX: Remove pre-authentication / no-user events
    df = df[df['user_id'].notna()]
    df = df[df['user_id'].astype(str).str.strip() != '-']
    df = df[df['user_id'].astype(str).str.strip() != '']

    # Pre-process bytes_transferred
    df['bytes_transferred'] = pd.to_numeric(df.get('bytes_transferred', 0), errors='coerce').fillna(0)
    
    # Build a lookup dict BEFORE windowing:
    user_known_ips = {}
    if 'source_ip' in df.columns:
        for user_id, group in df[df['label'] == 0].groupby('user_id'):
            user_known_ips[user_id] = set(group['source_ip'].replace('', np.nan).dropna().unique())
            
    features_list = []
    has_success_col = 'success' in df.columns
    
    # Use pd.Grouper for highly optimized 5-minute rolling windows
    grouped = df.groupby(['user_id', pd.Grouper(key='timestamp', freq=f'{window_minutes}min')])
    
    for (user_id, window_start), group in grouped:
        if group.empty:
            continue
            
        # 1 & 2. login_count and failed_login_rate
        login_mask = group['event_type'].isin(['LOGIN', 'AUTH_FAIL'])
        login_events = group[login_mask]
        login_count = len(login_events)
        
        if has_success_col:
            failed_mask = (group['event_type'] == 'AUTH_FAIL') | (group['success'].astype(str).str.lower().isin(['false', '0.0', '0']))
            failed_logins = len(group[failed_mask & login_mask])
        else:
            failed_logins = len(group[group['event_type'] == 'AUTH_FAIL'])
            
        failed_login_rate = failed_logins / login_count if login_count > 0 else 0.0
        
        # 3. unique_ips
        if 'source_ip' in group.columns:
            unique_ips = group['source_ip'].replace('', np.nan).dropna().nunique()
        else:
            unique_ips = 0
            
        # 4. files_accessed_per_min
        file_events = group[group['event_type'].isin(['FILE_ACCESS', 'FILE_WRITE'])]
        files_accessed_per_min = len(file_events) / window_minutes
        
        # 5. bytes_transferred
        bytes_transferred = group['bytes_transferred'].sum()
        
        # 6 & 7. hour_of_day & is_weekend
        hour_of_day = group['timestamp'].iloc[0].hour
        is_weekend = 1 if group['timestamp'].iloc[0].weekday() >= 5 else 0
        
        # 8. new_ip_flag
        known_ips = user_known_ips.get(user_id, set())
        if 'source_ip' in group.columns:
            window_ips = set(group['source_ip'].replace('', np.nan).dropna().unique())
        else:
            window_ips = set()
            
        new_ip_flag = 1 if not window_ips.issubset(known_ips) else 0
        
        # Label & Attack Type
        label = 1 if (group['label'] == 1).any() else 0
        
        attack_types = group[group['attack_type'] != 'none']['attack_type']
        if attack_types.empty:
            attack_type = 'none'
        else:
            attack_type = attack_types.mode().iloc[0]
            
        features_list.append({
            'window_start': window_start,
            'user_id': user_id,
            'login_count': login_count,
            'failed_login_rate': failed_login_rate,
            'unique_ips': unique_ips,
            'files_accessed_per_min': files_accessed_per_min,
            'bytes_transferred': bytes_transferred,
            'hour_of_day': hour_of_day,
            'is_weekend': is_weekend,
            'new_ip_flag': new_ip_flag,
            'event_burst_rate': len(group) / 300.0,
            'label': label,
            'attack_type': attack_type
        })
        
    return pd.DataFrame(features_list)

def preprocess(feature_df):
    """
    Prepare the feature DataFrame for ML training.
    Steps:
      1. Fill any remaining NaN with 0
      2. Convert boolean columns to int (is_weekend, new_ip_flag)
      3. Scale numeric features using sklearn StandardScaler, fitting only on normal data
      4. Return: X (feature matrix), y (labels), scaler (fitted)
    """
    feature_df = feature_df.fillna(0)
    
    for col in ['is_weekend', 'new_ip_flag']:
        if col in feature_df.columns:
            feature_df[col] = feature_df[col].astype(int)
            
    feature_cols = ['login_count', 'failed_login_rate', 'unique_ips', 
                    'files_accessed_per_min', 'bytes_transferred', 'hour_of_day', 
                    'is_weekend', 'new_ip_flag', 'event_burst_rate']
                    
    X_df = feature_df[feature_cols].copy()
    y = feature_df['label'].astype(int).values
    
    scaler = StandardScaler()
    
    # Fit scaler ONLY on normal data (label=0) to avoid data leakage
    normal_windows = feature_df[feature_df['label'] == 0]
    if len(normal_windows) > 0:
        scaler.fit(normal_windows[feature_cols])
    else:
        scaler.fit(X_df)
        
    X_scaled = scaler.transform(X_df)
    
    return X_scaled, y, scaler

def save_features(feature_df, output_path="data/features.csv"):
    """
    Save the raw (unscaled) feature DataFrame to CSV.
    This is the human-readable version for inspection.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    feature_df.to_csv(output_path, index=False)

if __name__ == "__main__":
    df = load_logs()
    if df.empty:
        print("No logs available. Exiting.")
    else:
        print(f"Loaded {len(df)} raw log events")
        
        features_df = extract_features(df, window_minutes=5)
        print(f"Extracted {len(features_df)} feature windows")
        
        if not features_df.empty:
            counts = features_df['label'].value_counts()
            normal_count = counts.get(0, 0)
            attack_count = counts.get(1, 0)
            total = len(features_df)
            
            print("Label distribution:")
            print(f"0 (normal): {normal_count} windows ({(normal_count/total)*100:.1f}%)")
            print(f"1 (attack):  {attack_count} windows ({(attack_count/total)*100:.1f}%)")
            
            print("Attack breakdown:")
            attack_types = features_df[features_df['label'] == 1]['attack_type'].value_counts()
            for attack_type, count in attack_types.items():
                if attack_type != 'none':
                    print(f"{attack_type}: {count} windows")
            
            save_features(features_df)
            print("Saved features to: data/features.csv")
            print(f"Feature matrix shape: ({len(features_df)}, 9)")
