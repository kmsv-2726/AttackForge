import pandas as pd
import numpy as np
import glob
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix, f1_score

def _extract_windows(df, window_minutes=5):
    """Slide a time window over the log DataFrame and extract features, including MITRE techniques."""
    if df.empty:
        return pd.DataFrame()
        
    df = df[df['user_id'].notna()]
    df = df[df['user_id'].astype(str).str.strip() != '-']
    df = df[df['user_id'].astype(str).str.strip() != '']

    df['bytes_transferred'] = pd.to_numeric(df.get('bytes_transferred', 0), errors='coerce').fillna(0)
    
    if 'mitre_technique_id' not in df.columns:
        df['mitre_technique_id'] = 'None'
    df['mitre_technique_id'] = df['mitre_technique_id'].fillna('None')
    
    unique_techniques = [x for x in df['mitre_technique_id'].unique() if x != 'None']
    
    features_list = []
    
    grouped = df.groupby(['user_id', pd.Grouper(key='timestamp', freq=f'{window_minutes}min')])
    
    for (user_id, window_start), group in grouped:
        if group.empty:
            continue
            
        login_mask = group['event_type'].isin(['LOGIN', 'AUTH_FAIL'])
        login_events = group[login_mask]
        login_count = len(login_events)
        
        failed_mask = (group['event_type'] == 'AUTH_FAIL')
        if 'success' in group.columns:
            failed_mask = failed_mask | (group['success'].astype(str).str.lower().isin(['false', '0.0', '0']))
        failed_logins = len(group[failed_mask & login_mask])
            
        failed_login_rate = failed_logins / login_count if login_count > 0 else 0.0
        
        unique_ips = group['source_ip'].replace('', np.nan).dropna().nunique() if 'source_ip' in group.columns else 0
        
        file_events = group[group['event_type'].isin(['FILE_ACCESS', 'FILE_WRITE'])]
        files_accessed_per_min = len(file_events) / window_minutes
        
        bytes_val = np.log1p(group['bytes_transferred'].sum())
        
        hour_of_day = group['timestamp'].iloc[0].hour
        is_weekend = 1 if group['timestamp'].iloc[0].weekday() >= 5 else 0
        
        # Label & Attack Type
        label = 1 if (group['label'] == 1).any() else 0
        
        attack_types = group[group['attack_type'] != 'none']['attack_type']
        if attack_types.empty:
            attack_type = 'Normal'
        else:
            attack_type = attack_types.mode().iloc[0]
            if attack_type.lower() == 'phishing':
                attack_type = 'Phishing'
            elif attack_type.lower() == 'ransomware':
                attack_type = 'Ransomware'
            elif attack_type.lower() == 'insider_threat':
                attack_type = 'Insider_Threat'
        
        row = {
            'login_count': login_count,
            'failed_login_rate': failed_login_rate,
            'unique_ips': unique_ips,
            'files_accessed_per_min': files_accessed_per_min,
            'bytes_transferred': bytes_val,
            'hour_of_day': hour_of_day,
            'is_weekend': is_weekend,
            'event_burst_rate': len(group) / 300.0,
            'attack_type': attack_type
        }
        
        # Add MITRE technique counts
        tech_counts = group['mitre_technique_id'].value_counts()
        for tech in unique_techniques:
            row[f'mitre_count_{tech}'] = tech_counts.get(tech, 0)
            
        features_list.append(row)
        
    return pd.DataFrame(features_list)

def prepare_multiclass_data(csv_paths):
    dfs = []
    for path in csv_paths:
        dfs.append(pd.read_csv(path))
        
    if not dfs:
        raise ValueError("No CSV paths provided or found.")
        
    combined = pd.concat(dfs, ignore_index=True)
    if 'event_id' in combined.columns:
        combined = combined.drop_duplicates(subset=['event_id'])
        
    combined['timestamp'] = pd.to_datetime(combined['timestamp'])
    combined = combined.sort_values('timestamp').reset_index(drop=True)
    
    features_df = _extract_windows(combined)
    
    features_df = features_df.fillna(0)
    
    X_df = features_df.drop(columns=['attack_type'])
    y_raw = features_df['attack_type']
    
    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(y_raw)
    
    return X_df.values, y, label_encoder

def train_attack_classifier(X_train, y_train):
    model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
    model.fit(X_train, y_train)
    return model

def predict_attack_type(model, X_test):
    return model.predict(X_test)

def evaluate_multiclass(y_true, y_pred, label_encoder=None):
    metrics_dict = {}
    
    metrics_dict['accuracy'] = accuracy_score(y_true, y_pred)
    metrics_dict['macro_f1'] = f1_score(y_true, y_pred, average='macro')
    
    report = classification_report(y_true, y_pred, output_dict=True, zero_division=0)
    metrics_dict['classification_report'] = report
    metrics_dict['confusion_matrix'] = confusion_matrix(y_true, y_pred)
    
    return metrics_dict

if __name__ == "__main__":
    def get_latest_files(pattern, n=1):
        files = glob.glob(pattern)
        if not files:
            return []
        files.sort(key=os.path.getctime, reverse=True)
        return files[:n]
        
    csv_paths = (
        get_latest_files("data/normal_logs/*.csv", 2) +
        get_latest_files("data/attack_logs/phishing_logs_*.csv", 1) +
        get_latest_files("data/attack_logs/ransomware_logs_*.csv", 1) +
        get_latest_files("data/attack_logs/insider_threat_logs_*.csv", 1)
    )
    
    if not csv_paths:
        print("No logs found.")
    else:
        print(f"Loading {len(csv_paths)} recent log files...")
        print("Preparing multi-class data...")
        X, y, le = prepare_multiclass_data(csv_paths)
        print(f"Extracted {len(X)} feature windows.")
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
        
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        print("Training Random Forest Classifier...")
        model = train_attack_classifier(X_train_scaled, y_train)
        
        print("Evaluating...")
        y_pred = predict_attack_type(model, X_test_scaled)
        metrics = evaluate_multiclass(y_test, y_pred, le)
        
        print(f"\nOverall Accuracy: {metrics['accuracy']:.4f}")
        print(f"Macro F1 Score: {metrics['macro_f1']:.4f}\n")
        
        print("Per-class metrics:")
        for idx, class_name in enumerate(le.classes_):
            idx_str = str(idx)
            if idx_str in metrics['classification_report']:
                class_metrics = metrics['classification_report'][idx_str]
                print(f"  {class_name}:")
                print(f"    Precision: {class_metrics['precision']:.4f}")
                print(f"    Recall:    {class_metrics['recall']:.4f}")
                print(f"    F1:        {class_metrics['f1-score']:.4f}")
                
        print("\nConfusion Matrix:")
        print(metrics['confusion_matrix'])
