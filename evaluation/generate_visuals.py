import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import glob
import os
import sys
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay, classification_report

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detector.attack_classifier import prepare_multiclass_data, train_attack_classifier, predict_attack_type

def generate_all_plots():
    os.makedirs('evaluation/visuals', exist_ok=True)
    sns.set_theme(style="whitegrid")
    
    # 1. Load data for mapping
    log_files = glob.glob("data/attack_logs/*.csv")
    if not log_files:
        print("No attack logs found.")
        return
    
    df_logs = pd.concat([pd.read_csv(f) for f in log_files], ignore_index=True)
    df_logs['timestamp'] = pd.to_datetime(df_logs['timestamp'])
    
    # --- 1. MITRE Heatmap ---
    mitre_logs = df_logs[df_logs['mitre_technique_id'].notna() & (df_logs['mitre_technique_id'] != 'None')]
    if not mitre_logs.empty:
        plt.figure(figsize=(12, 8))
        heatmap_data = pd.crosstab(mitre_logs['mitre_tactic'], mitre_logs['mitre_technique'])
        sns.heatmap(heatmap_data, annot=True, cmap="YlOrRd", fmt="d")
        plt.title('MITRE Tactic vs Technique Frequency', fontsize=15)
        plt.tight_layout()
        plt.savefig('evaluation/visuals/mitre_heatmap.png', dpi=150)
        print("Saved: evaluation/visuals/mitre_heatmap.png")

    # --- 2. Attack Timeline ---
    if not mitre_logs.empty:
        plt.figure(figsize=(15, 7))
        sns.scatterplot(data=mitre_logs, x='timestamp', y='mitre_technique_id', hue='attack_type', s=100, alpha=0.7)
        plt.title('Timeline of MITRE Techniques Triggered', fontsize=15)
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig('evaluation/visuals/attack_timeline.png', dpi=150)
        print("Saved: evaluation/visuals/attack_timeline.png")

    # --- 3. Confusion Matrix ---
    csv_paths = glob.glob("data/attack_logs/*.csv") + glob.glob("data/normal_logs/*.csv")
    X, y, le = prepare_multiclass_data(csv_paths)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    model = train_attack_classifier(X_train_scaled, y_train)
    y_pred = predict_attack_type(model, X_test_scaled)
    
    cm = confusion_matrix(y_test, y_pred)
    fig, ax = plt.subplots(figsize=(10, 8))
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=le.classes_)
    disp.plot(ax=ax, cmap='Blues')
    plt.title('Attack Classification Confusion Matrix', fontsize=15)
    plt.tight_layout()
    plt.savefig('evaluation/visuals/confusion_matrix.png', dpi=150)
    print("Saved: evaluation/visuals/confusion_matrix.png")

    # --- 4. Detection Rates (Recall) ---
    report = classification_report(y_test, y_pred, target_names=le.classes_, output_dict=True, zero_division=0)
    recalls = [report[cls]['recall'] * 100 for cls in le.classes_]
    
    plt.figure(figsize=(10, 6))
    sns.barplot(x=list(le.classes_), y=recalls, palette="viridis")
    plt.title('Detection Rate (Recall) per Attack Type', fontsize=15)
    plt.ylabel('Recall %')
    plt.ylim(0, 110)
    for i, v in enumerate(recalls):
        plt.text(i, v + 2, f"{v:.1f}%", ha='center', fontweight='bold')
    plt.tight_layout()
    plt.savefig('evaluation/visuals/detection_rates.png', dpi=150)
    print("Saved: evaluation/visuals/detection_rates.png")

if __name__ == "__main__":
    generate_all_plots()
