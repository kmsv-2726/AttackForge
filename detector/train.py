import os
import sys
# Add parent directory sequence to sys.path to allow 'detector.' imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import numpy as np
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, roc_curve
)
from detector.features import load_logs, extract_features, preprocess
from detector.model import AnomalyDetector

def main():
    print("Step 1 — Load features")
    df_raw = load_logs()
    df_feat = extract_features(df_raw)
    X, y, scaler = preprocess(df_feat)
    
    print("Step 2 — Split data")
    # We must keep df_feat aligned to get attack_type later
    X_train, X_test, y_train, y_test, df_train, df_test = train_test_split(
        X, y, df_feat, test_size=0.2, random_state=42, stratify=y
    )
    
    print("Step 3 — Train on normal only")
    # Unsupervised learning: extract ONLY the normal rows from the training set
    X_train_normal = X_train[y_train == 0]
    
    # Calculate real attack rate from training data
    real_attack_rate = y_train.mean()
    # Clamp between 0.005 and 0.05 (IsolationForest valid range)
    contamination = float(np.clip(real_attack_rate, 0.005, 0.05))
    print(f"  Tuned contamination: {contamination:.4f} "
          f"(real attack rate: {real_attack_rate:.4f})")

    detector = AnomalyDetector(contamination=contamination)
    detector.fit(X_train_normal)
    
    print("Step 4 — Predict on test set")
    # Predict on the full test set (normal + mixed attacks)
    y_pred = detector.predict(X_test)
    y_scores = detector.score_samples(X_test)
    
    # Sklearn's score_samples returns a lower score for anomalies.
    # For ROC-AUC, a higher score should indicate the positive class (attack=1).
    # We negate the raw scores so higher = more anomalous.
    anomaly_scores = -y_scores
    
    print("Step 5 — Evaluate and print results")
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    auc = roc_auc_score(y_test, anomaly_scores)
    cm = confusion_matrix(y_test, y_pred)
    
    total_train = len(y_train)
    total_test = len(y_test)
    test_normal = np.sum(y_test == 0)
    test_attack = np.sum(y_test == 1)
    
    print("\n══════════════════════════════════════════")
    print("  ANOMALY DETECTOR — EVALUATION REPORT")
    print("══════════════════════════════════════════")
    print(f"\nTraining set:   {total_train} windows  (normal only)")
    print(f"Test set:       {total_test} windows  (normal + attack mixed)")
    print(f"  Normal:       {test_normal}  ({test_normal/total_test*100:.1f}%)")
    print(f"  Attack:       {test_attack}  ({test_attack/total_test*100:.1f}%)")
    
    print("\n── Detection Results ───────────────────")
    print(f"  Precision:    {precision:.2f}   (of all alerts, how many were real attacks?)")
    print(f"  Recall:       {recall:.2f}   (of all attacks, how many were caught?)")
    print(f"  F1 Score:     {f1:.2f}   (balance of precision and recall)")
    print(f"  ROC-AUC:      {auc:.2f}   (0.5=random, 1.0=perfect)")
    
    print("\n── Confusion Matrix ────────────────────")
    print("                  Predicted Normal  Predicted Attack")
    print(f"  Actual Normal        {cm[0,0]:<4}               {cm[0,1]:<4}")
    print(f"  Actual Attack        {cm[1,0]:<4}               {cm[1,1]:<4}")
    
    print("\n── Per Attack-Type Recall ──────────────")
    for atype in ['phishing', 'ransomware', 'insider_threat']:
        mask = (df_test['attack_type'] == atype)
        total_atype = mask.sum()
        if total_atype > 0:
            caught_atype = np.sum((y_test[mask] == 1) & (y_pred[mask] == 1))
            print(f"  {atype:<14}: {caught_atype}/{total_atype} caught  ({caught_atype/total_atype*100:.1f}%)")
        else:
            print(f"  {atype:<14}: 0/0 caught  (0.0%)")
            
    print("\n══════════════════════════════════════════")
    
    print("Step 6 — Save the model")
    # The models/ directory is automatically handled by the save() method
    detector.save("models/anomaly_detector.pkl")
    print("Model saved to models/anomaly_detector.pkl")
    
    print("Step 7 — Plot ROC curve")
    fpr, tpr, _ = roc_curve(y_test, anomaly_scores)
    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, label=f'Isolation Forest (AUC={auc:.3f})')
    plt.plot([0,1],[0,1],'--', color='gray', label='Random baseline')
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate (Recall)')
    plt.title('ROC Curve — Anomaly Detector')
    plt.legend()
    plt.tight_layout()
    
    os.makedirs("models", exist_ok=True)
    plt.savefig('models/roc_curve_anomaly.png')
    print("ROC curve saved to models/roc_curve_anomaly.png")

if __name__ == "__main__":
    main()
