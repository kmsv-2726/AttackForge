import os
import sys
import argparse
import datetime
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import (
    precision_score, recall_score, f1_score, roc_auc_score,
    confusion_matrix, roc_curve
)
from sklearn.model_selection import train_test_split

# Add parent directory to path so we can import detector modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detector.features import preprocess
from detector.model import AnomalyDetector, SupervisedDetector

def load_model(model_type="supervised", model_path=None):
    """
    Load a saved detector model from disk.

    Args:
        model_type: "supervised" or "anomaly"
        model_path: explicit path — if None, uses default paths:
                    supervised → models/supervised_detector.pkl
                    anomaly    → models/anomaly_detector.pkl
    Returns:
        Loaded model object (AnomalyDetector or SupervisedDetector)
    """
    if model_path is None:
        if model_type == "supervised":
            model_path = "models/supervised_detector.pkl"
        elif model_type == "anomaly":
            model_path = "models/anomaly_detector.pkl"
        else:
            raise ValueError(f"Unknown model_type: {model_type}")

    if model_type == "supervised":
        model = SupervisedDetector()
        model.load(model_path)
    elif model_type == "anomaly":
        model = AnomalyDetector()
        model.load(model_path)
    return model

def load_test_data(features_path="data/features.csv", test_size=0.2, random_state=42):
    """
    Load features.csv and return the held-out TEST split only.
    Uses same split parameters as train.py for consistency.

    Returns:
        X_test, y_test, df_feat_test (with attack_type column)
    """
    if not os.path.exists(features_path):
        raise FileNotFoundError(f"Features file not found at {features_path}. Run features.py first.")
        
    df_feat = pd.read_csv(features_path)
    # Recreate the preprocess and split logic exactly as in train.py
    X, y, scaler = preprocess(df_feat)
    
    # Must use same split to compare with train.py
    X_train, X_test, y_train, y_test, df_train, df_test = train_test_split(
        X, y, df_feat, test_size=test_size, random_state=random_state, stratify=y
    )
    return X_test, y_test, df_test

def compute_metrics(model, X_test, y_test, model_type="supervised"):
    """
    Compute all standard detection metrics.

    Args:
        model:      loaded AnomalyDetector or SupervisedDetector
        X_test:     feature matrix for test set
        y_test:     true labels for test set
        model_type: "supervised" uses predict_proba for AUC
                    "anomaly" uses score_samples for AUC

    Returns dict with keys:
        precision, recall, f1, roc_auc,
        false_alarm_rate, confusion_matrix,
        y_pred, y_scores, y_test
    """
    y_pred = model.predict(X_test)
    
    if model_type == "supervised":
        # Returns probability of class 1
        y_scores = model.predict_proba(X_test)
    elif model_type == "anomaly":
        # Negative mapping so higher = more anomalous (closer to attack)
        y_scores = -model.score_samples(X_test)
    else:
        raise ValueError(f"Unknown model_type: {model_type}")

    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    roc_auc = roc_auc_score(y_test, y_scores)
    cm = confusion_matrix(y_test, y_pred)
    
    if y_test.sum() == len(y_test):
        # All attacks, no normal, false alarm rate is 0
        false_alarm_rate = 0.0
    else:
        # False alarm rate = False Positive / Actual Normal
        # cm[0, 1] is FP, cm[0, 0] is TN
        false_alarm_rate = cm[0, 1] / (cm[0, 0] + cm[0, 1])

    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "roc_auc": roc_auc,
        "false_alarm_rate": false_alarm_rate,
        "confusion_matrix": cm,
        "y_pred": y_pred,
        "y_scores": y_scores,
        "y_test": y_test
    }

def compute_mttd(df_feat_test, y_pred, window_minutes=5):
    """
    Compute Mean Time To Detect for each attack in the test set.

    Logic:
      - Group test windows by user_id and sort by window_start
      - For each user who has at least one attack window (label=1):
          Find the first window where attack starts (label=1)
          Find the first window where model raises alert (y_pred=1)
          MTTD for this user = time between those two windows
      - Average MTTD across all detected attacks

    Args:
        df_feat_test: feature DataFrame with window_start, user_id,
                      label, attack_type columns
        y_pred:       model predictions aligned with df_feat_test rows
        window_minutes: size of each window (5 minutes default)

    Returns:
        mttd_minutes (float): average minutes to first detection
                              None if no attacks were detected
    """
    df = df_feat_test.copy()
    df['y_pred'] = y_pred
    df['window_start'] = pd.to_datetime(df['window_start'])
    
    mttds = []
    
    grouped = df.groupby('user_id')
    for user_id, group in grouped:
        group = group.sort_values('window_start')
        
        # Check if user has an attack
        if (group['label'] == 1).sum() > 0:
            first_attack_time = group[group['label'] == 1]['window_start'].min()
            
            # Look at predictions AT OR AFTER the first attack time
            subsequent_alerts = group[(group['window_start'] >= first_attack_time) & (group['y_pred'] == 1)]
            
            if not subsequent_alerts.empty:
                first_alert_time = subsequent_alerts['window_start'].min()
                mttd = (first_alert_time - first_attack_time).total_seconds() / 60.0
                mttds.append(mttd)
            
    if mttds:
        return np.mean(mttds)
    return None

def per_attack_metrics(df_feat_test, y_test, y_pred):
    """
    Compute precision, recall, and F1 per attack type.

    Returns dict:
        {
          "phishing":       {"precision": x, "recall": x, "f1": x,
                             "caught": n, "total": n},
          "ransomware":     {...},
          "insider_threat": {...}
        }
    """
    results = {}
    attack_types = [t for t in df_feat_test['attack_type'].unique() if t != 'none']
    
    for atype in attack_types:
        mask = (df_feat_test['attack_type'] == atype)
        total = mask.sum()
        if total == 0:
            continue
            
        caught = np.sum((y_test[mask] == 1) & (y_pred[mask] == 1))
        
        # To compute precision and F1 in isolation, subset to Normal OR this attack
        mask_normal_or_this = (df_feat_test['attack_type'] == 'none') | (df_feat_test['attack_type'] == atype)
        y_true_sub = y_test[mask_normal_or_this]
        y_pred_sub = y_pred[mask_normal_or_this]
        
        prec = precision_score(y_true_sub, y_pred_sub, zero_division=0)
        rec = recall_score(y_true_sub, y_pred_sub, zero_division=0)
        f1 = f1_score(y_true_sub, y_pred_sub, zero_division=0)
        
        results[atype] = {
            "precision": prec,
            "recall": rec,
            "f1": f1,
            "caught": caught,
            "total": total
        }
        
    return results

def plot_roc_curve(results_dict, save_path="evaluation/roc_comparison.png"):
    """
    Plot ROC curves for one or more models on the same chart.

    Args:
        results_dict: {model_name: {"y_test": ..., "y_scores": ..., "auc": ...}}
        save_path: where to save the PNG

    Colours:
        anomaly    → steelblue
        supervised → darkorange
        Any extras → green, red, purple (cycle)
    """
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    plt.figure(figsize=(9, 6))
    
    colors = {
        "anomaly": "steelblue",
        "supervised": "darkorange"
    }
    fallback_colors = ["green", "red", "purple", "brown"]
    fallback_idx = 0
    
    for m_name, m_data in results_dict.items():
        fpr, tpr, _ = roc_curve(m_data["y_test"], m_data["y_scores"])
        auc = m_data.get("auc", 0)
        
        color = colors.get(m_name)
        if not color:
            color = fallback_colors[fallback_idx % len(fallback_colors)]
            fallback_idx += 1
            
        plt.plot(fpr, tpr, label=f'{m_name.capitalize()} (AUC={auc:.3f})', color=color, linewidth=2)
        if m_name == "supervised":
            plt.fill_between(fpr, tpr, alpha=0.08, color=color)
            
    plt.plot([0,1],[0,1],'--', color='gray', label='Random baseline', linewidth=1)
    plt.xlabel('False Positive Rate', fontsize=12)
    plt.ylabel('True Positive Rate (Recall)', fontsize=12)
    plt.title('ROC Curve Comparison', fontsize=13)
    plt.legend(fontsize=11)
    plt.tight_layout()
    plt.savefig(save_path, dpi=150)
    plt.close()

def plot_confusion_matrix(cm, model_name, save_path="evaluation/confusion_matrix.png"):
    """
    Plot a labelled confusion matrix heatmap using matplotlib.
    Labels: Normal / Attack on both axes.
    Show raw counts and percentages in each cell.
    """
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    fig, ax = plt.subplots(figsize=(6, 5))
    cax = ax.matshow(cm, cmap=plt.cm.Blues, alpha=0.7)
    
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            total = np.sum(cm)
            pct = (cm[i, j] / total) * 100 if total > 0 else 0
            ax.text(x=j, y=i, s=f"{cm[i, j]}\\n({pct:.1f}%)", va='center', ha='center', size='large')
            
    plt.title(f'Confusion Matrix — {model_name}', pad=20)
    plt.xlabel('Predicted Label')
    plt.ylabel('True Label')
    ax.set_xticklabels([''] + ['Normal', 'Attack'])
    ax.set_yticklabels([''] + ['Normal', 'Attack'])
    ax.xaxis.set_ticks_position('bottom')
    plt.tight_layout()
    plt.savefig(save_path, dpi=150)
    plt.close()

def plot_feature_importance(model, model_name, save_path="evaluation/feature_importance.png"):
    """
    Plot horizontal bar chart of feature importances.
    Only works for SupervisedDetector (has feature_importances() method).
    Skip silently for AnomalyDetector.
    """
    if not hasattr(model, 'feature_importances'):
        return
        
    importances = model.feature_importances()
    
    if not importances or not isinstance(importances, dict):
        return
        
    sorted_items = sorted(importances.items(), key=lambda x: x[1])
    features = [item[0] for item in sorted_items]
    scores = [item[1] for item in sorted_items]
    
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    plt.figure(figsize=(8, 5))
    plt.barh(features, scores, color='darkorange', alpha=0.8)
    plt.xlabel('Importance Score')
    plt.title(f'Feature Importance — {model_name}')
    plt.tight_layout()
    plt.savefig(save_path, dpi=150)
    plt.close()

def build_report_text(metrics, mttd, per_attack, model_name="Model"):
    """Helper to build the report text string."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    mttd_str = f"{mttd:.1f} min" if mttd is not None else "N/A"
    
    lines = [
        "╔" + "═"*46 + "╗",
        f"║   EVALUATION REPORT — {model_name:<22} ║",
        f"║   Timestamp: {now:<31} ║",
        "╚" + "═"*46 + "╝",
        "",
        "── Overall Metrics ─────────────────────────────",
        f"  Precision:       {metrics['precision']:.2f}   (alerts that were real attacks)",
        f"  Recall:          {metrics['recall']:.2f}   (attacks that were caught)",
        f"  F1 Score:        {metrics['f1']:.2f}",
        f"  ROC-AUC:         {metrics['roc_auc']:.2f}",
        f"  False Alarm Rate:{metrics['false_alarm_rate']:.2f}   (normal windows wrongly flagged)",
        f"  MTTD:            {mttd_str:<7} (mean time to first detection)",
        "",
        "── Confusion Matrix ────────────────────────────",
        "                Predicted Normal  Predicted Attack",
        f"  Actual Normal      {metrics['confusion_matrix'][0,0]:<4}               {metrics['confusion_matrix'][0,1]:<4}",
        f"  Actual Attack        {metrics['confusion_matrix'][1,0]:<4}               {metrics['confusion_matrix'][1,1]:<4}",
        "",
        "── Per Attack-Type Results ─────────────────────",
        "                  Precision  Recall    F1   Caught/Total"
    ]
    
    # Optional dynamic ordering, but explicit is fine per spec
    for atype in ['phishing', 'ransomware', 'insider_threat']:
        if atype in per_attack:
            res = per_attack[atype]
            line = f"  {atype:<16}  {res['precision']:.2f}       {res['recall']:.2f}      {res['f1']:.2f}  {res['caught']}/{res['total']}"
            lines.append(line)
            
    lines.append("")
    lines.append("── Files Saved ─────────────────────────────────")
    lines.append("  Report:            evaluation/report.txt")
    lines.append("  ROC curve:         evaluation/roc_comparison.png")
    lines.append("  Confusion matrix:  evaluation/confusion_matrix.png")
    lines.append("  Feature importance:evaluation/feature_importance.png\n")
    
    return "\n".join(lines)

def print_report(metrics, mttd, per_attack, model_name="Model"):
    """
    Print a full human-readable evaluation report to stdout.
    Same format as the report in train.py but more detailed —
    includes MTTD and per-attack-type precision + F1.
    """
    print(build_report_text(metrics, mttd, per_attack, model_name))

def save_report(metrics, mttd, per_attack, model_name, save_path="evaluation/report.txt"):
    """
    Save the same report as print_report() to a text file.
    Appends a timestamp so multiple runs do not overwrite.
    This file is used in Week 9 to compare before/after evasion.
    """
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    report_text = build_report_text(metrics, mttd, per_attack, model_name)
    
    with open(save_path, "a", encoding="utf-8") as f:
        f.write(report_text + "\n")

def evaluate(model_type="supervised", model_path=None, features_path="data/features.csv"):
    """
    Main entry point — runs the full evaluation pipeline:
      1. Load model
      2. Load test data
      3. Compute all metrics + MTTD
      4. Compute per-attack metrics
      5. Print report
      6. Save report to file
      7. Generate all plots

    Args:
        model_type: "supervised" or "anomaly"
        model_path: optional explicit model path
        features_path: path to features CSV
    """
    # 1. Load model
    model = load_model(model_type, model_path)
    
    # 2. Load test data
    X_test, y_test, df_feat_test = load_test_data(features_path)
    
    # 3. Compute metrics + MTTD
    metrics = compute_metrics(model, X_test, y_test, model_type)
    mttd = compute_mttd(df_feat_test, metrics['y_pred'])
    
    # 4. Compute per-attack metrics
    per_attack = per_attack_metrics(df_feat_test, y_test, metrics['y_pred'])
    
    # 5. Print report
    print_report(metrics, mttd, per_attack, model_name=model_type)
    
    # 6. Save report
    save_report(metrics, mttd, per_attack, model_name=model_type)
    
    # 7. Generate plots
    plot_confusion_matrix(metrics['confusion_matrix'], model_name=model_type)
    if model_type == "supervised":
        plot_feature_importance(model, model_name=model_type)
        
    return metrics

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate cyber attack detector models.")
    parser.add_argument("--model", type=str, default="supervised", choices=["supervised", "anomaly", "both"],
                        help="Model to evaluate: supervised, anomaly, or both.")
    parser.add_argument("--features", type=str, default="data/features.csv",
                        help="Path to the features CSV file.")
    args = parser.parse_args()

    results_dict = {}

    if args.model in ["supervised", "both"]:
        metrics = evaluate(model_type="supervised", features_path=args.features)
        results_dict["supervised"] = {
            "y_test": metrics["y_test"],
            "y_scores": metrics["y_scores"],
            "auc": metrics["roc_auc"]
        }

    if args.model in ["anomaly", "both"]:
        metrics = evaluate(model_type="anomaly", features_path=args.features)
        results_dict["anomaly"] = {
            "y_test": metrics["y_test"],
            "y_scores": metrics["y_scores"],
            "auc": metrics["roc_auc"]
        }

    plot_roc_curve(results_dict)
