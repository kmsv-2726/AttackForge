import os
import joblib
from sklearn.ensemble import IsolationForest

class AnomalyDetector:
    """
    Unsupervised anomaly detector using Isolation Forest.

    How it works:
        Trains ONLY on normal (label=0) windows.
        Learns what normal behaviour looks like.
        At inference time, scores any window — the further from
        normal, the higher the anomaly score.
        Flags windows with score below a threshold as attacks.

    Why Isolation Forest:
        Works well on tabular data with many features.
        Does not need attack examples to train.
        Fast to train and interpret.
        Built into scikit-learn.
    """

    def __init__(self, contamination=0.02, n_estimators=100, random_state=42):
        """
        Args:
            contamination: expected fraction of anomalies in data
                           Set to ~0.02 matching our ~2% attack rate.
            n_estimators:  number of trees in the forest.
            random_state:  for reproducibility.
        """
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=random_state
        )

    def fit(self, X_normal):
        """
        Train the model on NORMAL windows only.
        X_normal: numpy array of feature vectors, all label=0.
        """
        self.model.fit(X_normal)

    def predict(self, X):
        """
        Predict whether each window is normal or anomalous.
        Returns array: 1 = attack detected, 0 = normal.
        Note: sklearn IsolationForest returns -1 for anomaly,
              1 for normal — convert to our 0/1 convention.
        """
        preds = self.model.predict(X)
        # Convert sklearn output to match our labels:
        # -1 (anomaly) -> 1 (attack)
        # 1 (normal) -> 0 (normal)
        return (preds == -1).astype(int)

    def score_samples(self, X):
        """
        Return raw anomaly scores for each window.
        Lower score = more anomalous.
        Used for ROC-AUC calculation.
        """
        return self.model.score_samples(X)

    def save(self, path="models/anomaly_detector.pkl"):
        """Save the trained model to disk using joblib."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump(self.model, path)

    def load(self, path="models/anomaly_detector.pkl"):
        """Load a saved model from disk."""
        self.model = joblib.load(path)
