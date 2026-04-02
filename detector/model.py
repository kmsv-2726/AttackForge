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

    def __init__(self,
                 contamination=0.01,
                 n_estimators=200,      # was 100 — more trees = better boundary
                 max_samples=0.8,       # was 'auto' — subsample 80% per tree
                 max_features=0.8,      # was 1.0 — use 80% of features per tree
                 random_state=42):
        """
        Isolation Forest anomaly detector with tuned hyperparameters.

        n_estimators=200: more trees give a smoother anomaly boundary,
          especially important when attack examples are sparse.

        max_samples=0.8: each tree trains on 80% of data, reducing
          overfitting to the dominant normal class.

        max_features=0.8: each tree sees 80% of features, making the
          ensemble more robust to noisy features like login_count
          which barely differs between normal and attack.
        """
        from sklearn.ensemble import IsolationForest
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            max_samples=max_samples,
            max_features=max_features,
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
