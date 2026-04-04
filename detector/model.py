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

class SupervisedDetector:
    """
    Supervised attack classifier using Random Forest.

    How it works:
        Trains on BOTH normal (label=0) AND attack (label=1) windows.
        Learns the specific patterns that distinguish each attack type.
        At inference time, outputs a probability that a window is
        an attack — higher probability = more confident it is an attack.

    Why Random Forest:
        Handles imbalanced classes well (we have ~98% normal, ~2% attack).
        Gives feature importance scores — tells us WHICH features
        matter most for detecting each attack type.
        Robust to outliers and noisy features.
        No assumptions about feature distributions (unlike logistic regression).
        Built into scikit-learn, fast to train.

    Why this beats Isolation Forest:
        It has seen attack examples. It knows what AUTH_FAIL spikes,
        file encryption bursts, and after-hours access look like.
        Isolation Forest had to guess. This model knows.
    """

    def __init__(self, n_estimators=200, max_depth=None,
                 class_weight='balanced', random_state=42):
        """
        Args:
            n_estimators:  number of trees. 200 gives stable results.
            max_depth:     None = grow full trees. Captures complex patterns.
            class_weight:  'balanced' automatically weights the minority
                           class (attacks) higher to compensate for
                           the ~98/2 normal/attack imbalance.
            random_state:  for reproducibility.
        """
        from sklearn.ensemble import RandomForestClassifier
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            class_weight=class_weight,
            random_state=random_state
        )
        self.feature_names = None

    def fit(self, X_train, y_train, feature_names=None):
        """
        Train on labeled data — both normal and attack windows.
        X_train: feature matrix (all rows, normal and attack)
        y_train: labels (0=normal, 1=attack)
        feature_names: list of feature column names for importance plot
        """
        self.feature_names = feature_names
        self.model.fit(X_train, y_train)

    def predict(self, X):
        """
        Predict 0 (normal) or 1 (attack) for each window.
        """
        return self.model.predict(X)

    def predict_proba(self, X):
        """
        Return attack probability for each window (0.0 to 1.0).
        Used for ROC-AUC calculation and threshold tuning.
        Returns the probability of class 1 (attack).
        """
        return self.model.predict_proba(X)[:, 1]

    def feature_importances(self):
        """
        Return a dict of {feature_name: importance_score}.
        Higher score = more useful for detecting attacks.
        """
        if self.feature_names is None:
            return dict(enumerate(self.model.feature_importances_))
        return dict(zip(self.feature_names, self.model.feature_importances_))

    def save(self, path="models/supervised_detector.pkl"):
        """Save the trained model to disk using joblib."""
        import joblib, os
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump(self, path)

    def load(self, path="models/supervised_detector.pkl"):
        """Load a saved model from disk."""
        import joblib
        loaded = joblib.load(path)
        self.model = loaded.model
        self.feature_names = loaded.feature_names
