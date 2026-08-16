"""
ml_threat_detector.py

Trains and evaluates two models on the UCI "Phishing Websites" dataset
(11,055 samples, 30 lexical/structural URL features, binary class
label: 1 = legitimate, -1 = phishing):

  1. A supervised Random Forest Classifier (default hyperparameters).
  2. An unsupervised Isolation Forest, treating the minority class
     (phishing) as the anomaly class.

Dataset source: UCI Machine Learning Repository, "Phishing Websites"
(Mohammad, R. & McCluskey, L., 2012, https://doi.org/10.24432/C51W2X),
mirrored as phishing.csv in this repository for reproducibility.

Usage:
    python3 ml_threat_detector.py
"""

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import (
    classification_report,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
)

DATA_PATH = "phishing.csv"
LABEL_COL = "class"


def load_and_preprocess():
    df = pd.read_csv(DATA_PATH)

    print("First five rows:")
    print(df.head())
    print()

    print("Class distribution (1 = legitimate, -1 = phishing):")
    print(df[LABEL_COL].value_counts())
    print()

    before = len(df)
    df = df.dropna()
    dropped_na = before - len(df)

    before = len(df)
    df = df.drop_duplicates()
    dropped_dupes = before - len(df)

    print(f"Rows dropped for nulls: {dropped_na}")
    print(f"Duplicate rows dropped: {dropped_dupes}")
    print(f"Remaining rows: {len(df)}")
    print()

    # All 30 feature columns in this dataset are already integer-encoded
    # (-1 / 0 / 1), so no categorical encoding step is needed beyond
    # dropping the leading Index column, which carries no signal.
    if "Index" in df.columns:
        df = df.drop(columns=["Index"])

    return df


def run_random_forest(X_train, X_test, y_train, y_test):
    clf = RandomForestClassifier(random_state=42)
    clf.fit(X_train, y_train)
    preds = clf.predict(X_test)

    print("Random Forest — classification_report on the test set:")
    print(classification_report(y_test, preds, target_names=["phishing (-1)", "legitimate (1)"]))

    return {
        "accuracy": accuracy_score(y_test, preds),
        "precision": precision_score(y_test, preds, pos_label=1),
        "recall": recall_score(y_test, preds, pos_label=1),
        "f1": f1_score(y_test, preds, pos_label=1),
    }


def run_isolation_forest(X_train, X_test, y_train, y_test):
    # Isolation Forest is trained unsupervised (it never sees y_train),
    # then we compare its -1/1 anomaly output against the true labels
    # purely for evaluation. contamination is set to the minority
    # class's observed proportion in the training set so the model's
    # expected anomaly rate roughly matches the real phishing rate.
    contamination = (y_train == -1).mean()
    iso = IsolationForest(random_state=42, contamination=contamination)
    iso.fit(X_train)

    # IsolationForest.predict returns 1 for inliers ("normal") and -1
    # for outliers ("anomaly") — this happens to match our label
    # convention (1 = legitimate, -1 = phishing) directly.
    preds = iso.predict(X_test)

    return {
        "accuracy": accuracy_score(y_test, preds),
        "precision": precision_score(y_test, preds, pos_label=1),
        "recall": recall_score(y_test, preds, pos_label=1),
        "f1": f1_score(y_test, preds, pos_label=1),
    }


def main():
    df = load_and_preprocess()

    X = df.drop(columns=[LABEL_COL])
    y = df[LABEL_COL]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    rf_metrics = run_random_forest(X_train, X_test, y_train, y_test)
    iso_metrics = run_isolation_forest(X_train, X_test, y_train, y_test)

    print("\nModel comparison:")
    print(f"{'Model':<20}{'Accuracy':<12}{'Precision':<12}{'Recall':<12}{'F1 Score':<12}")
    print(f"{'Random Forest':<20}{rf_metrics['accuracy']:<12.4f}{rf_metrics['precision']:<12.4f}"
          f"{rf_metrics['recall']:<12.4f}{rf_metrics['f1']:<12.4f}")
    print(f"{'Isolation Forest':<20}{iso_metrics['accuracy']:<12.4f}{iso_metrics['precision']:<12.4f}"
          f"{iso_metrics['recall']:<12.4f}{iso_metrics['f1']:<12.4f}")


if __name__ == "__main__":
    main()
