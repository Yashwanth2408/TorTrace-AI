import pandas as pd
import numpy as np
import os
import json
import joblib
from sklearn.model_selection import train_test_split, GridSearchCV, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, roc_curve
from sklearn.utils import resample
import matplotlib.pyplot as plt

def main():
    # 1. Load and concat datasets (A+B for broad eval; just Scenario-A for focused)
    csv_a = 'data/batch_results/Scenario-A-merged_5s.csv'
    csv_b = 'data/batch_results/Scenario-B-merged_5s.csv'
    df_a = pd.read_csv(csv_a)
    df_b = pd.read_csv(csv_b)
    df_a.columns = df_a.columns.str.strip()
    df_b.columns = df_b.columns.str.strip()
    # Use both for broad, or just scenario A for focused test
    df = pd.concat([df_a, df_b], ignore_index=True)  # Or just use df = df_a
    print("Label distribution (original):")
    df['label'] = df['label'].astype(str).str.lower().str.strip()
    print(df['label'].value_counts())
    # Binary label: 1 = tor, 0 = nontor or any other
    df['label_simple'] = df['label'].apply(lambda x: 1 if 'tor' in x else 0)
    print("Tor/nonTor class balance:", df['label_simple'].value_counts())
    drop_cols = ['label', 'label_simple', 'Source IP', 'Destination IP']
    df_num = df.drop(columns=[col for col in drop_cols if col in df.columns])
    X = df_num.select_dtypes(include=['number']).copy()
    y = df['label_simple']
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    is_finite = np.isfinite(X).all(axis=1)
    X = X[is_finite]
    y = y[is_finite]
    X = X.fillna(0)
    print("Final usable samples:", len(X))

    # 2. Stratified train-test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, stratify=y, test_size=0.2, random_state=42)

    # 3. Downsample only training majority class for balance
    train_data = X_train.copy()
    train_data['label_simple'] = y_train
    tor = train_data[train_data['label_simple'] == 1]
    nontor = train_data[train_data['label_simple'] == 0]
    if len(tor) > len(nontor):
        tor_downsampled = resample(tor, replace=False, n_samples=len(nontor), random_state=42)
        train_balanced = pd.concat([tor_downsampled, nontor])
    else:
        nontor_downsampled = resample(nontor, replace=False, n_samples=len(tor), random_state=42)
        train_balanced = pd.concat([tor, nontor_downsampled])
    X_train_bal = train_balanced.drop(columns=['label_simple'])
    y_train_bal = train_balanced['label_simple']
    print(f"Balanced training set shape: {X_train_bal.shape}, TOR:{sum(y_train_bal == 1)}, nonTOR:{sum(y_train_bal == 0)}")

    # 4. Hyperparameter tuning (RandomForest)
    param_grid = {
        'n_estimators': [100, 200],
        'max_depth': [10, 20, None],
        'min_samples_split': [2, 5],
        'min_samples_leaf': [1, 2]
    }
    grid_search = GridSearchCV(RandomForestClassifier(random_state=42, n_jobs=-1),
                               param_grid, cv=3, scoring='roc_auc', n_jobs=-1)
    grid_search.fit(X_train_bal, y_train_bal)
    clf = grid_search.best_estimator_
    print("Best parameters:", grid_search.best_params_)

    # 5. Cross-validation
    cv_scores = cross_val_score(clf, X_train_bal, y_train_bal, cv=5, scoring='roc_auc')
    print("Cross-validation ROC-AUC scores:", cv_scores)
    print("Mean CV ROC-AUC:", cv_scores.mean())

    # 6. Train and predict
    clf.fit(X_train_bal, y_train_bal)
    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]

    # 7. Evaluation
    print("\nClassification Report:\n", classification_report(y_test, y_pred, digits=4))
    print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))
    print("ROC-AUC: %.4f" % roc_auc_score(y_test, y_proba))

    # 8. Feature Importances
    importances = clf.feature_importances_
    feat_list = list(X_train_bal.columns)
    top_feats = sorted(zip(importances, feat_list), reverse=True)[:15]
    print("\nTop 15 Features:")
    for score, fname in top_feats:
        print(f"{fname}: {score:.5f}")
    print("\nModel expects these features (in order):")
    print(X_train_bal.columns.tolist())

    # 9. Feature Selection (top 10 features)
    top_feature_names = [fname for _, fname in top_feats[:10]]
    X_train_selected = X_train_bal[top_feature_names]
    X_test_selected = X_test[top_feature_names]
    clf_selected = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    clf_selected.fit(X_train_selected, y_train_bal)
    y_pred_selected = clf_selected.predict(X_test_selected)
    y_proba_selected = clf_selected.predict_proba(X_test_selected)[:, 1]
    print("\nSelected Features Classification Report:")
    print(classification_report(y_test, y_pred_selected, digits=4))
    print("Selected Features ROC-AUC:", roc_auc_score(y_test, y_proba_selected))

    # 10. ROC Curve Plot
    out_dir = "data/batch_results"
    os.makedirs(out_dir, exist_ok=True)
    fpr, tpr, _ = roc_curve(y_test, y_proba)
    plt.figure()
    plt.plot(fpr, tpr, label="ROC (area = %.2f)" % roc_auc_score(y_test, y_proba))
    plt.plot([0, 1], [0, 1], 'k--')
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("ROC Curve")
    plt.legend(loc="lower right")
    plt.grid(True, linestyle='--', linewidth=0.5)
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, "roc_curve_balanced.png"), dpi=150)
    plt.close()
    print(f"ROC curve saved as {os.path.join(out_dir, 'roc_curve_balanced.png')}")

    # 11. Export metrics to JSON
    results = {
        "classification_report": classification_report(y_test, y_pred, output_dict=True, digits=4),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "roc_auc": roc_auc_score(y_test, y_proba),
        "top_features": [{"feature": fname, "importance": score} for score, fname in top_feats],
        "cv_scores": cv_scores.tolist(),
        "best_params": grid_search.best_params_
    }
    with open(os.path.join(out_dir, "evaluation_results.json"), "w") as f:
        json.dump(results, f, indent=2)
    print(f"Metrics saved to {os.path.join(out_dir, 'evaluation_results.json')}")

    # 12. Save model
    joblib.dump(clf, os.path.join(out_dir, "tor_detection_model.pkl"))
    print(f"Model saved to {os.path.join(out_dir, 'tor_detection_model.pkl')}")

    print("Done.")

if __name__ == '__main__':
    main()
