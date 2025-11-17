import pandas as pd
import numpy as np
import os
import joblib
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier, VotingClassifier, StackingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, roc_curve, accuracy_score
from sklearn.utils import resample
from sklearn.decomposition import PCA
import matplotlib.pyplot as plt
import xgboost as xgb
import warnings
warnings.filterwarnings('ignore')

# 1. Load data
# --------------
df = pd.read_csv('data/batch_results/tor_nontor_merged_features.csv')
df.columns = df.columns.str.strip()

FEATURE_COLUMNS = [
    'Source Port', 'Destination Port', 'Protocol', 'Flow Duration', 'Flow Bytes/s',
    'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
    'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
    'Active Mean', 'Active Std', 'Active Max', 'Active Min',
    'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
]

missing_cols = [c for c in FEATURE_COLUMNS if c not in df.columns]
if missing_cols:
    raise Exception(f"Missing required features in input data: {missing_cols}")
df = df[FEATURE_COLUMNS + ['label']]

# 2. Clean, label
# -------------------
df['label'] = df['label'].astype(str).str.lower().str.strip()
df['label'] = df['label'].apply(lambda x: 'tor' if x == 'tor' else 'nontor')
for col in FEATURE_COLUMNS:
    df[col] = df[col].replace([np.inf, -np.inf], np.nan)
    median = df[col].median()
    df[col] = df[col].fillna(median)

# 3. Balance classes
# ---------------------
majority = df[df['label'] == 'tor']
minority = df[df['label'] == 'nontor']
if len(majority) > len(minority):
    majority_bal = resample(majority, replace=False, n_samples=len(minority), random_state=42)
    df_bal = pd.concat([majority_bal, minority]).sample(frac=1, random_state=42).reset_index(drop=True)
else:
    df_bal = df.copy()
print("="*70)
print("Balanced label distribution:\n", df_bal['label'].value_counts())
print("="*70)

X = df_bal[FEATURE_COLUMNS]
y = df_bal['label']
y_bin = y.map({'tor': 1, 'nontor': 0})

# 4. Train-Test Split
# -------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
y_train_bin = y_train.map({'tor': 1, 'nontor': 0})
y_test_bin = y_test.map({'tor': 1, 'nontor': 0})

# 5. RandomForest: Hyperparameter Tuning + Feature Importance
# ----------------------------------------------------------
print("\n[1/6] Training RandomForest with GridSearch...")
param_grid = {
    'n_estimators': [100, 200],
    'max_depth': [10, 20, None],
    'min_samples_split': [2, 5],
    'min_samples_leaf': [1, 2],
}
gs_rf = GridSearchCV(RandomForestClassifier(random_state=42, class_weight='balanced'),
                     param_grid, cv=3, n_jobs=-1, scoring='roc_auc', verbose=0)
gs_rf.fit(X_train, y_train)
best_rf = gs_rf.best_estimator_
print("✓ Best RF Parameters:", gs_rf.best_params_)

feat_imp = pd.Series(best_rf.feature_importances_, index=FEATURE_COLUMNS).sort_values(ascending=False)
plt.figure(figsize=(12, 6))
feat_imp.plot(kind='bar')
plt.title('Random Forest Feature Importances')
plt.tight_layout()
plt.savefig('data/batch_results/feature_importances.png', dpi=120)
plt.close()
print('✓ Top 10 features:')
print(feat_imp.head(10))

# 6. DecisionTreeClassifier
# ----------------------
print("\n[2/6] Training DecisionTree...")
dt_params = {'max_depth': [5, 10, 15]}
gs_dt = GridSearchCV(DecisionTreeClassifier(random_state=42), dt_params, cv=3, n_jobs=-1, scoring='roc_auc', verbose=0)
gs_dt.fit(X_train, y_train)
best_dt = gs_dt.best_estimator_
print("✓ Best DT Parameters:", gs_dt.best_params_)

# 7. XGBoost (Base)
# -----------------------------------------------------
print("\n[3/6] Training XGBoost (Base)...")
xgb_params = {
    'n_estimators': [100, 200],
    'max_depth': [10, 20],
    'learning_rate': [0.1, 0.3]
}
gs_xgb = GridSearchCV(xgb.XGBClassifier(eval_metric='auc', random_state=42),
                      xgb_params, cv=3, n_jobs=-1, scoring='roc_auc', verbose=0)
gs_xgb.fit(X_train, y_train_bin)
best_xgb = gs_xgb.best_estimator_
print("✓ Best XGB Parameters:", gs_xgb.best_params_)

# 8. Advanced XGBoost (More Tuning)
# ----------------------------------
print("\n[4/6] Training Advanced XGBoost...")
xgb_params_advanced = {
    'n_estimators': [200, 300],
    'max_depth': [10, 12, 15],
    'learning_rate': [0.05, 0.1],
    'subsample': [0.8, 0.9],
    'colsample_bytree': [0.8, 0.9],
    'min_child_weight': [1, 3]
}
gs_xgb_adv = GridSearchCV(
    xgb.XGBClassifier(eval_metric='auc', random_state=42),
    xgb_params_advanced,
    cv=3,
    n_jobs=-1,
    scoring='roc_auc',
    verbose=0
)
gs_xgb_adv.fit(X_train, y_train_bin)
best_xgb_adv = gs_xgb_adv.best_estimator_
print("✓ Best Advanced XGB Parameters:", gs_xgb_adv.best_params_)

# 9. ENSEMBLE METHOD 1: Voting Classifier
# ----------------------------------------
print("\n[5/6] Training Voting Classifier (Soft Voting)...")
voting_clf = VotingClassifier(
    estimators=[
        ('rf', best_rf),
        ('xgb_adv', best_xgb_adv),
        ('dt', best_dt)
    ],
    voting='soft',
    weights=[2, 3, 1]  # More weight to advanced XGBoost
)
voting_clf.fit(X_train, y_train)
print("✓ Voting Classifier trained")

# 10. ENSEMBLE METHOD 2: Stacking Classifier
# -------------------------------------------
print("\n[6/6] Training Stacking Classifier (Meta-Learning)...")
stacking_clf = StackingClassifier(
    estimators=[
        ('rf', best_rf),
        ('xgb_adv', best_xgb_adv),
        ('dt', best_dt)
    ],
    final_estimator=LogisticRegression(max_iter=1000),
    cv=5,
    passthrough=False  # Only use meta-features
)
stacking_clf.fit(X_train, y_train)
print("✓ Stacking Classifier trained")

# 11. Evaluation Function
# -----------------------
def model_eval(name, model, X_test, y_test, y_test_bin, use_bin_for_predict=False):
    """Evaluate model and return metrics"""
    y_prob = model.predict_proba(X_test)[:, 1]
    y_pred = model.predict(X_test)
    
    # Handle binary vs string labels
    if use_bin_for_predict:
        acc = accuracy_score(y_test_bin, y_pred)
        report = classification_report(y_test_bin, y_pred, target_names=['nontor', 'tor'], digits=4)
    else:
        acc = accuracy_score(y_test, y_pred)
        report = classification_report(y_test, y_pred, digits=4)
    
    roc_auc = roc_auc_score(y_test_bin, y_prob)
    
    print(f'\n--- {name} ---')
    print(report)
    print(f'Accuracy: {acc:.4f}')
    print(f'ROC-AUC: {roc_auc:.4f}')
    
    # ROC Curve
    fpr, tpr, _ = roc_curve(y_test_bin, y_prob)
    plt.figure(figsize=(6, 5))
    plt.plot(fpr, tpr, label=f'ROC-AUC = {roc_auc:.2f}', linewidth=2)
    plt.plot([0, 1], [0, 1], 'k--', linewidth=1)
    plt.xlabel('False Positive Rate', fontsize=11)
    plt.ylabel('True Positive Rate', fontsize=11)
    plt.title(f'ROC Curve - {name}', fontsize=12, fontweight='bold')
    plt.legend(fontsize=10)
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    fname = f'data/batch_results/roc_{name.replace(" ", "_")}.png'
    plt.savefig(fname, dpi=120)
    plt.close()
    
    return acc, roc_auc

# 12. Evaluate All Models
# -----------------------
print("\n" + "="*70)
print("EVALUATING ALL MODELS")
print("="*70)

results = []

# Base Models
acc_rf, auc_rf = model_eval('RandomForest', best_rf, X_test, y_test, y_test_bin)
results.append({'Model': 'RandomForest (Base)', 'Accuracy': acc_rf, 'ROC-AUC': auc_rf})

acc_dt, auc_dt = model_eval('DecisionTree', best_dt, X_test, y_test, y_test_bin)
results.append({'Model': 'DecisionTree (Base)', 'Accuracy': acc_dt, 'ROC-AUC': auc_dt})

acc_xgb, auc_xgb = model_eval('XGBoost_Base', best_xgb, X_test, y_test, y_test_bin, use_bin_for_predict=True)
results.append({'Model': 'XGBoost (Base)', 'Accuracy': acc_xgb, 'ROC-AUC': auc_xgb})

# Advanced Models
acc_xgb_adv, auc_xgb_adv = model_eval('XGBoost_Advanced', best_xgb_adv, X_test, y_test, y_test_bin, use_bin_for_predict=True)
results.append({'Model': 'XGBoost (Advanced)', 'Accuracy': acc_xgb_adv, 'ROC-AUC': auc_xgb_adv})

# Ensemble Models
acc_vote, auc_vote = model_eval('Voting_Ensemble', voting_clf, X_test, y_test, y_test_bin)
results.append({'Model': 'Voting Ensemble', 'Accuracy': acc_vote, 'ROC-AUC': auc_vote})

acc_stack, auc_stack = model_eval('Stacking_Ensemble', stacking_clf, X_test, y_test, y_test_bin)
results.append({'Model': 'Stacking Ensemble', 'Accuracy': acc_stack, 'ROC-AUC': auc_stack})

# 13. Top-N Features Model
# ------------------------
TOP_N = 10
best_features = feat_imp.head(TOP_N).index.tolist()
print(f'\n✓ Best {TOP_N} features: {best_features}')
X_train_best = X_train[best_features]
X_test_best = X_test[best_features]
rfs_top = RandomForestClassifier(
    n_estimators=gs_rf.best_params_['n_estimators'],
    max_depth=gs_rf.best_params_['max_depth'],
    min_samples_split=gs_rf.best_params_['min_samples_split'],
    min_samples_leaf=gs_rf.best_params_['min_samples_leaf'],
    random_state=42,
    class_weight='balanced'
)
rfs_top.fit(X_train_best, y_train)
acc_rf_top, auc_rf_top = model_eval(f'RF_Top{TOP_N}', rfs_top, X_test_best, y_test, y_test_bin)
results.append({'Model': f'RF Top-{TOP_N} Features', 'Accuracy': acc_rf_top, 'ROC-AUC': auc_rf_top})

# 14. Results Summary Table
# -------------------------
print("\n" + "="*70)
print("FINAL RESULTS - ALL MODELS COMPARISON")
print("="*70)

results_df = pd.DataFrame(results)
results_df = results_df.sort_values('Accuracy', ascending=False).reset_index(drop=True)
results_df['Accuracy %'] = (results_df['Accuracy'] * 100).round(2)
print(results_df[['Model', 'Accuracy %', 'ROC-AUC']].to_string(index=False))

# Highlight best model
best_model_name = results_df.iloc[0]['Model']
best_acc = results_df.iloc[0]['Accuracy %']
best_auc = results_df.iloc[0]['ROC-AUC']

print("\n" + "="*70)
print(f" BEST MODEL: {best_model_name}")
print(f"   Accuracy: {best_acc:.2f}%")
print(f"   ROC-AUC: {best_auc:.4f}")
print("="*70)

# 15. Save All Models
# -------------------
joblib.dump(best_rf, 'tor_detection_model_RF.pkl')
joblib.dump(best_dt, 'tor_detection_model_DT.pkl')
joblib.dump(best_xgb, 'tor_detection_model_XGB.pkl')
joblib.dump(best_xgb_adv, 'tor_detection_model_XGB_ADVANCED.pkl')
joblib.dump(voting_clf, 'tor_detection_model_VOTING.pkl')
joblib.dump(stacking_clf, 'tor_detection_model_STACKING.pkl')
joblib.dump(rfs_top, 'tor_detection_model_RF_TOP.pkl')

# Save the best model as tor_detection_model.pkl
joblib.dump(best_xgb_adv, 'tor_detection_model.pkl')

with open('data/batch_results/best_features.txt', 'w') as f:
    f.write('\n'.join(best_features))

# Save results table
results_df.to_csv('data/batch_results/model_comparison.csv', index=False)

print('\n✓ All models saved successfully!')
print('✓ Results saved to: data/batch_results/model_comparison.csv')
print('✓ ROC curves saved to: data/batch_results/roc_*.png')
print('✓ Feature importance saved to: data/batch_results/feature_importances.png')
