import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, accuracy_score
import time

# Step 2: Define columns manually
columns = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent',
    'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root',
    'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login',
    'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
    'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'target'
]

# Step 3: Load dataset
# Ensure the dataset is comma-separated
df = pd.read_csv(r"C:\Users\HP\Desktop\KDDTrain+.txt", names=columns, sep=',')  # Use sep=',' for CSV format

print("✅ Dataset loaded successfully!")
print(df.head())  # Check the first few rows of the dataset

# Step 4: Preprocessing
# Handle missing values in the target column (if any)
df['target'] = df['target'].apply(lambda x: 1 if x == 'normal' else 0)  # Convert target to binary (1 = normal, 0 = attack)

# Check for NaN values and drop them
print("NaN values in the dataset before cleaning:")
print(df.isnull().sum())

# Drop rows with NaN values (if any)
df = df.dropna()

# One-hot encode categorical columns
df = pd.get_dummies(df)

# Check the shape of the dataframe
print(f"Shape of dataset after preprocessing: {df.shape}")

# Features and labels
X = df.drop(['target'], axis=1)  # Features (drop target column)
y = df['target']                 # Labels: 1=normal, 0=attack

# Check the shape of X and y
print(f"Shape of X: {X.shape}, Shape of y: {y.shape}")

# Step 5: Train-test split
if X.shape[0] > 0:
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
else:
    print("Error: No samples found in the dataset after preprocessing.")
    exit()

# ========================
# 🧠 AI-Driven Detection (Isolation Forest)
# ========================
print("\n🔵 AI-Driven Detection (Isolation Forest)")

# Train Isolation Forest
iso_forest = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
iso_forest.fit(X_train)

# Predict
y_pred_ai = iso_forest.predict(X_test)
y_pred_ai = np.where(y_pred_ai == 1, 1, 0)

# Evaluate AI model
acc_ai = accuracy_score(y_test, y_pred_ai)
tn, fp, fn, tp = confusion_matrix(y_test, y_pred_ai).ravel()
fpr_ai = fp / (fp + tn)
pdr_ai = tp / (tp + fn)

print(f"Threat Detection Accuracy: {acc_ai*100:.2f}%")
print(f"False Positive Rate: {fpr_ai*100:.2f}%")
print(f"Penetration Detection Rate: {pdr_ai*100:.2f}%")

# MTTD Simulation
start_time = time.time()
iso_forest.predict([X_test.iloc[0]])
end_time = time.time()
print(f"Simulated Mean Time to Detect (MTTD): {(end_time - start_time)*1000:.2f} ms")

# Simulate Incident Response
def simulate_incident_response():
    print("\n[Incident Detected] Executing automated response...")
    time.sleep(1)
    print("[Response Completed] Instance isolated, keys revoked, alert sent.")

simulate_incident_response()

# ========================
# 🛡 Traditional Rule-Based Detection
# ========================
print("\n🟢 Traditional Rule-Based Detection")

# Define manual rule detector
def rule_based_detector(X):
    preds = []
    for _, row in X.iterrows():
        if row['src_bytes'] > 10000 or row['wrong_fragment'] > 0:
            preds.append(0)  # Attack
        else:
            preds.append(1)  # Normal
    return np.array(preds)

# Predict using manual rules
y_pred_rule = rule_based_detector(X_test)

# Evaluate rule-based system
acc_rule = accuracy_score(y_test, y_pred_rule)
tn, fp, fn, tp = confusion_matrix(y_test, y_pred_rule).ravel()
fpr_rule = fp / (fp + tn)
pdr_rule = tp / (tp + fn)

print(f"Threat Detection Accuracy: {acc_rule*100:.2f}%")
print(f"False Positive Rate: {fpr_rule*100:.2f}%")
print(f"Penetration Detection Rate: {pdr_rule*100:.2f}%")

# ========================
# 📊 Comparison Summary
# ========================
print("\n📊 Final Comparison Summary")
print(f"🔵 AI-Driven (Isolation Forest):")
print(f"  - Accuracy: {acc_ai*100:.2f}%")
print(f"  - False Positive Rate: {fpr_ai*100:.2f}%")
print(f"  - Penetration Detection Rate: {pdr_ai*100:.2f}%")

print(f"\n🟢 Traditional Rule-Based:")
print(f"  - Accuracy: {acc_rule*100:.2f}%")
print(f"  - False Positive Rate: {fpr_rule*100:.2f}%")
print(f"  - Penetration Detection Rate: {pdr_rule*100:.2f}%")
