import os
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report

DATASET_PATH = "dataset/fake_job_postings.csv"
MODEL_PATH = "model.pkl"
VECTORIZER_PATH = "vectorizer.pkl"

data = pd.read_csv(DATASET_PATH)

required_columns = ["title", "description", "fraudulent"]
for col in required_columns:
    if col not in data.columns:
        raise ValueError(f"Missing required column: {col}")

data = data[required_columns].dropna()

data["text"] = data["title"].astype(str) + " " + data["description"].astype(str)

X = data["text"]
y = data["fraudulent"]

vectorizer = TfidfVectorizer(
    max_features=7000,
    stop_words="english",
    lowercase=True
)

X_vectorized = vectorizer.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(
    X_vectorized,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

model = LogisticRegression(
    max_iter=1000,
    class_weight="balanced"
)

model.fit(X_train, y_train)

y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)

print("AI Model Trained Successfully ✅")
print(f"Accuracy: {accuracy * 100:.2f}%")
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

joblib.dump(model, MODEL_PATH)
joblib.dump(vectorizer, VECTORIZER_PATH)

print(f"\nModel saved as: {MODEL_PATH}")
print(f"Vectorizer saved as: {VECTORIZER_PATH}")

sample_job = [
    "Work from home job. Earn 50000 per week. No interview required. Registration fee required. Immediate joining."
]

sample_vector = vectorizer.transform(sample_job)
prediction = model.predict(sample_vector)[0]
confidence = model.predict_proba(sample_vector).max() * 100

print("\nSample Test:")
if prediction == 1:
    print("Prediction: High Risk — Verify Manually")
else:
    print("Prediction: Low Risk")

print(f"Confidence: {confidence:.2f}%")