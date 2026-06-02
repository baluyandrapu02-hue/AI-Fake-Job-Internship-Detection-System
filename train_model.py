import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

# Load dataset
data = pd.read_csv("dataset/fake_job_postings.csv")

# Select useful columns
data = data[["title", "description", "fraudulent"]]

# Remove empty rows
data = data.dropna()

# Combine title + description
data["text"] = data["title"] + " " + data["description"]

X = data["text"]
Y = data["fraudulent"]

# Convert text into numbers
vectorizer = TfidfVectorizer(max_features=5000)
X = vectorizer.fit_transform(X)

# Train/Test split
X_train, X_test, Y_train, Y_test = train_test_split(
    X,
    Y,
    test_size=0.2,
    random_state=42
)

# Train model
model = LogisticRegression()
model.fit(X_train, Y_train)

print("AI Model Trained Successfully ✅")

# Test with sample job
sample_job = [
    "Work from home job. Earn 50000 per week. No interview required. Registration fee required. Immediate joining."
]

sample_vector = vectorizer.transform(sample_job)

prediction = model.predict(sample_vector)[0]
confidence = model.predict_proba(sample_vector).max() * 100

if prediction == 1:
    print("Prediction: Fake Job / High Risk ❌")
else:
    print("Prediction: Real Job / Low Risk ✅")

print(f"Confidence: {confidence:.2f}%")