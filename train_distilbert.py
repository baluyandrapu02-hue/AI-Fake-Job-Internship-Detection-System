import pandas as pd
import torch

from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
from datasets import Dataset
from transformers import (
    DistilBertTokenizer,
    DistilBertForSequenceClassification,
    Trainer,
    TrainingArguments,
)

DATASET_PATH = "dataset/fake_job_postings.csv"
MODEL_SAVE_PATH = "distilbert_fake_job_model"

print("Loading dataset...")
data = pd.read_csv(DATASET_PATH)

data = data[["title", "description", "fraudulent"]].dropna()
data["text"] = data["title"].astype(str) + " " + data["description"].astype(str)
data = data[["text", "fraudulent"]].rename(columns={"fraudulent": "label"})

# Keep test data natural/imbalanced
train_df, test_df = train_test_split(
    data,
    test_size=0.2,
    random_state=42,
    stratify=data["label"],
)

# Balance only training data
real_train = train_df[train_df["label"] == 0]
fake_train = train_df[train_df["label"] == 1]

real_sample = real_train.sample(n=min(4000, len(real_train)), random_state=42)
fake_sample = fake_train.sample(n=min(4000, len(real_sample)), replace=True, random_state=42)

train_df = pd.concat([real_sample, fake_sample]).sample(frac=1, random_state=42)

# Keep test smaller for faster evaluation
test_df = test_df.sample(n=min(1000, len(test_df)), random_state=42)

print("Train size:", len(train_df))
print("Test size:", len(test_df))
print("Train real jobs:", (train_df["label"] == 0).sum())
print("Train fake jobs:", (train_df["label"] == 1).sum())

tokenizer = DistilBertTokenizer.from_pretrained("distilbert-base-uncased")


def tokenize_function(examples):
    return tokenizer(
        examples["text"],
        truncation=True,
        padding="max_length",
        max_length=128,
    )


train_dataset = Dataset.from_pandas(train_df.reset_index(drop=True))
test_dataset = Dataset.from_pandas(test_df.reset_index(drop=True))

train_dataset = train_dataset.map(tokenize_function, batched=True)
test_dataset = test_dataset.map(tokenize_function, batched=True)

train_dataset = train_dataset.remove_columns(["text"])
test_dataset = test_dataset.remove_columns(["text"])

train_dataset.set_format("torch")
test_dataset.set_format("torch")

model = DistilBertForSequenceClassification.from_pretrained(
    "distilbert-base-uncased",
    num_labels=2,
)

training_args = TrainingArguments(
    output_dir="./distilbert_results",
    eval_strategy="epoch",
    save_strategy="no",
    learning_rate=2e-5,
    per_device_train_batch_size=8,
    per_device_eval_batch_size=8,
    num_train_epochs=2,
    weight_decay=0.01,
    logging_dir="./distilbert_logs",
    logging_steps=50,
    report_to="none"
)

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_dataset,
    eval_dataset=test_dataset,
)

print("Starting DistilBERT training...")
trainer.train()

print("Evaluating model...")
predictions = trainer.predict(test_dataset)

y_true = predictions.label_ids
y_pred = predictions.predictions.argmax(axis=1)

probs = torch.softmax(torch.tensor(predictions.predictions), dim=1).numpy()[:, 1]

print("\nClassification Report:")
print(classification_report(y_true, y_pred, target_names=["Real Job", "Fake Job"]))

print("ROC-AUC Score:", roc_auc_score(y_true, probs))

print("Saving model...")
model.save_pretrained(MODEL_SAVE_PATH)
tokenizer.save_pretrained(MODEL_SAVE_PATH)

print(f"DistilBERT model saved to: {MODEL_SAVE_PATH}")