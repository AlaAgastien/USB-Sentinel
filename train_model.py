import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.pipeline import Pipeline
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, classification_report


# Load dataset
df = pd.read_csv("database/sensitive_files_dataset.csv")


# Features
X = df[
    [
        "filename",
        "extension",
        "size_kb",
        "keyword_count",
        "filename_length",
        "extension_type"
    ]
]

# Target
y = df["sensitive"]


# Categorical features
categorical_features = [
    "filename",
    "extension"
]

# Numerical features
numerical_features = [
    "size_kb",
    "keyword_count",
    "filename_length",
    "extension_type"
]


# Preprocessing
preprocessor = ColumnTransformer(
    transformers=[
        (
            "categorical",
            OneHotEncoder(handle_unknown="ignore"),
            categorical_features
        ),
        (
            "numerical",
            "passthrough",
            numerical_features
        )
    ]
)


# Create pipeline
model = Pipeline(
    steps=[
        ("preprocessor", preprocessor),
        (
            "classifier",
            DecisionTreeClassifier(random_state=42)
        )
    ]
)


# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)


# Train model
model.fit(X_train, y_train)


# Test model
y_pred = model.predict(X_test)


# Accuracy
accuracy = accuracy_score(y_test, y_pred)

print("\nAccuracy:", accuracy)


# Classification report
print("\nClassification Report:")
print(
    classification_report(
        y_test,
        y_pred
    )
)


# Save complete pipeline
joblib.dump(
    model,
    "database/sensitive_file_model.pkl"
)


print("\nModel saved successfully!")
print("File: database/sensitive_file_model.pkl")