import os
import joblib
import pandas as pd


# Load trained model
model = joblib.load(
    "database/sensitive_file_model.pkl"
)


# Sensitive keywords
SENSITIVE_KEYWORDS = [
    "password",
    "salary",
    "employee",
    "bank",
    "account",
    "confidential",
    "private",
    "secret",
    "credit",
    "personal"
]


def analyze_file(file_path):

    # -----------------------------
    # File information
    # -----------------------------

    file_name = os.path.basename(file_path)

    extension = os.path.splitext(file_name)[1].lower()

    size_kb = os.path.getsize(file_path) / 1024


    # -----------------------------
    # Keyword count
    # -----------------------------

    filename_lower = file_name.lower()

    keyword_count = sum(
        1
        for keyword in SENSITIVE_KEYWORDS
        if keyword in filename_lower
    )


    # -----------------------------
    # Filename length
    # -----------------------------

    filename_length = len(
        os.path.splitext(file_name)[0]
    )


    # -----------------------------
    # Extension type
    # -----------------------------

    sensitive_extensions = [
        ".xlsx",
        ".xls",
        ".csv",
        ".pdf",
        ".docx",
        ".doc",
        ".txt"
    ]

    extension_type = (
        1
        if extension in sensitive_extensions
        else 0
    )


    # -----------------------------
    # Create input data
    # -----------------------------

    features = pd.DataFrame([{
        "filename": file_name,
        "extension": extension,
        "size_kb": size_kb,
        "keyword_count": keyword_count,
        "filename_length": filename_length,
        "extension_type": extension_type
    }])


    # -----------------------------
    # ML prediction
    # -----------------------------

    prediction = model.predict(features)[0]


    if prediction == 1:
        result = "Sensitive"
    else:
        result = "Not Sensitive"


    # -----------------------------
    # Return result
    # -----------------------------

    return {
        "file_name": file_name,
        "extension": extension,
        "size_kb": size_kb,
        "keyword_count": keyword_count,
        "filename_length": filename_length,
        "extension_type": extension_type,
        "prediction": result
    }