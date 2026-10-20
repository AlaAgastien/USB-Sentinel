import pandas as pd
import random
import os


# --------------------------------
# Normal files
# --------------------------------

normal_files = [
    ("photo", ".jpg"),
    ("holiday", ".jpg"),
    ("image", ".png"),
    ("song", ".mp3"),
    ("movie", ".mp4"),
    ("assignment", ".pdf"),
    ("project", ".pdf"),
    ("notes", ".txt"),
    ("report", ".docx"),
    ("marks", ".xlsx"),
    ("assignment_data", ".xlsx"),
    ("project_data", ".xlsx"),
    ("presentation", ".pptx"),
    ("book", ".pdf"),
    ("video", ".avi"),
]


# --------------------------------
# Sensitive files
# --------------------------------

sensitive_files = [
    ("password", ".txt"),
    ("salary", ".xlsx"),
    ("employee_salary", ".xlsx"),
    ("bank_account", ".xlsx"),
    ("bank_details", ".pdf"),
    ("confidential", ".docx"),
    ("private", ".pdf"),
    ("secret", ".txt"),
    ("credit_card", ".csv"),
    ("personal_data", ".xlsx"),
    ("employee_data", ".csv"),
    ("login_details", ".txt"),
    ("confidential_report", ".xlsx"),
]


data = []


# --------------------------------
# Generate Normal Records
# --------------------------------

for i in range(250):

    name, extension = random.choice(normal_files)

    size_kb = random.randint(10, 50000)

    keyword_count = 0

    filename_length = len(name)

    extension_type = 1 if extension in [
        ".txt", ".pdf", ".docx", ".xlsx", ".csv"
    ] else 0

    data.append([
        name,
        extension,
        size_kb,
        keyword_count,
        filename_length,
        extension_type,
        0
    ])


# --------------------------------
# Generate Sensitive Records
# --------------------------------

for i in range(250):

    name, extension = random.choice(sensitive_files)

    size_kb = random.randint(10, 5000)

    keyword_count = random.randint(1, 3)

    filename_length = len(name)

    extension_type = 1

    data.append([
        name,
        extension,
        size_kb,
        keyword_count,
        filename_length,
        extension_type,
        1
    ])


# --------------------------------
# Create DataFrame
# --------------------------------

df = pd.DataFrame(
    data,
    columns=[
        "filename",
        "extension",
        "size_kb",
        "keyword_count",
        "filename_length",
        "extension_type",
        "sensitive"
    ]
)


# --------------------------------
# Save Dataset
# --------------------------------

os.makedirs("database", exist_ok=True)

df.to_csv(
    "database/sensitive_files_dataset.csv",
    index=False
)


print("Improved dataset created successfully!")
print("Total records:", len(df))

print("\nNormal records:", len(df[df["sensitive"] == 0]))
print("Sensitive records:", len(df[df["sensitive"] == 1]))

print("\nSample records:")
print(df.head(10))