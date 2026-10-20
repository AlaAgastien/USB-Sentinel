
from pathlib import Path
from modules.prevention import quarantine_sensitive_file

# Create a sample file for testing.
sample = Path("test_sensitive.txt")
sample.write_text(
    "CONFIDENTIAL employee salary information",
    encoding="utf-8"
)

success, message, destination = quarantine_sensitive_file(
    sample,
    quarantine_dir="quarantine"
)

print(message)

if success:
    print("Quarantine location:", destination)
    print("Original file still exists:", sample.exists())
