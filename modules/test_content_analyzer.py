
import sys
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR))

from modules.content_analyzer import analyze_file_content

test_file = "test_document.txt"

with open(test_file, "w", encoding="utf-8") as file:
    file.write("""
    CONFIDENTIAL EMPLOYEE RECORD
    Employee salary: 45000
    Contact: test@example.com
    """)

result = analyze_file_content(test_file)

print("\nCONTENT ANALYSIS RESULT")
print("-----------------------")
print("File:", result["file"])
print("Status:", result["status"])
print("Sensitive:", result["sensitive"])
print("Matched keywords:", result["keyword_matches"])
print("Matched patterns:", result["pattern_matches"])
print("Reason:", result["message"])
