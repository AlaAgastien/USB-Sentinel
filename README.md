# 🔐 USB Sentinel
### USB Data Exfiltration Detection & Prevention System

**A Content-Based, Machine Learning-Assisted Cybersecurity Mini Project**

## 📌 Project Overview

USB Sentinel is a cybersecurity application designed to detect potentially sensitive information in files accessed through monitored USB storage locations and help reduce the risk of unauthorized data leakage.

The system analyzes supported file contents to identify potentially sensitive information, combines content analysis with machine learning-based classification, and presents detection results through an interactive Streamlit dashboard.

It also supports USB drive monitoring, email notifications, JSON-based detection history, and basic prevention through file handling and quarantine mechanisms.

USB Sentinel aims to provide a simple and practical approach to identifying potential data exfiltration risks through removable storage devices.

## 🎯 Objectives

- Identify potentially sensitive information within supported files.
- Monitor configured USB directories for file activity.
- Use content analysis and machine learning to detect potentially sensitive files.
- Notify the designated recipient when suspicious files are detected.
- Maintain detection records for security monitoring and review.
- Provide basic preventive actions to help reduce potential data leakage.
- Present security information through a user-friendly dashboard.

## ✨ Key Features

### 🔍 1. Content-Based Sensitive File Detection
Analyzes the actual contents of supported files to identify potentially sensitive information, rather than relying exclusively on filenames or file extensions.

### 🤖 2. Machine Learning Classification
Uses a trained machine learning model to classify files based on the features supplied to the model by the detection pipeline.

### 🔌 3. USB Drive Monitoring
Identifies removable storage devices and monitors configured directories for file activity using Python monitoring tools.

### 📧 4. Email Security Alerts
Sends email notifications to the configured recipient when a file is identified as potentially sensitive.

### 📊 5. Interactive Security Dashboard
Provides a Streamlit-based interface for viewing monitoring information, detection results, and security-related records.

### 📝 6. JSON-Based Detection History
Stores detection information locally in JSON format, allowing recorded results to be reviewed without requiring a SQL database.

### 📄 7. Detection Reports
Provides report-export functionality where enabled in the application, allowing detection records to be used for review and documentation.

### 🛡️ 8. Basic Prevention and Quarantine
Includes a prevention component intended to reduce the risk associated with potentially sensitive files. Quarantine-based handling can help isolate flagged files, depending on the configured workflow.

**Note:** Detection and quarantine do not guarantee that unauthorized copying is blocked before it occurs.

## 🏗️ System Architecture and Workflow

The system follows a modular workflow:

1. **USB Monitoring:** Identify removable storage devices and monitor the configured location.
2. **File Activity Detection:** Detect relevant file activity in the monitored directory.
3. **Content Analysis:** Examine supported file contents for potentially sensitive information.
4. **Feature Extraction and Classification:** Prepare the relevant features and use the trained machine learning model where applicable.
5. **Risk Identification:** Determine whether the file should be flagged for further attention.
6. **Prevention and Quarantine:** Apply the available preventive handling to flagged files.
7. **Detection Logging:** Store detection details in JSON-based records.
8. **Email Notification:** Alert the configured recipient when a potentially sensitive file is detected.
9. **Dashboard Display:** Present detection results and available history through Streamlit.

## 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| Python | Core application logic |
| Scikit-learn | Machine learning model training and classification |
| Streamlit | Interactive web dashboard |
| Pandas | Dataset processing and data handling |
| Psutil | System and removable-drive information |
| Watchdog | File-system activity monitoring |
| JSON | Detection history and local records |
| CSV | Training dataset storage |
| Joblib / Pickle | Saving and loading the trained model, as used by the implementation |
| SMTP | Email alert delivery |
| Git and GitHub | Version control and project hosting |

## 📂 Project Structure

```text
USB_Exfiltration_Detection/
│
├── app.py
├── train_model.py
├── create_dataset.py
├── requirements.txt
│
├── modules/
│   ├── file_monitor.py
│   ├── sensitive_file_detector.py
│   ├── content_analyzer.py
│   ├── alert_system.py
│   └── prevention.py
│
├── database/
│   ├── sensitive_files_dataset.csv
│   └── sensitive_file_model.pkl
│
├── logs/
│   └── latest_detection.json
│
├── quarantine/
│
└── README.md
```

*This is the intended structure based on the project files discussed previously. Adjust it to match the final contents of your GitHub repository.*

## ⚙️ Installation and Setup

### Prerequisites

- Python 3.11 or another compatible Python version.
- Git installed on your computer.
- Visual Studio Code or another Python editor.
- The required Python packages.
- The trained machine learning model or the ability to generate it.
- SMTP email configuration for email alerts.

### Step 1: Clone the Repository

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd USB_Exfiltration_Detection
```

Replace the placeholder with the URL of your GitHub repository.

### Step 2: Create a Virtual Environment

```bash
python -m venv venv
```

Activate the environment on Windows:

```bash
venv\Scripts\activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Configure Email Alerts

Configure the sender email, recipient email, and SMTP credentials according to the application's email configuration.

Keep passwords and app passwords in environment variables or a local configuration file excluded from Git.

**Never upload email credentials, private configuration files, or other secrets to GitHub.**

### Step 5: Run the Application

```bash
streamlit run app.py
```

Open the local address displayed in the terminal to access the USB Sentinel dashboard.

### Step 6: Test the System

- Configure the directory to be monitored.
- Add sample files containing test data.
- Observe the detection results on the dashboard.
- Verify that detection records are saved.
- Check email notifications for flagged files.
- Test quarantine and report-export functions if enabled.

Follow the project's actual configuration and model-loading requirements when running it on another computer.

## 🧪 Testing and Evaluation

USB Sentinel can be evaluated using safe sample files containing different types of information.

Suggested test scenarios:

- A normal image or document.
- A text file containing sample sensitive keywords.
- A document containing dummy personal or financial information.
- Multiple files added to the monitored directory.
- A file classified as potentially sensitive.
- Verification of detection history and email notifications.
- Verification of the available prevention and reporting functions.

Use dummy data for testing. Actual detection performance depends on supported file formats, content extraction, the training dataset, and the model's predictions.

## 🔒 Security Considerations

- Use sample data during demonstrations.
- Protect email credentials and confidential information.
- Do not commit sensitive documents or private logs to a public repository.
- Ensure that files are processed only in supported formats.
- Treat machine learning predictions as indicators of potential risk, not definitive proof.
- Monitor and test quarantine actions carefully to avoid unintended file loss.
- Remember that monitoring, detection, and email alerts alone do not guarantee prevention of unauthorized copying.

## 🚀 Future Enhancements

- Support for additional document formats.
- Improved detection of sensitive information in different file types.
- Enhanced machine learning performance with larger and more diverse datasets.
- Stronger USB access-control and real-time prevention mechanisms.
- Improved audit logging and security reporting.
- User authentication and role-based access control.

## 🎓 Project Information

| Field | Details |
|---|---|
| Project Name | USB Sentinel |
| Project Title | USB Data Exfiltration Detection & Prevention System |
| Domain | Cybersecurity |
| Focus Areas | Data Loss Prevention (DLP), USB Security, Content Analysis, Machine Learning |
| Project Type | Academic Mini Project |
| Interface | Streamlit Dashboard |
| Storage | Local files and JSON-based detection records |

## 👩‍💻 Project Purpose

USB Sentinel demonstrates how content analysis, machine learning, file monitoring, and email notifications can work together to identify potential data leakage risks associated with removable storage devices.

The project is intended for academic learning and cybersecurity demonstration purposes.

---

**USB Sentinel — Detect potential data leakage. Monitor suspicious file activity. Strengthen data security.**
