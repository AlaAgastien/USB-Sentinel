import smtplib
from email.message import EmailMessage


# ==========================================
# EMAIL CONFIGURATION
# ==========================================

SENDER_EMAIL = "sender's email"

APP_PASSWORD = "app password of your system"

RECEIVER_EMAIL = "receiver's email"


# ==========================================
# SEND EMAIL ALERT
# ==========================================

def send_alert(file_name, extension, size_kb):

    message = EmailMessage()

    message["Subject"] = (
        "⚠️ USB Security Alert - Sensitive File Detected"
    )

    message["From"] = SENDER_EMAIL

    message["To"] = RECEIVER_EMAIL

    message.set_content(
        f"""
USB DATA EXFILTRATION ALERT

A potentially sensitive file has been detected
on the USB drive.

File Name: {file_name}
Extension: {extension}
File Size: {size_kb:.2f} KB

Prediction: SENSITIVE

⚠️ Possible data exfiltration detected.

Please review the file transfer.
"""
    )

    try:

        with smtplib.SMTP_SSL(
            "smtp.gmail.com",
            465
        ) as server:

            server.login(
                SENDER_EMAIL,
                APP_PASSWORD
            )

            server.send_message(message)

        print("📧 Email alert sent successfully!")

    except Exception as e:

        print("❌ Email alert failed:")
        print(e)
