
import os
import sys
import time
import json
import threading

from pathlib import Path
from datetime import datetime

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


# --------------------------------------------------
# PATHS AND IMPORTS
# --------------------------------------------------

PROJECT_DIR = Path(__file__).resolve().parent.parent
MODULE_DIR = Path(__file__).resolve().parent

sys.path.insert(0, str(PROJECT_DIR))
sys.path.insert(0, str(MODULE_DIR))

from sensitive_file_detector import analyze_file
from content_analyzer import analyze_file_content
from prevention import quarantine_sensitive_file
from alert_system import send_alert


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

USB_PATH = r"D:\\"  # Change if your USB drive letter differs.

LOG_FILE = PROJECT_DIR / "logs" / "latest_detection.json"
QUARANTINE_DIR = PROJECT_DIR / "quarantine"

STABLE_SECONDS = 2
MAX_WAIT_SECONDS = 60

processing_paths = set()
processed_signatures = {}
lock = threading.RLock()


# --------------------------------------------------
# FILE SIGNATURE
# --------------------------------------------------

def get_signature(file_path):
    """Return file size and modification time."""

    try:
        stat = os.stat(file_path)
        return stat.st_size, stat.st_mtime_ns
    except OSError:
        return None


# --------------------------------------------------
# WAIT FOR COPY TO COMPLETE
# --------------------------------------------------

def wait_for_file_complete(file_path):
    """Wait until the file stops changing."""

    start_time = time.time()
    previous_signature = None
    stable_since = None

    while time.time() - start_time < MAX_WAIT_SECONDS:

        if not os.path.isfile(file_path):
            return False

        signature = get_signature(file_path)

        if signature is None:
            previous_signature = None
            stable_since = None

        elif signature == previous_signature:

            if stable_since is None:
                stable_since = time.time()

            if time.time() - stable_since >= STABLE_SECONDS:
                return True

        else:
            previous_signature = signature
            stable_since = None

        time.sleep(1)

    print("File did not stabilize before timeout:", file_path)
    return False


# --------------------------------------------------
# SAVE DETECTION HISTORY
# --------------------------------------------------

def save_detection(record):
    """Append a record without deleting earlier history."""

    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    with lock:
        records = []

        if LOG_FILE.exists():
            try:
                with open(LOG_FILE, "r", encoding="utf-8") as file:
                    old_data = json.load(file)

                if isinstance(old_data, list):
                    records = old_data
                elif isinstance(old_data, dict):
                    records = [old_data]

            except (json.JSONDecodeError, OSError) as error:
                print("Cannot read detection history:", error)
                print("Existing history was not overwritten.")
                return False

        new_path = os.path.normcase(
            os.path.abspath(record.get("file_path", ""))
        )

        new_prediction = str(
            record.get("prediction", "")
        ).strip().lower()

        try:
            new_time = datetime.strptime(
                record["time"], "%Y-%m-%d %H:%M:%S"
            )
        except (ValueError, KeyError):
            new_time = datetime.now()

        # Prevent duplicate history entries for the same event.
        for old in reversed(records):

            if not isinstance(old, dict):
                continue

            old_path = old.get("file_path", "")

            if not old_path:
                continue

            old_path = os.path.normcase(
                os.path.abspath(old_path)
            )

            old_prediction = str(
                old.get("prediction", "")
            ).strip().lower()

            if (
                old_path != new_path
                or old_prediction != new_prediction
            ):
                continue

            old_time = None

            for fmt in (
                "%Y-%m-%d %H:%M:%S",
                "%d-%m-%Y %H:%M:%S"
            ):
                try:
                    old_time = datetime.strptime(
                        old.get("time", ""), fmt
                    )
                    break
                except (ValueError, TypeError):
                    continue

            if old_time is not None:
                seconds = (new_time - old_time).total_seconds()

                if 0 <= seconds <= 10:
                    print(
                        "Duplicate history record ignored:",
                        record["file_name"]
                    )
                    return True

        records.append(record)
        temp_file = LOG_FILE.with_suffix(".tmp")

        try:
            with open(temp_file, "w", encoding="utf-8") as file:
                json.dump(
                    records,
                    file,
                    indent=4,
                    ensure_ascii=False
                )

            os.replace(temp_file, LOG_FILE)

            print("History saved. Total records:", len(records))
            return True

        except OSError as error:
            print("Could not save detection history:", error)
            return False


# --------------------------------------------------
# RESTORE PREVIOUS FILE SIGNATURES
# --------------------------------------------------

def restore_processed_signatures():
    """Restore signatures of previously recorded files."""

    if not LOG_FILE.exists():
        return

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as file:
            records = json.load(file)

        if isinstance(records, dict):
            records = [records]

        if not isinstance(records, list):
            return

        for record in records:

            if not isinstance(record, dict):
                continue

            file_path = record.get("file_path")

            if not file_path:
                continue

            key = os.path.normcase(
                os.path.abspath(file_path)
            )

            signature = get_signature(file_path)

            if signature is not None:
                processed_signatures[key] = signature

    except (json.JSONDecodeError, OSError) as error:
        print("Could not restore previous signatures:", error)


# --------------------------------------------------
# USB FILE EVENT HANDLER
# --------------------------------------------------

class USBFileHandler(FileSystemEventHandler):

    def process_file(self, file_path):

        file_path = os.path.abspath(file_path)
        file_key = os.path.normcase(file_path)

        if not os.path.isfile(file_path):
            return

        # Ignore files outside the selected USB drive.
        try:
            usb_root = os.path.normcase(
                os.path.abspath(USB_PATH)
            )

            if os.path.commonpath(
                [file_key, usb_root]
            ) != usb_root:
                return

        except (ValueError, OSError):
            return

        # Prevent simultaneous processing of the same path.
        with lock:
            if file_key in processing_paths:
                return

            processing_paths.add(file_key)

        reserved_signature = None

        try:

            # Wait until copying is complete.
            if not wait_for_file_complete(file_path):
                return

            signature = get_signature(file_path)

            if signature is None:
                return

            # Ignore an unchanged file already processed.
            with lock:

                if processed_signatures.get(file_key) == signature:
                    print(
                        "Duplicate event ignored:",
                        os.path.basename(file_path)
                    )
                    return

                processed_signatures[file_key] = signature
                reserved_signature = signature

            print("\n" + "=" * 60)
            print("NEW FILE DETECTED")
            print("=" * 60)
            print("File:", file_path)

            # ------------------------------------------
            # 1. EXISTING MACHINE LEARNING DETECTION
            # ------------------------------------------

            result = analyze_file(file_path)

            if not isinstance(result, dict):
                raise ValueError(
                    "ML detector did not return a dictionary."
                )

            ml_prediction = str(
                result.get("prediction", "Unknown")
            ).strip()

            # ------------------------------------------
            # 2. NEW CONTENT-BASED DETECTION
            # ------------------------------------------

            content_result = analyze_file_content(file_path)

            if not isinstance(content_result, dict):
                raise ValueError(
                    "Content analyzer did not return a dictionary."
                )

            content_sensitive = (
                content_result.get("sensitive") is True
            )

            content_status = content_result.get(
                "status", "Unknown"
            )

            keyword_matches = content_result.get(
                "keyword_matches", []
            )

            pattern_matches = content_result.get(
                "pattern_matches", []
            )

            content_message = content_result.get(
                "message", ""
            )

            print("\nCONTENT ANALYSIS")
            print("-" * 40)
            print("Content status:", content_status)
            print("Content reason:", content_message)
            print("Matched keywords:", keyword_matches)
            print("Matched patterns:", pattern_matches)

            # ------------------------------------------
            # 3. COMBINE BOTH DETECTION RESULTS
            # ------------------------------------------

            if (
                ml_prediction.lower() == "sensitive"
                or content_sensitive
            ):
                prediction = "Sensitive"

            elif ml_prediction.lower() in (
                "not sensitive", "safe"
            ):
                prediction = "Not Sensitive"

            else:
                prediction = "Unknown"

            # If content cannot be analyzed, an ML prediction
            # of Unknown must not be treated as a safe result.
            print("\nFINAL DETECTION")
            print("-" * 40)
            print("ML prediction:", ml_prediction)
            print("Content sensitive:", content_sensitive)
            print("Final prediction:", prediction)

            # Ensure the file did not change during analysis.
            current_signature = get_signature(file_path)

            if (
                current_signature is None
                or current_signature != signature
            ):
                with lock:
                    if (
                        processed_signatures.get(file_key)
                        == signature
                    ):
                        processed_signatures.pop(file_key, None)

                reserved_signature = None

                print(
                    "File changed during analysis; "
                    "waiting for another event."
                )
                return

            # ------------------------------------------
            # 4. FILE DETAILS
            # ------------------------------------------

            filename = result.get(
                "file_name",
                os.path.basename(file_path)
            )

            extension = result.get(
                "extension",
                Path(file_path).suffix
            )

            size_kb = result.get(
                "size_kb",
                round(signature[0] / 1024, 2)
            )

            print("\nFILE DETAILS")
            print("-" * 40)
            print("File name:", filename)
            print("Extension:", extension)
            print("Size:", size_kb, "KB")
            print(
                "ML keyword count:",
                result.get("keyword_count", "N/A")
            )

            # ------------------------------------------
            # 5. CREATE DETECTION HISTORY RECORD
            # ------------------------------------------

            record = {
                "file_name": filename,
                "file_path": file_path,
                "extension": extension,
                "size_kb": size_kb,

                # Existing ML details
                "keyword_count": result.get(
                    "keyword_count", 0
                ),
                "filename_length": result.get(
                    "filename_length", 0
                ),
                "extension_type": result.get(
                    "extension_type", "Unknown"
                ),
                "ml_prediction": ml_prediction,

                # New content-analysis details
                "content_status": content_status,
                "content_sensitive": content_sensitive,
                "content_keywords": keyword_matches,
                "content_patterns": pattern_matches,
                "content_analysis_message": content_message,

                # Combined final decision
                "prediction": prediction,

                "time": datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),

                "email_status": "Not required",
                "quarantined": False,
                "prevention_status": "Not required"
            }

            # ------------------------------------------
            # 6. EMAIL ALERT AND QUARANTINE
            # ------------------------------------------

            if prediction == "Sensitive":

                print(
                    "\nWARNING: Sensitive file detected!"
                )

                # Email alert
                try:
                    send_alert(
                        filename,
                        extension,
                        size_kb
                    )

                    record["email_status"] = "Sent"
                    print("Email alert sent successfully.")

                except Exception as error:

                    record["email_status"] = "Failed"

                    print("Email alert failed:", error)

                # Quarantine prevention
                try:
                    success, message, destination = (
                        quarantine_sensitive_file(
                            file_path,
                            quarantine_dir=str(QUARANTINE_DIR)
                        )
                    )

                    record["prevention_status"] = str(message)
                    record["quarantined"] = bool(success)

                    if destination:
                        record["quarantine_path"] = str(
                            destination
                        )

                    print("Prevention result:", message)

                except Exception as error:

                    record["prevention_status"] = (
                        f"Quarantine failed: {error}"
                    )

                    print("Quarantine error:", error)

            elif prediction == "Not Sensitive":

                print(
                    "\nFile classified as NOT SENSITIVE."
                )
                print("No quarantine required.")

            else:

                # Unknown must not be reported as safe.
                print(
                    "\nWARNING: File could not be "
                    "classified confidently."
                )
                print(
                    "Automatic quarantine skipped. "
                    "Manual review is recommended."
                )

                record["prevention_status"] = (
                    "Not classified; manual review recommended"
                )

            # ------------------------------------------
            # 7. SAVE DETECTION HISTORY
            # ------------------------------------------

            if not save_detection(record):
                print(
                    "WARNING: Detection history was not saved."
                )

            print("=" * 60)

        except Exception as error:

            print("Error processing file:", error)

            # Allow a later event to retry after a failure.
            if reserved_signature is not None:

                with lock:
                    if (
                        processed_signatures.get(file_key)
                        == reserved_signature
                    ):
                        processed_signatures.pop(file_key, None)

        finally:

            with lock:
                processing_paths.discard(file_key)

    def on_created(self, event):

        if not event.is_directory:
            self.process_file(event.src_path)

    def on_moved(self, event):

        if not event.is_directory:
            self.process_file(event.dest_path)


# --------------------------------------------------
# START MONITORING
# --------------------------------------------------

if __name__ == "__main__":

    if not os.path.isdir(USB_PATH):

        print("USB drive not found:", USB_PATH)
        print("Check the USB drive letter in USB_PATH.")

        raise SystemExit(1)

    restore_processed_signatures()

    print("=" * 60)
    print("USB SENTINEL - FILE MONITOR")
    print("=" * 60)
    print("Monitoring USB:", USB_PATH)
    print("Detection log:", LOG_FILE)
    print("Quarantine folder:", QUARANTINE_DIR)
    print("Detection modes: ML + File Content Analysis")
    print("Waiting for copied files...")
    print("Press Ctrl+C to stop.")
    print("=" * 60)

    event_handler = USBFileHandler()
    observer = Observer()

    observer.schedule(
        event_handler,
        USB_PATH,
        recursive=True
    )

    observer.start()

    try:

        while True:
            time.sleep(1)

    except KeyboardInterrupt:

        print("\nStopping USB monitor...")
        observer.stop()

    finally:

        observer.join()
        print("USB monitor stopped.")

