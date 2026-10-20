
import os
import shutil
from pathlib import Path
from datetime import datetime


def quarantine_sensitive_file(
    file_path,
    quarantine_dir="quarantine"
):
    """
    Move a detected sensitive file out of the USB folder
    into a quarantine folder on the computer.

    Returns a status message and the destination path.
    """

    source = Path(file_path).resolve()
    quarantine = Path(quarantine_dir).resolve()

    if not source.exists() or not source.is_file():
        return False, "File does not exist.", None

    # Prevent moving a file into a folder inside itself.
    if source == quarantine or quarantine in source.parents:
        return False, "Invalid quarantine destination.", None

    try:
        quarantine.mkdir(parents=True, exist_ok=True)

        # Use a unique name to avoid overwriting files.
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        destination = quarantine / f"{timestamp}_{source.name}"

        # Move rather than copy, so the original USB location
        # no longer contains the detected file.
        shutil.move(str(source), str(destination))

        return (
            True,
            "Sensitive file quarantined successfully.",
            str(destination)
        )

    except (OSError, shutil.Error) as error:
        return (
            False,
            f"Quarantine failed: {error}",
            None
        )
