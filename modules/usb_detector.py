
import psutil
import os


def detect_usb_drives():
    """
    Detect mounted removable drives on Windows.
    Returns a list of detected drive paths.
    """
    usb_drives = []

    for partition in psutil.disk_partitions(all=False):
        drive_path = partition.mountpoint

        if os.name == "nt":
            # Windows removable drives commonly use drive letters.
            try:
                import ctypes

                drive_type = ctypes.windll.kernel32.GetDriveTypeW(
                    drive_path
                )

                # DRIVE_REMOVABLE = 2
                if drive_type == 2:
                    usb_drives.append(drive_path)

            except (AttributeError, OSError):
                continue

    return usb_drives


if __name__ == "__main__":
    drives = detect_usb_drives()

    if drives:
        print("Detected removable drives:")
        for drive in drives:
            print(f"- {drive}")
    else:
        print("No removable USB drives detected.")
