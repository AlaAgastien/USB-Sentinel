

import io
import json
from pathlib import Path
from datetime import datetime

import pandas as pd
import streamlit as st

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)


# ==================================================
# 1. CONFIGURATION
# ==================================================

BASE_DIR = Path(__file__).resolve().parent

LOG_FILE = BASE_DIR / "logs" / "latest_detection.json"
QUARANTINE_DIR = BASE_DIR / "quarantine"

st.set_page_config(
    page_title="USB Sentinel | USB Sentinel",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)


# ==================================================
# 2. ATTRACTIVE DARK SECURITY THEME
# ==================================================

st.markdown("""
<style>
    .stApp {
        background: linear-gradient(
            135deg, #0b1120 0%, #111c35 55%, #17152f 100%
        );
    }

    .block-container {
        padding-top: 1.8rem;
        padding-bottom: 2rem;
        max-width: 1500px;
    }

    [data-testid="stSidebar"] {
        background: linear-gradient(
            180deg, #111827 0%, #172554 100%
        );
        border-right: 1px solid #334155;
    }

    [data-testid="stSidebar"] * {
        color: #e2e8f0;
    }

    h1, h2, h3 {
        color: #f1f5f9 !important;
        font-weight: 700 !important;
    }

    p, label {
        color: #dbeafe;
    }

    .metric-card {
        background: linear-gradient(
            135deg, #1e293b, #252449
        );
        border: 1px solid #475569;
        border-radius: 16px;
        padding: 20px;
        min-height: 125px;
        box-shadow: 0 5px 18px rgba(0,0,0,0.22);
    }

    .metric-label {
        color: #cbd5e1;
        font-size: 14px;
    }

    .metric-value {
        color: #a5b4fc;
        font-size: 32px;
        font-weight: 800;
        margin-top: 10px;
    }

    .section-card {
        background: rgba(30, 41, 59, 0.65);
        border: 1px solid #334155;
        border-radius: 14px;
        padding: 18px;
    }

    .stButton > button,
    .stDownloadButton > button {
        background: linear-gradient(
            90deg, #4f46e5, #7c3aed
        );
        color: white !important;
        border: none;
        border-radius: 10px;
        font-weight: 600;
        min-height: 42px;
    }

    .stButton > button:hover,
    .stDownloadButton > button:hover {
        background: linear-gradient(
            90deg, #6366f1, #8b5cf6
        );
        border: 1px solid #a5b4fc;
    }

    [data-testid="stDataFrame"] {
        border: 1px solid #334155;
        border-radius: 12px;
        overflow: hidden;
    }

    hr {
        border-color: #334155;
    }

    [data-testid="stAlert"] {
        border-radius: 12px;
    }
</style>
""", unsafe_allow_html=True)


# ==================================================
# 3. LOAD DETECTION HISTORY
# ==================================================

def load_history():
    if not LOG_FILE.exists():
        return []

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)

        if isinstance(data, dict):
            data = [data]

        if isinstance(data, list):
            return [
                item for item in data
                if isinstance(item, dict)
            ]

        return []

    except (json.JSONDecodeError, OSError) as error:
        st.error(f"Could not read detection history: {error}")
        return []


# ==================================================
# 4. LOAD QUARANTINE FILES
# ==================================================

def get_quarantine_files():
    files = []

    if not QUARANTINE_DIR.exists():
        return files

    try:
        for path in QUARANTINE_DIR.rglob("*"):
            if not path.is_file():
                continue

            try:
                stat = path.stat()

                files.append({
                    "File Name": path.name,
                    "Location": str(path),
                    "Size (KB)": round(stat.st_size / 1024, 2),
                    "Modified": datetime.fromtimestamp(
                        stat.st_mtime
                    ).strftime("%Y-%m-%d %H:%M:%S")
                })

            except OSError:
                continue

    except OSError:
        pass

    return files


# ==================================================
# 5. HELPER FUNCTIONS
# ==================================================

def safe_text(value, default="Not recorded"):
    if value is None or value == "":
        return default
    return str(value)


def show_status(value):
    status = str(value or "Unknown").strip().lower()

    if status == "sensitive":
        st.error("🔴 SENSITIVE")

    elif status in ("not sensitive", "safe"):
        st.success("🟢 NOT SENSITIVE")

    else:
        st.warning("🟡 UNKNOWN / NOT ANALYZED")


def metric_card(label, value, icon):
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">
                {icon} &nbsp; {label}
            </div>
            <div class="metric-value">{value}</div>
        </div>
        """,
        unsafe_allow_html=True
    )


def content_list(value):
    if isinstance(value, list):
        return ", ".join(str(item) for item in value) or "None"
    return safe_text(value, "None")


# ==================================================
# 6. GENERATE PDF REPORT
# ==================================================

def create_history_pdf(rows):
    buffer = io.BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        rightMargin=25,
        leftMargin=25,
        topMargin=30,
        bottomMargin=35
    )

    styles = getSampleStyleSheet()

    styles["Title"].textColor = colors.HexColor("#312E81")

    cell_style = styles["BodyText"]
    cell_style.fontSize = 7
    cell_style.leading = 9

    story = [
        Paragraph("USB SENTINEL", styles["Title"]),
        Paragraph(
            "USB Data Exfiltration Detection - History Report",
            styles["Heading2"]
        ),
        Spacer(1, 10),
        Paragraph(
            "Generated: " +
            datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
            styles["Normal"]
        ),
        Paragraph(f"Total records: {len(rows)}", styles["Normal"]),
        Spacer(1, 14)
    ]

    headers = [
        "File",
        "Final Result",
        "ML Result",
        "Content Sensitive",
        "Keywords",
        "Time",
        "Email",
        "Quarantined"
    ]

    table_data = [headers]

    for row in rows:
        table_data.append([
            Paragraph(
                safe_text(row.get("File"), ""),
                cell_style
            ),
            safe_text(row.get("Final Prediction"), ""),
            safe_text(row.get("ML Prediction"), ""),
            safe_text(row.get("Content Sensitive"), ""),
            Paragraph(
                safe_text(row.get("Keywords Found"), "None"),
                cell_style
            ),
            safe_text(row.get("Time"), ""),
            safe_text(row.get("Email"), ""),
            safe_text(row.get("Quarantined"), "")
        ])

    if not rows:
        table_data.append([
            Paragraph("No records found.", cell_style),
            "", "", "", "", "", "", ""
        ])

    table = Table(
        table_data,
        repeatRows=1,
        colWidths=[100, 70, 70, 85, 125, 100, 60, 65]
    )

    table.setStyle(TableStyle([
        (
            "BACKGROUND", (0, 0), (-1, 0),
            colors.HexColor("#312E81")
        ),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        (
            "GRID", (0, 0), (-1, -1), 0.4,
            colors.HexColor("#CBD5E1")
        ),
        (
            "ROWBACKGROUNDS", (0, 1), (-1, -1),
            [colors.white, colors.HexColor("#EEF2FF")]
        ),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7)
    ]))

    story.append(table)

    def add_footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#64748B"))

        canvas.drawString(
            25, 18,
            "USB Sentinel | Security Detection Report"
        )

        canvas.drawRightString(
            landscape(A4)[0] - 25,
            18,
            f"Page {doc.page}"
        )

        canvas.restoreState()

    document.build(
        story,
        onFirstPage=add_footer,
        onLaterPages=add_footer
    )

    buffer.seek(0)
    return buffer.getvalue()


# ==================================================
# 7. SIDEBAR NAVIGATION
# ==================================================

with st.sidebar:
    st.markdown("# 🔐 USB SENTINEL")
    st.caption("DATA EXFILTRATION DETECTION")

    st.divider()

    page = st.radio(
        "NAVIGATION",
        [
            "Dashboard",
            "Latest Detection",
            "Detection History",
            "Quarantine"
        ],
        index=0
    )

    st.divider()

    if st.button("🔄 Refresh Data", use_container_width=True):
        st.rerun()

    st.markdown("---")
    st.caption("🛡️ ML + Content-Based Detection")
    st.caption("📧 Email Alert System")
    st.caption("🔒 Quarantine Management")


# ==================================================
# 8. LOAD DATA FOR PAGES
# ==================================================

history = load_history()

# Assumes the monitor appends records chronologically.
latest = history[-1] if history else {}

quarantine_files = get_quarantine_files()

sensitive_count = sum(
    str(item.get("prediction", "")).lower() == "sensitive"
    for item in history
)

alerts_sent = sum(
    str(item.get("email_status", "")).lower() == "sent"
    for item in history
)

quarantined_count = sum(
    bool(item.get("quarantined", False))
    for item in history
)


# ==================================================
# 9. DASHBOARD PAGE
# ==================================================

if page == "Dashboard":

    st.title("🛡️ Sentinel Dashboard")
    st.caption(
        "Your Data. Your Security. Our Watch."
    )

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        metric_card("Files Detected", len(history), "📁")

    with col2:
        metric_card("Sensitive Files", sensitive_count, "🚨")

    with col3:
        metric_card("Email Alerts Sent", alerts_sent, "📧")

    with col4:
        metric_card("Quarantined Events", quarantined_count, "🔒")

    st.markdown("### 📌 Latest Detection")

    if latest:

        left, right = st.columns([2, 1])

        with left:
            st.markdown(
                f"**File:** {safe_text(latest.get('file_name'))}"
            )
            st.write(
                "**Detected at:**",
                safe_text(latest.get("time"))
            )
            st.write(
                "**Extension:**",
                safe_text(latest.get("extension"))
            )
            st.write(
                "**File size:**",
                safe_text(latest.get("size_kb")),
                "KB"
            )

        with right:
            st.markdown("**Final Prediction**")
            show_status(latest.get("prediction"))

        st.markdown("#### Content Analysis")

        st.write(
            "**Content analysis status:**",
            safe_text(latest.get("content_status"))
        )
        st.write(
            "**Content analysis reason:**",
            safe_text(latest.get("content_analysis_message"))
        )
        st.write(
            "**Matched keywords:**",
            content_list(latest.get("content_keywords", []))
        )
        st.write(
            "**Matched patterns:**",
            content_list(latest.get("content_patterns", []))
        )

        st.write(
            "**Email status:**",
            safe_text(latest.get("email_status"))
        )
        st.write(
            "**Prevention status:**",
            safe_text(latest.get("prevention_status"))
        )

    else:
        st.info(
            "No detections recorded yet. Start your file monitor "
            "and copy a test file to your monitored USB drive."
        )

    st.markdown("### 🕒 Recent Activity")

    if history:
        recent_rows = []

        for item in reversed(history[-5:]):
            recent_rows.append({
                "File": item.get("file_name", "Unknown"),
                "Prediction": item.get("prediction", "Unknown"),
                "Time": item.get("time", "Unknown"),
                "Email": item.get("email_status", "Unknown"),
                "Quarantined": item.get("quarantined", False)
            })

        st.dataframe(
            pd.DataFrame(recent_rows),
            use_container_width=True,
            hide_index=True
        )

    else:
        st.caption("No recent activity.")


# ==================================================
# 10. LATEST DETECTION PAGE
# ==================================================

elif page == "Latest Detection":

    st.title("🔎 Latest Detection")
    st.caption("Detailed analysis of the latest recorded file.")

    if not latest:
        st.info("No detection details are available yet.")

    else:
        left, right = st.columns([2, 1])

        with left:
            st.subheader(
                safe_text(latest.get("file_name"), "Unknown file")
            )
            st.write(
                "**File path:**",
                safe_text(latest.get("file_path"))
            )
            st.write(
                "**Detection time:**",
                safe_text(latest.get("time"))
            )
            st.write(
                "**Extension:**",
                safe_text(latest.get("extension"))
            )
            st.write(
                "**Size:**",
                safe_text(latest.get("size_kb")),
                "KB"
            )

        with right:
            st.markdown("#### Final Result")
            show_status(latest.get("prediction"))

            st.write(
                "**Email alert:**",
                safe_text(latest.get("email_status"))
            )
            st.write(
                "**Quarantined:**",
                "Yes" if latest.get("quarantined") else "No"
            )

        st.divider()

        st.subheader("🤖 File Security Check")

        st.write(
            "**ML prediction:**",
            safe_text(latest.get("ml_prediction"))
        )
        st.write(
            "**Filename keyword count:**",
            safe_text(latest.get("keyword_count"))
        )
        st.write(
            "**Filename length:**",
            safe_text(latest.get("filename_length"))
        )
        st.write(
            "**Extension type:**",
            safe_text(latest.get("extension_type"))
        )

        st.divider()

        st.subheader("📄 File Content Analysis")

        st.write(
            "**Analysis status:**",
            safe_text(latest.get("content_status"))
        )
        st.write(
            "**Content sensitive:**",
            safe_text(latest.get("content_sensitive"))
        )
        st.write(
            "**Reason:**",
            safe_text(latest.get("content_analysis_message"))
        )
        st.write(
            "**Sensitive keywords:**",
            content_list(latest.get("content_keywords", []))
        )
        st.write(
            "**Detected patterns:**",
            content_list(latest.get("content_patterns", []))
        )

        st.divider()

        st.subheader("🔒 Prevention Details")

        st.write(
            "**Prevention status:**",
            safe_text(latest.get("prevention_status"))
        )

        if latest.get("quarantine_path"):
            st.write(
                "**Quarantine location:**",
                latest["quarantine_path"]
            )


# ==================================================
# 11. DETECTION HISTORY PAGE
# ==================================================

elif page == "Detection History":

    st.title("📜 Detection History")
    st.caption("Search, filter, and export previous detections.")

    if not history:
        st.info("No detection history is available yet.")

    else:
        search = st.text_input(
            "🔍 Search by filename",
            placeholder="Type a filename..."
        )

        status_filter = st.selectbox(
            "Filter by final prediction",
            ["All", "Sensitive", "Not Sensitive", "Unknown"]
        )

        filtered = history.copy()

        if search.strip():
            filtered = [
                item for item in filtered
                if search.lower() in str(
                    item.get("file_name", "")
                ).lower()
            ]

        if status_filter != "All":
            filtered = [
                item for item in filtered
                if str(
                    item.get("prediction", "Unknown")
                ).lower() == status_filter.lower()
            ]

        rows = []

        for item in reversed(filtered):
            rows.append({
                "File": item.get("file_name", "Unknown"),
                "Final Prediction": item.get(
                    "prediction", "Unknown"
                ),
                "ML Prediction": item.get(
                    "ml_prediction", "Not recorded"
                ),
                "Content Sensitive": item.get(
                    "content_sensitive", "Not recorded"
                ),
                "Keywords Found": content_list(
                    item.get("content_keywords", [])
                ),
                "Time": item.get("time", "Unknown"),
                "Email": item.get("email_status", "Unknown"),
                "Quarantined": item.get("quarantined", False)
            })

        st.markdown(f"**Records found: {len(rows)}**")

        if rows:
            st.dataframe(
                pd.DataFrame(rows),
                use_container_width=True,
                hide_index=True
            )

        else:
            st.warning("No records match the selected filters.")

        # ------------------------------------------
        # CSV AND PDF EXPORT SIDE BY SIDE
        # ------------------------------------------

        st.markdown("### 📥 Export Detection History")

        csv_col, pdf_col = st.columns(2)

        csv_data = (
            pd.DataFrame(rows)
            .to_csv(index=False)
            .encode("utf-8")
        )

        pdf_data = create_history_pdf(rows)

        with csv_col:
            st.download_button(
                label="📊 Export History as CSV",
                data=csv_data,
                file_name="usb_detection_history.csv",
                mime="text/csv",
                use_container_width=True
            )

        with pdf_col:
            st.download_button(
                label="📄 Export History as PDF",
                data=pdf_data,
                file_name="usb_detection_history.pdf",
                mime="application/pdf",
                use_container_width=True
            )

        st.caption(
            "Exports contain the records matching your current "
            "search and filter. File contents are not included."
        )


# ==================================================
# 12. QUARANTINE PAGE
# ==================================================

elif page == "Quarantine":

    st.title("🔒 Quarantine Management")
    st.caption(
        "Review files currently stored in the quarantine directory."
    )

    st.warning(
        "Quarantined files may contain sensitive information. "
        "Only access them if authorized."
    )

    st.write("**Quarantine folder:**", str(QUARANTINE_DIR))

    col1, col2 = st.columns(2)

    with col1:
        metric_card(
            "Files Currently Present",
            len(quarantine_files),
            "📁"
        )

    with col2:
        metric_card(
            "Recorded Quarantine Events",
            quarantined_count,
            "🛡️"
        )

    if quarantine_files:
        st.subheader("📂 Files in Quarantine")

        st.dataframe(
            pd.DataFrame(quarantine_files),
            use_container_width=True,
            hide_index=True
        )

        quarantine_csv = (
            pd.DataFrame(quarantine_files)
            .to_csv(index=False)
            .encode("utf-8")
        )

        st.download_button(
            "📥 Export Quarantine List as CSV",
            data=quarantine_csv,
            file_name="usb_quarantine_list.csv",
            mime="text/csv"
        )

    else:
        st.info(
            "No files were found in the configured quarantine folder. "
            "Check your prevention module's destination if you expect files."
        )

    st.divider()

    st.subheader("📋🔐 Protected Files")

    events = [
        item for item in reversed(history)
        if item.get("quarantined", False)
    ]

    if events:
        event_rows = []

        for item in events:
            event_rows.append({
                "File": item.get("file_name", "Unknown"),
                "Original Path": item.get("file_path", "Unknown"),
                "Quarantine Path": item.get(
                    "quarantine_path", "Not recorded"
                ),
                "Time": item.get("time", "Unknown"),
                "Status": item.get("prevention_status", "Unknown")
            })

        st.dataframe(
            pd.DataFrame(event_rows),
            use_container_width=True,
            hide_index=True
        )

    else:
        st.caption("No successful quarantine events recorded.")


# ==================================================
# 13. FOOTER
# ==================================================

st.divider()

st.markdown(
    "<div style='text-align:center; color:#94a3b8; "
    "font-size:13px;'>"
    "🔐 USB SENTINEL | "
    "</div>",
    unsafe_allow_html=True
)
