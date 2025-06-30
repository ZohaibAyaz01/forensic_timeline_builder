# 🕵️‍♂️ Forensic Timeline Builder

A powerful CLI tool for forensic analysts and cybersecurity professionals that analyzes a directory to extract **file system metadata**—such as creation, modification, and access timestamps—and builds a **chronological timeline** of digital activity.

---

## 📌 Features

📂 **Directory Scanner**: Analyze any directory with optional recursive scanning.
⏱  **Timestamps Extractor**: Capture accurate creation, modification, and access times.
🎨 **Color-coded Terminal Timeline** (if `colorama` is installed).
📊 **Statistics Dashboard**: View total events, file sizes, and activity duration.
🔍 **Filters**: By event type (`CREATE`, `MODIFY`, `ACCESS`) and date range.
💾 **Export to CSV/JSON**: For reporting and archival.
🧠 **Interactive & Command-line Modes**.
💡 **Lightweight & Portable**: No heavy dependencies.

---

## 🧰 Requirements

- Python 3.6+
- (Optional) [colorama](https://pypi.org/project/colorama/) for enhanced colored output:

```bash
pip install colorama
