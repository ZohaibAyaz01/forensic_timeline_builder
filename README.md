# 🕵️‍♂️ Forensic Timeline Builder

A powerful CLI tool for forensic analysts and cybersecurity professionals that analyzes a directory to extract **file system metadata**—such as creation, modification, and access timestamps—and builds a **chronological timeline** of digital activity.

---

## 📌 Features

- ✅ Recursive or non-recursive directory scanning  
- 📁 Extracts file creation, modification, and access times  
- 🎨 Color-coded terminal output using `colorama` (if available)  
- 🔍 Filter timeline by event type or date range  
- 📊 View timeline statistics (event distribution, total data size, duration, etc.)  
- 💾 Export timeline to **CSV** or **JSON** format  
- 🌐 Cross-platform support: **Windows**, **Linux**, and **macOS**

---

## 🧰 Requirements

- Python 3.6+
- (Optional) [colorama](https://pypi.org/project/colorama/) for enhanced colored output:

```bash
pip install colorama
