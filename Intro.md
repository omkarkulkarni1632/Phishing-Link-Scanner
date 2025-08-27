# 🛡️ Phishing Link Scanner using Python  
🎯 **Project Goal**: Build an advanced Phishing Link Scanner with a modern Python-based frontend and real-time threat intelligence

---

## 📌 Project Overview  
This project is designed to detect potentially harmful or suspicious URLs using both **heuristic analysis** and **public threat intelligence**. Built using **Python** and a stylish `tkinter` GUI, this tool provides a detailed risk summary, detects phishing patterns, expands shortened URLs, checks WHOIS domain data, and logs each scan for review.

---

## 🚀 Features  

✅ **Modern GUI** using `tkinter` with gradient background and hover effects  
🔍 **Scans URLs for multiple phishing indicators**:  
• IP address used in domain  
• Suspicious top-level domains (`.tk`, `.ml`, etc.)  
• Excessive hyphens in domain  
• Missing HTTPS encryption  

🔗 **Short URL detection & expansion**:  
• Recognizes popular shorteners (e.g., `bit.ly`, `t.co`, `tinyurl.com`)  
• Automatically expands the shortened link before scanning

🧠 **PhishTank integration**:  
• Checks the URL against a public phishing database (PhishTank)  
• Flags and blocks known phishing URLs

🌐 **Domain Age Check (WHOIS)**:  
• Uses `whois` to get domain creation date  
• Flags domains younger than 30 days as suspicious

📄 **Result display**:  
• Multi-line message showing shortener info, threat level, and domain age  
• Color-coded feedback (green = safe, red = suspicious, orange = warnings)

🗂️ **Scan logging**:  
• Records scanned URLs, results, WHOIS info, and timestamp in `scan_log.txt`

🔁 **Clear button**:  
• Resets the URL field and scan result

📦 **Input validation**:  
• Detects and handles invalid or empty URL inputs

---

## 🧰 Technologies Used  

- **Python 3.x**  
- `tkinter` – frontend GUI  
- `requests` – HTTP requests  
- `re` – regex for pattern matching  
- `validators` – URL validation  
- `whois` – for domain info  
- `socket`, `datetime` – networking and timestamps  

---

