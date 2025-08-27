import tkinter as tk
from tkinter import messagebox
import requests
import validators
import re
from datetime import datetime
import whois
import socket

# Add a list of common shorteners
SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'bit.do', 'cutt.ly', 'tiny.cc', 'rebrand.ly', 'shorte.st', 'trib.al', 'soo.gd', 's2r.co', 'lc.chat', 'bl.ink', 'mcaf.ee', 'po.st', 'qr.ae', 'v.gd', 'x.co', 'yourls.org', 'lnkd.in', 'db.tt', 'qr.ae', 'ln.is', 'amzn.to', 'fb.me', 'wp.me', 'ift.tt', 't.ly', 'rb.gy', 'shorturl.at'
]

# --- Phishing Analysis Functions ---

def is_valid_url(url):
    return validators.url(url)

def fetch_page(url):
    try:
        response = requests.get(url, timeout=10)
        return response.text
    except requests.exceptions.RequestException:
        return None

def analyze_url(url):
    # Check for IP address in domain
    ip_pattern = r"https?://(?:\d{1,3}\.){3}\d{1,3}"
    if re.match(ip_pattern, url):
        return ("Looks Suspicious", "Contains IP address in domain.", "red")
    # Check for too many hyphens
    domain = re.sub(r"https?://", "", url).split("/")[0]
    if domain.count('-') > 3:
        return ("Looks Suspicious", "Domain contains too many hyphens.", "red")
    # Check for strange TLDs
    tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
    if any(domain.endswith(tld) for tld in tlds):
        return ("Looks Suspicious", f"Domain uses suspicious TLD ({', '.join(tlds)}).", "red")
    # Check for HTTPS
    if not url.startswith("https://"):
        return ("Looks Suspicious", "URL does not use HTTPS.", "red")
    # If all checks pass
    return ("Safe-looking URL", "No immediate phishing indicators found.", "green")

def log_scan(url, result, reason):
    with open("scan_log.txt", "a") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {url} - {result}: {reason}\n")

# --- PhishTank/Threat Feed Check ---
def check_phishtank(url):
    # You can get a free API key from https://phishtank.org/api_register.php
    API_KEY = None  # Set your API key here if you have one
    try:
        # Use PhishTank public API (no key required, but slower and less reliable)
        response = requests.post(
            'https://checkurl.phishtank.com/checkurl/',
            data={
                'url': url,
                'format': 'json',
                'app_key': API_KEY or ''
            },
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            if data.get('results', {}).get('valid') and data['results'].get('in_database'):
                if data['results'].get('phish_detail_page'):
                    return True, 'PhishTank: Known Phishing URL'
        return False, None
    except Exception as e:
        return None, f"PhishTank check failed: {e}"

# --- Short URL Detection & Expansion ---
def is_short_url(url):
    domain = re.sub(r"https?://", "", url).split("/")[0].lower()
    return any(domain == s or domain.endswith('.' + s) for s in SHORTENERS)

def expand_url(url):
    try:
        resp = requests.head(url, allow_redirects=True, timeout=10)
        return resp.url
    except Exception:
        return url

# --- Domain Age Lookup (WHOIS) ---
def get_domain_age(url):
    try:
        domain = re.sub(r"https?://", "", url).split("/")[0]
        # Remove port if present
        domain = domain.split(':')[0]
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if not creation_date:
            return None, 'WHOIS: Creation date not found.'
        age_days = (datetime.now() - creation_date).days
        return age_days, f"WHOIS: Domain created {creation_date.strftime('%Y-%m-%d')} ({age_days} days ago)"
    except Exception as e:
        return None, f"WHOIS lookup failed: {e}"

# --- Tkinter UI ---

def scan_url():
    url = url_entry.get().strip()
    if not url:
        result_label.config(text="Please enter a URL.", fg="#e74c3c")
        return
    if not is_valid_url(url):
        result_label.config(text="Invalid Link: URL format is incorrect.", fg="#e74c3c")
        log_scan(url, "Invalid Link", "URL format is incorrect.")
        return
    # Short URL detection and expansion
    resolved_url = url
    if is_short_url(url):
        resolved_url = expand_url(url)
        shortener_msg = f"Shortened URL detected. Expanded to: {resolved_url}\n"
    else:
        shortener_msg = ""
    # PhishTank/Threat Feed check
    phish_result, phish_reason = check_phishtank(resolved_url)
    if phish_result:
        result_label.config(text=f"Known Phishing URL (PhishTank): {resolved_url}", fg="#e74c3c")
        log_scan(resolved_url, "Known Phishing URL", "PhishTank match.")
        return
    elif phish_result is None and phish_reason:
        # API error or offline
        result_label.config(text=f"Warning: {phish_reason}", fg="#e67e22")
    # Domain age lookup
    age_days, whois_msg = get_domain_age(resolved_url)
    suspicious_age = False
    if age_days is not None and age_days < 30:
        suspicious_age = True
    # Main analysis
    result, reason, color = analyze_url(resolved_url)
    color_map = {"red": "#e74c3c", "green": "#27ae60"}
    # Compose result message
    msg = shortener_msg
    if url != resolved_url:
        msg += f"Original: {url}\nExpanded: {resolved_url}\n"
    msg += f"{result}: {reason}\n"
    if whois_msg:
        msg += whois_msg + "\n"
    if suspicious_age:
        msg += "Suspicious – Very young domain (<30 days old)\n"
    result_label.config(text=msg.strip(), fg=color_map.get(color, color))
    log_scan(resolved_url, result, reason)
    if whois_msg:
        log_scan(resolved_url, "WHOIS", whois_msg)
    if suspicious_age:
        log_scan(resolved_url, "Suspicious", "Very young domain (<30 days old)")

def clear_fields():
    url_entry.delete(0, tk.END)
    result_label.config(text="")

root = tk.Tk()
root.title("Phishing URL Scanner")
root.geometry("800x500")
root.resizable(False, False)

# Simulate a green-yellow gradient background using a Canvas
canvas = tk.Canvas(root, width=800, height=500, highlightthickness=0)
canvas.place(x=0, y=0)
for i in range(0, 500):
    # Start: green (#a8e063), End: yellow (#f9d423)
    r = int(0xa8 + (0xf9 - 0xa8) * i / 500)
    g = int(0xe0 + (0xd4 - 0xe0) * i / 500)
    b = int(0x63 + (0x23 - 0x63) * i / 500)
    color = f'#{r:02x}{g:02x}{b:02x}'
    canvas.create_line(0, i, 800, i, fill=color)

# Main frame with shadow effect
shadow = tk.Frame(root, bg="#b2bec3", width=540, height=370)
shadow.place(relx=0.5, rely=0.5, anchor="center", x=8, y=8)
frame = tk.Frame(root, padx=30, pady=30, bg="#ffffff", bd=0, relief="flat", highlightbackground="#0984e3", highlightthickness=3)
frame.place(relx=0.5, rely=0.5, anchor="center")

# Title and subtitle
icon_label = tk.Label(frame, text="🔎", font=("Segoe UI", 32), bg="#ffffff")
icon_label.pack(pady=(0, 0))
title_label = tk.Label(frame, text="Phishing URL Scanner", font=("Segoe UI", 24, "bold"), bg="#ffffff", fg="#0984e3")
title_label.pack(pady=(0, 4))
subtitle_label = tk.Label(frame, text="Scan links for phishing, shorteners, and domain age", font=("Segoe UI", 12), bg="#ffffff", fg="#636e72")
subtitle_label.pack(pady=(0, 18))

url_entry = tk.Entry(frame, width=50, font=("Segoe UI", 14), bd=2, relief="solid", highlightthickness=1, highlightbackground="#0984e3", highlightcolor="#0984e3")
url_entry.pack(pady=10, ipady=6)
url_entry.insert(0, "")

button_frame = tk.Frame(frame, bg="#ffffff")
button_frame.pack(pady=(10, 0))

# Button hover effects
def on_enter(e):
    e.widget["bg"] = "#00b894"
def on_leave(e):
    if e.widget == scan_btn:
        e.widget["bg"] = "#0984e3"
    else:
        e.widget["bg"] = "#636e72"

scan_btn = tk.Button(button_frame, text="🔍 Scan", width=14, font=("Segoe UI", 12, "bold"), bg="#0984e3", fg="#fff", activebackground="#74b9ff", activeforeground="#2d3436", bd=0, cursor="hand2", command=scan_url)
scan_btn.grid(row=0, column=0, padx=8)
scan_btn.bind("<Enter>", on_enter)
scan_btn.bind("<Leave>", on_leave)

clear_btn = tk.Button(button_frame, text="🧹 Clear", width=14, font=("Segoe UI", 12, "bold"), bg="#636e72", fg="#fff", activebackground="#b2bec3", activeforeground="#2d3436", bd=0, cursor="hand2", command=clear_fields)
clear_btn.grid(row=0, column=1, padx=8)
clear_btn.bind("<Enter>", on_enter)
clear_btn.bind("<Leave>", on_leave)

# Result area with colored border and background
result_frame = tk.Frame(frame, bg="#f1f8e9", bd=2, relief="groove", highlightbackground="#00b894", highlightthickness=2)
result_frame.pack(pady=18, fill="x")
result_label = tk.Label(result_frame, text="", font=("Segoe UI", 14, "bold"), bg="#f1f8e9", fg="#2d3436", wraplength=480, justify="left")
result_label.pack(padx=8, pady=8, fill="x")

root.mainloop()