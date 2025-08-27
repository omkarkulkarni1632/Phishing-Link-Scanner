# Phishing Link Scanner

A small Tkinter-based GUI tool to scan URLs for common phishing indicators. It checks URL formatting, shortener expansion, PhishTank, WHOIS domain age, and a few heuristic checks (IP-in-domain, excessive hyphens, suspicious TLDs, HTTPS usage).

## Features

- Validate URL format
- Detect and expand common short URLs
- Check PhishTank (public API) for known phishing URLs
- Perform WHOIS lookup to estimate domain age
- Heuristic checks: IP in domain, many hyphens, suspicious TLDs, missing HTTPS
- Simple, user-friendly Tkinter GUI (`Phishing_Link_Scanner.py`)
- Appends scan results to `scan_log.txt` with timestamps

## Requirements

- Windows, macOS, or Linux with Python 3.8+
- Recommended: create a virtual environment

Python packages (install with pip):
- requests
- validators
- python-whois

## Install

Open PowerShell in the project folder (where `Phishing_Link_Scanner.py` is located).

```powershell
# Create and activate a venv (Windows PowerShell)
python -m venv .venv; .\.venv\Scripts\Activate.ps1

# Install dependencies
python -m pip install --upgrade pip; pip install requests validators python-whois
```

If you prefer not to use a venv, install the packages globally with pip.

## Run

From the project directory (PowerShell):

```powershell
# Run the GUI scanner
python Phishing_Link_Scanner.py
```

Enter a URL in the input field and click "🔍 Scan". Results and warnings will appear in the GUI and be appended to `scan_log.txt`.

## Notes & Limitations

- The PhishTank check uses the public endpoint and may be slow or rate-limited. Add an API key in the script (`check_phishtank`) for improved reliability.
- WHOIS lookups depend on the `python-whois` package and the availability of WHOIS servers; results may be missing for some domains.
- This tool performs heuristic checks and is not a replacement for a full security product — treat results as guidance, not definitive verdicts.

## Suggestions / Next Steps

- Add a `requirements.txt` for reproducible installs.
- Add tests for utility functions (URL validation, expansion, WHOIS parsing).
- Bundle as an executable using PyInstaller for non-Python users.
- Improve PhishTank integration with API key support and fallback threat feeds.

## License

Add a license file if you intend to publish the project. For private or academic use, include an appropriate license in a `LICENSE` file.

---

Requirements coverage:
- Generate README.md: Done
- Include install & run instructions: Done
- List dependencies and notes: Done
- Map next steps and limitations: Done

