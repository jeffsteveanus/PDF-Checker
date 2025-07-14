# PDF Checker

PDF Checker is a Python tool for analyzing PDF files for image DPI, color spaces, embedded links, JavaScript, and potential security issues. It can optionally scan files using VirusTotal (API key required).

## Features

- Detects image DPI and color spaces (RGB, CMYK, etc.)
- Lists and checks all embedded links for suspicious domains
- Scans for embedded JavaScript, launch actions, and embedded files
- Optional VirusTotal scan for malware detection

## Requirements

- Python 3.7+
- [PyMuPDF (fitz)](https://pymupdf.readthedocs.io/en/latest/)
- [requests](https://docs.python-requests.org/en/latest/)

Install dependencies:

```sh
pip install pymupdf requests
```

## Usage

```sh
python pdf-checker.py -f <path_to_pdf>
```

Optional VirusTotal scan (requires API key):

```sh
python pdf-checker.py -f <path_to_pdf> --scan
```

## VirusTotal API Key

To enable VirusTotal scanning, set your API key in the script:

```python
VIRUSTOTAL_API_KEY = "YOUR_API_KEY_HERE"
```

## Example Output

```
[PDF Info] PDF file: sample.pdf
[PDF Info] Number of pages: 2
[PDF Info] Page 1: 21.01 cm x 29.7 cm
[PDF Info] Detected Color Spaces: RGB
[PDF Info] Average Image DPI: 300

[Security] Scanning for links and checking for malicious patterns...
[Info] No suspicious links detected.
[Security] Running general PDF security checks...
[Info] No suspicious JavaScript, embedded files, or launch actions found.
```
