import fitz
import argparse
import os
import re
import requests
import time
import sys

# Set your VirusTotal API key here
VIRUSTOTAL_API_KEY = "YOUR_API_KEY_HERE"
VIRUSTOTAL_SCAN_URL = "https://www.virustotal.com/api/v3/files"
VIRUSTOTAL_REPORT_URL = "https://www.virustotal.com/api/v3/analyses/"

def print_banner():
    banner = r"""
  _____  _____  ______    _____ _               _             
 |  __ \|  __ \|  ____|  / ____| |             | |            
 | |__) | |  | | |__    | |    | |__   ___  ___| | _____ _ __ 
 |  ___/| |  | |  __|   | |    | '_ \ / _ \/ __| |/ / _ \ '__|
 | |    | |__| | |      | |____| | | |  __/ (__|   <  __/ |   
 |_|    |_____/|_|       \_____|_| |_|\___|\___|_|\_\___|_|

   Scan PDF for DPI, Colors, Links, JavaScript, and Viruses

                    PDF Checker v1.1.0
                  Author: Jeff Steveanus
=============================================================="""
    print(banner)

def scan_file_virustotal(filepath):
    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY.strip() == "" or VIRUSTOTAL_API_KEY == "YOUR_API_KEY_HERE":
        print("[Error] VirusTotal API key is not set.")
        print("        Please set your API key in the script before using --scan.")
        sys.exit(1)

    print("\n[VirusTotal] Submitting file for scan...")
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        with open(filepath, "rb") as f:
            files = {"file": (os.path.basename(filepath), f)}
            response = requests.post(VIRUSTOTAL_SCAN_URL, files=files, headers=headers)

        if response.status_code != 200:
            print(f"[Error] Submission failed: {response.status_code} - {response.text}")
            return

        analysis_id = response.json().get("data", {}).get("id")
        print(f"[VirusTotal] Analysis ID: {analysis_id}")

        print("[VirusTotal] Waiting for scan results...", end="", flush=True)
        while True:
            report = requests.get(VIRUSTOTAL_REPORT_URL + analysis_id, headers=headers)
            if report.status_code != 200:
                print(f"\n[Error] Failed to fetch report: {report.status_code}")
                return
            data = report.json().get("data", {})
            if data.get("attributes", {}).get("status") == "completed":
                break
            print(".", end="", flush=True)
            time.sleep(3)

        stats = data["attributes"]["stats"]
        print("\n[VirusTotal] Scan Results:")
        print(f" - Harmless: {stats.get('harmless')}")
        print(f" - Malicious: {stats.get('malicious')}")
        print(f" - Suspicious: {stats.get('suspicious')}")
        print(f" - Undetected: {stats.get('undetected')}")
        print(f" - Timeout: {stats.get('timeout')}")
    except Exception as e:
        print(f"[Error] VirusTotal scan failed: {e}")

def check_color_space(image_colorspace):
    if image_colorspace in ["DeviceRGB", "RGB"]:
        return "RGB"
    elif image_colorspace in ["DeviceCMYK", "CMYK"]:
        return "CMYK"
    else:
        return f"Other ({image_colorspace})"

def extract_and_check_links(doc):
    print("\n[Security] Scanning for links and checking for malicious patterns...\n")
    suspicious_links = []
    link_count = 0

    for page_num in range(len(doc)):
        page = doc[page_num]
        links = page.get_links()
        for lnk in links:
            if 'uri' in lnk:
                uri = lnk['uri']
                link_count += 1
                print(f"[Link] Page {page_num + 1}: {uri}")

                if re.search(r"(\.ru|\.cn|bit\.ly|\.tk|drive\.google\.com|dropbox\.com)", uri, re.IGNORECASE):
                    suspicious_links.append(uri)

    if link_count == 0:
        print("[Info] No links found.")
    elif suspicious_links:
        print("\n[Warning] Suspicious Links Detected:")
        for s in suspicious_links:
            print(f" - {s}")
    else:
        print("\n[Info] No suspicious links detected.")

def check_security_issues(doc):
    print("\n[Security] Running general PDF security checks...\n")
    js_found = False
    embedded_files = False
    launch_actions = False

    for page_num in range(len(doc)):
        page = doc[page_num]
        if page.get_text("rawdict").get("js", None):
            js_found = True
            print(f"[Warning] JavaScript found on page {page_num + 1}")

        links = page.get_links()
        for l in links:
            if l.get("kind") == fitz.LINK_LAUNCH:
                launch_actions = True
                print(f"[Warning] Launch action (exec) found on page {page_num + 1}")

    if doc.embfile_count() > 0:
        embedded_files = True
        print(f"[Warning] PDF contains {doc.embfile_count()} embedded file(s)")

    if not any([js_found, embedded_files, launch_actions]):
        print("[Info] No suspicious JavaScript, embedded files, or launch actions found.")

def check_pdf_colorspace_dpi_size(filepath, scan=False):
    if not os.path.isfile(filepath):
        print(f"[Error] File not found: {filepath}")
        return

    doc = fitz.open(filepath)
    found_colorspaces = set()
    dpi_list = []

    print(f"\n[PDF Info] PDF file: {os.path.basename(filepath)}")
    print(f"[PDF Info] Number of pages: {len(doc)}")

    for page_num in range(len(doc)):
        page = doc[page_num]
        images = page.get_images(full=True)

        page_width_pt = page.rect.width
        page_height_pt = page.rect.height
        width_cm = round((page_width_pt / 72) * 2.54, 2)
        height_cm = round((page_height_pt / 72) * 2.54, 2)

        print(f"[PDF Info] Page {page_num + 1}: {width_cm} cm x {height_cm} cm")

        for img_index, img in enumerate(images):
            xref = img[0]
            width = img[2]
            height = img[3]
            colorspace = img[5]
            rect = page.get_image_bbox(img)

            found_colorspaces.add(check_color_space(colorspace))

            display_width = rect.width
            display_height = rect.height

            if display_width > 0 and display_height > 0:
                dpi_x = (width / display_width) * 72
                dpi_y = (height / display_height) * 72
                dpi_avg = round((dpi_x + dpi_y) / 2)
                dpi_list.append(dpi_avg)

    print("[PDF Info] Detected Color Spaces: ", ", ".join(found_colorspaces))
    if dpi_list:
        print(f"[PDF Info] Average Image DPI: {sum(dpi_list) // len(dpi_list)}")
        print(f"[PDF Info] All Detected DPIs: {dpi_list}")
    else:
        print("[PDF Info] No images with DPI information found.")

    extract_and_check_links(doc)
    check_security_issues(doc)

    if scan:
        scan_file_virustotal(filepath)

# Main program
if __name__ == "__main__":
    print_banner()

    parser = argparse.ArgumentParser(
        description="Check PDF color space, DPI, links, security and optionally scan with VirusTotal.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "-f", "--file",
        required=False,
        help="Path to the PDF file to analyze"
    )
    parser.add_argument(
        "-s", "--scan",
        action="store_true",
        help="Enable file scanning via VirusTotal (requires API key)"
    )

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    if args.file:
        check_pdf_colorspace_dpi_size(args.file, scan=args.scan)
    else:
        print("[Error] Please specify a PDF file with -f")
        print("Use -h for help.")
