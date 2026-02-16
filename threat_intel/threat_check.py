import sys
import requests

API_KEY = "fc7733f250e3291f51a393ce720d22081238668377a19688f85355d2a60187cd"
OTX_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4/{}/general"

def check_ip(ip):
    headers = {"X-OTX-API-KEY": API_KEY}
    r = requests.get(OTX_URL.format(ip), headers=headers, timeout=5)
    if r.status_code == 200:
        data = r.json()
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        if pulse_count > 0:
            print(f"[!] Malicious IP detected: {ip}")
            return True
    return False

with open("malicious_iocs.txt") as f:
    iocs = f.read().splitlines()

for ioc in iocs:
    if ioc.count(".") == 3:
        if check_ip(ioc):
            print("[X] Threat detected — stopping pipeline")
            sys.exit(1)

print("[+] No malicious indicators found")

import os

print("\n=== Local IOC File Scan Started ===")

malicious_found = False

with open("malicious_iocs.txt") as f:
    iocs = [line.strip() for line in f if line.strip()]

for root, _, files in os.walk("."):
    for file in files:
        path = os.path.join(root, file)

        if ".git" in path:
            continue

        try:
            with open(path, errors="ignore") as current:
                content = current.read()

                for ioc in iocs:
                    if ioc in content:
                        print(f"[!] Malicious indicator found in file: {file}")
                        malicious_found = True
        except:
            pass

if malicious_found:
    print("[X] Threat detected in project files — stopping pipeline")
    sys.exit(1)
else:
    print("[+] No malicious indicators in project files")
