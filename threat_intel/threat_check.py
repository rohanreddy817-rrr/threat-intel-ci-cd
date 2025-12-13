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

