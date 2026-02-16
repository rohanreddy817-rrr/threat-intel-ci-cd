import sys
import requests
import os

# ==============================
# 🔐 AlienVault OTX Configuration
# ==============================

API_KEY = "DUMMY_KEY"
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


# ==============================
# 🛡️ STEP 1 — External Threat Intel Check
# ==============================

with open("malicious_iocs.txt") as f:
    iocs = f.read().splitlines()

for ioc in iocs:
    if ioc.count(".") == 3:  # Looks like IPv4
        if check_ip(ioc):
            print("[X] Threat detected — stopping pipeline")
            sys.exit(1)

print("[+] No malicious indicators found in threat intel check")


# ==============================
# 🛡️ STEP 2 — Local File Scan
# ==============================

print("\n=== Local IOC File Scan Started ===")

malicious_found = False

with open("malicious_iocs.txt") as f:
    iocs = [line.strip() for line in f if line.strip()]

for root, _, files in os.walk("."):
    for file in files:

        # ❌ Skip Git internals
        if ".git" in root:
            continue

        # ❌ Skip IOC database itself
        if file == "malicious_iocs.txt":
            continue

        path = os.path.join(root, file)

        try:
            with open(path, errors="ignore") as current:
                content = current.read()

                for ioc in iocs:
                    if ioc in content:
                        print(f"[!] Malicious indicator found in file: {file}")
                        malicious_found = True

        except:
            pass


# ==============================
# 🛑 FINAL DECISION
# ==============================

if malicious_found:
    print("[X] Threat detected in project files — stopping pipeline")
    sys.exit(1)
else:
    print("[+] No malicious indicators in project files")
