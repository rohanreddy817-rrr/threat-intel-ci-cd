import sys
import requests
import os

print("=== Threat Intelligence Scan Started ===")

# ==============================
# 🔐 AlienVault OTX Configuration
# ==============================

API_KEY = "fc7733f250e3291f51a393ce720d22081238668377a19688f85355d2a60187cd"
OTX_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4/{}/general"

malicious_found = False
risk_level = "LOW"


def check_ip(ip):
    headers = {"X-OTX-API-KEY": API_KEY}
    try:
        r = requests.get(OTX_URL.format(ip), headers=headers, timeout=5)

        if r.status_code == 200:
            data = r.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)

            if pulse_count > 0:
                print(f"[!] Malicious IP detected: {ip}")
                return True
    except:
        pass

    return False


# ==============================
# 🛡️ STEP 1 — External Threat Intel Check
# ==============================

with open("malicious_iocs.txt") as f:
    iocs = [line.strip() for line in f if line.strip()]

for ioc in iocs:
    if ioc.count(".") == 3:  # Looks like IPv4
        if check_ip(ioc):
            print("[!] Threat detected from external intelligence")
            malicious_found = True
            risk_level = "HIGH"

print("[+] External Threat Check Completed")


# ==============================
# 🛡️ STEP 2 — Local File Scan
# ==============================

print("\n=== Local IOC File Scan Started ===")

for root, _, files in os.walk("."):
    for file in files:

        # Skip Git internals
        if ".git" in root:
            continue

        # Skip IOC file itself
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
                        risk_level = "HIGH"

        except:
            pass


# ==============================
# 🛑 FINAL DECISION
# ==============================

if malicious_found:
    print("\n🚨 THREAT DETECTED — BLOCKING PIPELINE")
    print(f"Risk Level: {risk_level}")
    print("Suggested Fix: Remove malicious IP/domain from project")

    # Logging
    with open("scan_log.txt", "a") as log:
        log.write("THREAT DETECTED | Risk: HIGH\n")

    sys.exit(1)

else:
    print("\n✅ No malicious indicators found")
    print(f"Risk Level: {risk_level}")

    with open("scan_log.txt", "a") as log:
        log.write("THREAT SCAN SAFE | Risk: LOW\n")
