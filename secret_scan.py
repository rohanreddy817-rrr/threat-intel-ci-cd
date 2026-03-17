import os
import sys
import re

print("=== Secret Leak Scan Started ===")

secret_found = False
risk_level = "LOW"

# Common secret patterns
patterns = [
    r"AKIA[0-9A-Z]{16}",     # AWS key
    r"password\s*=",         # password assignment
    r"api[_-]?key\s*=",      # api key
    r"secret\s*=",           # secret
    r"token\s*="             # token
]

for root, _, files in os.walk("."):
    for file in files:

        # Skip git folder
        if ".git" in root:
            continue

        path = os.path.join(root, file)

        try:
            with open(path, errors="ignore") as f:
                content = f.read()

                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        print(f"[!] Possible secret found in {file}")
                        secret_found = True
                        risk_level = "HIGH"

        except:
            pass


# ======================
# FINAL DECISION
# ======================

if secret_found:
    print("\n🚨 SECRET LEAK DETECTED — BLOCKING BUILD")
    print(f"Risk Level: {risk_level}")
    print("Suggested Fix: Remove hardcoded credentials")

    # Logging
    with open("scan_log.txt", "a") as log:
        log.write("SECRET THREAT DETECTED | Risk: HIGH\n")

    sys.exit(1)

else:
    print("\n✅ No secrets detected")
    print(f"Risk Level: {risk_level}")

    with open("scan_log.txt", "a") as log:
        log.write("SECRET SCAN SAFE | Risk: LOW\n")
