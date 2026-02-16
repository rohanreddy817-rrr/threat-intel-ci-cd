import os
import sys
import re

print("=== Secret Leak Scan Started ===")

secret_found = False

# Common secret patterns
patterns = [
    r"AKIA[0-9A-Z]{16}",      # AWS key
    r"password\s*=",          # password assignment
    r"api[_-]?key\s*=",       # api key
    r"secret\s*=",            # secret
    r"token\s*="              # token
]

for root, _, files in os.walk("."):
    for file in files:

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

        except:
            pass


if secret_found:
    print("❌ SECRET LEAK DETECTED — BLOCKING BUILD")
    sys.exit(1)
else:
    print("✅ No secrets detected")
