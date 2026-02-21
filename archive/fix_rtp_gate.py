import sys
import subprocess
import os

print(">>> KASBAH AUTOMATED FIX SCRIPT <<<")

# 1. Determine Python Executable
# If 'python' is missing, we use 'python3'
py_exe = sys.executable
print(f"[INFO] Using Python: {py_exe}")

# 2. Install Dependencies (Bypassing missing 'pip' command)
print("[INFO] Ensuring 'numpy' and 'cryptography' are installed...")
try:
    subprocess.check_call([py_exe, "-m", "pip", "install", "numpy"])
except Exception:
    pass # Assume it's there or handled

try:
    subprocess.check_call([py_exe, "-m", "pip", "install", "cryptography"])
except Exception:
    pass # Assume it's there or handled

# 3. Run Kasbah Main
print("[INFO] Launching Kasbah Engine...")
subprocess.call([py_exe, "kasbah_main.py"])
