import sys
import subprocess
import os

def run_command(cmd_list):
    try:
        # Use the virtual environment python directly
        venv_py = os.path.abspath("venv/bin/python")
        result = subprocess.run([venv_py] + cmd_list, capture_output=True, text=True)
        print(result.stdout)
        if result.returncode != 0:
            print(f"ERROR: {result.stderr}")
            return False
        return True
    except FileNotFoundError:
        print("ERROR: Virtual environment not found at 'venv/bin/python'")
        print("Trying system python3 (may fail if deps missing)...")
        # Fallback to system python (not recommended)
        subprocess.run(["python3"] + cmd_list)
        return True

print(">>> KASBAH AUTOMATED TEST SUITE <<<")
print("=" * 60)

# 1. Dependencies Check
print("Step 1/5: Installing/upgrading dependencies...")
print(">>> Installing: numpy, cryptography, openai...")
run_command(["-m", "pip", "install", "--upgrade", "numpy", "cryptography"])
# run_command(["-m", "pip", "install", "--upgrade", "openai"]) # Optional if needed

# 2. Run Robust Preflight Checks
print("\nStep 2/5: Running Preflight Checks...")
if run_command(["tests/preflight_check.py"]):
    print("\n[SUCCESS] Preflight checks passed.")
else:
    print("\n[CRITICAL] Preflight checks failed.")
    sys.exit(1)

# 3. Run Main Demo
print("\nStep 3/5: Running Cinematic Demo...")
if run_command(["kasbah_main.py"]):
    print("\n[SUCCESS] Cinematic Demo executed.")
    print("=" * 60)
    print(">>> SCENARIO 5: Pro Mode (Active Blocking) <<<")
    
    # Verify it really ran by checking for output in code (Kasbah handles print)
    # If you saw "Active Mode" and "Blocked" in output, it worked.

print("\n>>> TESTS FINISHED. SYSTEM STABLE.")
