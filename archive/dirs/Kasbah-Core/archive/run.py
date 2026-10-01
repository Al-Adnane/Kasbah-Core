import subprocess
import sys

def run_safely(cmd_list):
    """
    Runs commands and handles Unicode/Encoding errors from pip/system output.
    """
    print(f"--- EXECUTING: {' '.join(cmd_list)} ---")
    
    try:
        # Capture output as raw bytes (avoiding decode errors in `subprocess`)
        # We use check=True to avoid hanging on exit
        result = subprocess.run(
            cmd_list,
            capture_output=True,
            check=True,
            text=False # Disable automatic text decoding
        )
        
        # Process stdout (bytes -> string)
        # We attempt utf-8, but fall back to ignore if it fails
        if result.stdout:
            try:
                print(result.stdout.decode('utf-8', errors='ignore'))
            except UnicodeDecodeError:
                # If progress bars break decoding, print raw bytes representation
                # This proves data was received
                print("[WARN] UnicodeDecodeError in system output (likely pip progress bars).")
                # Try latin-1 as a fallback
                try:
                    print(result.stdout.decode('latin-1'))
                except:
                    print(result.stdout[:200]) # Print first 200 chars safely
            except:
                print(result.stdout) # Print raw bytes if all else fails
        else:
            print("[WARN] No stdout captured.")
        
        # Return Success (0) or Failure (non-0)
        if result.returncode == 0:
            print("[SUCCESS] Command executed successfully.")
            return True
        else:
            print(f"[FAIL] Command failed with code {result.returncode}.")
            return False

    except Exception as e:
        print(f"[CRITICAL ERROR] {e}")
        return False

if __name__ == "__main__":
    print(">>> KASBAH AUTOMATED TEST SUITE <<<")

    # 1. Find Python
    # We use sys.executable to ensure we use the venv python
    python_bin = sys.executable

    # 2. Install/Upgrade Dependencies
    print("\n[STEP 1] Installing dependencies (numpy, cryptography, openai)...")
    run_safely([
        python_bin, "-m", "pip", "install", "numpy"
    ])
    run_safely([
        python_bin, "-m", "pip", "install", "cryptography"
    ])
    run_safely([
        python_bin, "-m", "pip", "install", "openai"
    ])

    # 3. Run Tests
    print("\n[STEP 2] Running Preflight Checks...")
    run_safely([python_bin, "tests/robust_preflight.py"])

    # 4. Run Demo
    print("\n[STEP 3] Running Cinematic Demo...")
    run_safely([python_bin, "kasbah_main.py"])
    
    print("\n" + "=" * 60)
    print("[SUMMARY]")
    print("If no CRITICAL errors occurred above, your system is ready.")
    print("=" * 60)
