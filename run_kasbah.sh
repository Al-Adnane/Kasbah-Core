#!/bin/zsh
# Auto-activates venv and runs scripts with strict error checking
SCRIPT_DIR="$(cd "$(dirname "$0)"; pwd)"

# 1. Activate Environment
if [ -f "venv/bin/activate" ]; then
    echo "Activating Virtual Environment..."
    source venv/bin/activate
fi

# 2. Install/Upgrade Dependencies
echo "Ensuring dependencies are installed..."
pip install --quiet numpy cryptography openai --upgrade

# 3. Run Tests
echo "Running Preflight Checks..."
python3 tests/robust_preflight.py

# 4. Run Demo
echo "Running Demo..."
python3 kasbah_main.py
