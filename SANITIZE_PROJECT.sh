#!/bin/bash

echo "🔧 FIXING THE LIES: Replacing False Claims with Honesty..."
echo "===================================================================="

FILES_TO_FIX=$(find . -type f \( -name "*.md" -o -name "*.txt" -o -name "*.rst" -o -name "*.py" \) -not -path "./.git/*" -not -path "./venv/*")

for file in $FILES_TO_FIX; do
    echo "Sanitizing: $file"
    
    # 1. Crypto Claims
    sed -i.bak 's/Ed25519/HMAC-SHA256/gi' "$file"
    sed -i.bak 's/ed25519/hmac-sha256/gi' "$file"
    
    # 2. Execution Level Claims
    sed -i.bak 's/kernel-level/API-level/gi' "$file"
    sed -i.bak 's/kernel level/API level/gi' "$file"
    
    # 3. Hype Claims
    sed -i.bak 's/quantum-inspired/adaptive/gi' "$file"
    sed -i.bak 's/quantum inspired/adaptive/gi' "$file"
    
    # 4. Attack Claims
    sed -i.bak 's/detects.*FGSM/detects anomalies/gi' "$file"
    sed -i.bak 's/detects.*C&W/detects anomalies/gi' "$file"
    sed -i.bak 's/detects.*DeepFool/detects anomalies/gi' "$file"
    
    # 5. Unproven Metrics
    sed -i.bak 's/47% MTTD/significantly faster/gi' "$file"
    
    # 6. Moat Count Claims
    # (Be careful here, we only do a broad replacement for demo purposes)
    # sed -i.bak 's/13 Moats/7 Proven Moats/gi' "$file" 
done

echo ""
echo "===================================================================="
echo "✅ Sanitization Complete."
echo "Backup files created with .bak extension."
echo ""
echo "NEXT STEP: Review the changes in your README.md."
echo "Update your marketing to reflect: '7 Proven Security Layers'."

