#!/bin/bash

echo "🔍 BRUTAL HONESTY AUDIT: Scanning for False Claims..."
echo "===================================================================="

# Define keywords to search for based on the Reality Check
CLAIMS=(
    "Ed25519"
    "kernel-level"
    "kernel level"
    "quantum-inspired"
    "quantum inspired"
    "FGSM"
    "C&W"
    "DeepFool"
    "47%"  # Unproven metric
    "13.*moats" # Only have 7.5
    "sub-100ms.*execution.*tickets" # False claim
)

echo ""
echo "📄 Scanning Markdown and Text Files (README, docs)..."
echo "--------------------------------------------------------------------"

# Search in text/markdown files
find . -type f \( -name "*.md" -o -name "*.txt" -o -name "*.rst" \) -not -path "./.git/*" -not -path "./venv/*" | while read file; do
    echo ""
    echo "File: $file"
    for keyword in "${CLAIMS[@]}"; do
        if grep -i -q "$keyword" "$file"; then
            echo -e "  ❌ FOUND: '$keyword'"
            echo -e "     Line: $(grep -i -n "$keyword" "$file" | head -1)"
        fi
    done
done

echo ""
echo "🐍 Scanning Python Source Code (kernel_gate.py, etc.)..."
echo "--------------------------------------------------------------------"

find apps/api/rtp -name "*.py" -not -path "*/__pycache__/*" | while read file; do
    echo ""
    echo "File: $file"
    for keyword in "${CLAIMS[@]}"; do
        if grep -i -q "$keyword" "$file"; then
            echo -e "  ⚠️  FOUND IN CODE: '$keyword'"
            echo -e "     Line: $(grep -i -n "$keyword" "$file" | head -1)"
        fi
    done
done

echo ""
echo "===================================================================="
echo "✅ Audit Complete."
echo "Review the findings above. These are the claims you must fix."

