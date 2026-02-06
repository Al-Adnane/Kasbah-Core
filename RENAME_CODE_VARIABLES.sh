#!/bin/bash

echo "🏷️  RENAMING VARIABLES: Aligning Code with Reality..."

# Renaming 'ed25519' references in python files
find apps/api -name "*.py" -not -path "*/__pycache__/*" -exec sed -i.bak 's/ed25519/hmac_sha256/g' {} \;
find apps/api -name "*.py" -not -path "*/__pycache__/*" -exec sed -i.bak 's/Ed25519/HMAC_SHA256/g' {} \;

# Renaming 'kernel_gate' if it implies kernel level (optional, but maybe too risky for imports)
# We'll leave class names alone for now, but fix comments.

echo "✅ Variables renamed."
echo "Reviewing diffs..."
git diff --stat

