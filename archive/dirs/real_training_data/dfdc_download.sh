#!/bin/bash
# DFDC Download Script

# Option 1: AWS S3 (requires AWS CLI configured)
# aws s3 cp s3://dfdc/ ./dfdc/ --recursive

# Option 2: Kaggle (requires kaggle CLI configured)
kaggle competitions download -c deepfake-detection-challenge
unzip deepfake-detection-challenge.zip -d dfdc/

# Expected size: ~100GB for full dataset
echo "✅ DFDC download complete"