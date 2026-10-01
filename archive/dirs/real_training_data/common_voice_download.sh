#!/bin/bash
# Common Voice Download Script

# Option 1: Direct download (English, ~40GB)
wget https://mozilla-common-voice-datasets.s3.amazonaws.com/cv-corpus-15.0/en.tar.gz
tar -xzf en.tar.gz -d common_voice/

# Option 2: Using HuggingFace (Python)
# pip install datasets
# python3 -c "
# from datasets import load_dataset
# dataset = load_dataset('mozilla-foundation/common_voice_11_0', 'en')
# dataset.save_to_disk('common_voice_dataset')
# "

echo "✅ Common Voice download complete"