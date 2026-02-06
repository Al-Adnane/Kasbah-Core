#!/usr/bin/env python3
"""
FIND ALL 13 MOATS - Searches entire codebase for all 13 patented moats
"""

import os
import re
import sys
from pathlib import Path

print("🔍 SEARCHING FOR ALL 13 PATENTED MOATS")
print("=" * 60)

# Define all 13 moats with their descriptions
MOATS = {
    1: "Bidirectional feedback (I(t)→τ, P_threat→θ)",
    2: "Weighted geometric mean integrity",
    3: "Brittleness calculation B(r) = usage/Σusage",
    4: "Ticket generation (sub-100ms)",
    5: "Dynamic threshold modulation",
    6: "QIFT (adaptive Feature Transformation)",
    7: "CAIL (audit ledger with hash chaining)",
    8: "Adversarial pattern detection",
    9: "Predictive threat forecasting",
    10: "Cryptographic signing (HMAC-SHA256)",
    11: "TOCTOU prevention (one-time use)",
    12: "Resource monitoring (3 resources tracked)",
    13: "Phase-lead compensation"
}

# Search patterns for each moat
PATTERNS = {
    1: [r"bidirectional", r"feedback.*loop", r"I\(t\)→τ", r"P_threat→θ"],
    2: [r"weighted.*geometric.*mean", r"geometric.*mean.*integrity", r"wgm"],
    3: [r"brittleness.*calculation", r"B\(r\)\s*=\s*usage", r"usage/Σusage"],
    4: [r"ticket.*generation", r"sub.*100ms", r"ticket.*<.*100"],
    5: [r"dynamic.*threshold.*modulation", r"threshold.*adjust"],
    6: [r"QIFT", r"quantum.*inspired.*feature", r"feature.*transformation"],
    7: [r"CAIL", r"audit.*ledger", r"hash.*chain", r"tamper.*evident"],
    8: [r"adversarial.*pattern.*detection", r"attack.*pattern"],
    9: [r"predictive.*threat.*forecasting", r"threat.*prediction"],
    10: [r"HMAC-SHA256", r"cryptographic.*signing", r"digital.*signature"],
    11: [r"TOCTOU", r"one.*time.*use", r"time.*of.*check.*time.*of.*use"],
    12: [r"resource.*monitoring", r"cpu.*usage", r"memory.*usage", r"network.*io"],
    13: [r"phase.*lead.*compensation", r"compensation.*47%", r"MTTD.*improvement"]
}

# Alternative file names for audit ledger
AUDIT_FILES = [
    "audit_ledger.py",
    "audit.py",
    "audit_trail.py",
    "audit_log.py",
    "ledger.py",
    "cail.py",
    "audit_chain.py",
    "audit_module.py",
    "audit_system.py"
]

# Get current directory
base_dir = Path(__file__).parent

# Store results
found_moats = {}
missing_moats = []
audit_files_found = []

print("\n📁 SEARCHING FILES...")
print("-" * 40)

# First, find all Python files
python_files = []
for root, dirs, files in os.walk(base_dir):
    # Skip some directories
    if any(skip in root for skip in ['.git', '__pycache__', 'venv', '.pytest_cache']):
        continue
    
    for file in files:
        if file.endswith('.py'):
            python_files.append(Path(root) / file)

print(f"Found {len(python_files)} Python files")

# Search for audit files
print("\n🔍 LOOKING FOR AUDIT LEDGER FILES...")
for audit_file in AUDIT_FILES:
    for root, dirs, files in os.walk(base_dir):
        if audit_file in files:
            full_path = Path(root) / audit_file
            audit_files_found.append(str(full_path))
            print(f"✅ Found: {audit_file} at {full_path.relative_to(base_dir)}")

# Also search for audit-related content in any file
print("\n🔍 SEARCHING FOR AUDIT-RELATED CODE...")
audit_keywords = ["audit", "ledger", "cail", "hash chain", "tamper", "verification"]
for python_file in python_files:
    try:
        with open(python_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read().lower()
            
            # Check if it looks like an audit module
            if any(keyword in content for keyword in ["class auditledger", "class auditledger", "def audit_log"]):
                if str(python_file) not in audit_files_found:
                    audit_files_found.append(str(python_file))
                    print(f"⚠️  Possible audit module: {python_file.relative_to(base_dir)}")
    except:
        continue

# Now search for each moat
print("\n🔍 SEARCHING FOR ALL 13 MOATS...")
print("-" * 40)

for moat_num, moat_desc in MOATS.items():
    print(f"\nMoat {moat_num}: {moat_desc}")
    found = False
    matches = []
    
    # Search in each Python file
    for python_file in python_files:
        try:
            with open(python_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                content_lower = content.lower()
                
                # Check each pattern for this moat
                for pattern in PATTERNS[moat_num]:
                    if re.search(pattern, content_lower, re.IGNORECASE):
                        # Get line with match
                        lines = content.split('\n')
                        for i, line in enumerate(lines):
                            if re.search(pattern, line, re.IGNORECASE):
                                match_info = {
                                    'file': python_file.relative_to(base_dir),
                                    'line': i + 1,
                                    'code': line.strip()[:100] + '...' if len(line.strip()) > 100 else line.strip()
                                }
                                matches.append(match_info)
                                found = True
        except:
            continue
    
    if found:
        found_moats[moat_num] = matches
        print(f"✅ Found in {len(matches)} location(s)")
        # Show first 2 matches
        for i, match in enumerate(matches[:2]):
            print(f"   {i+1}. {match['file']}:{match['line']} - {match['code']}")
        if len(matches) > 2:
            print(f"   ... and {len(matches) - 2} more")
    else:
        missing_moats.append(moat_num)
        print("❌ Not found")

# Check main.py specifically for moat usage
print("\n🔍 CHECKING MAIN.PY FOR MOAT INTEGRATION...")
main_path = base_dir / "apps" / "api" / "main.py"
if main_path.exists():
    with open(main_path, 'r') as f:
        main_content = f.read()
    
    moats_in_main = []
    for moat_num in range(1, 14):
        # Check for common moat function names
        moat_indicators = [
            f"moat_{moat_num}",
            f"moat{moat_num}",
            f"brittleness" if moat_num == 3 else "",
            f"integrity.*score" if moat_num == 2 else "",
            f"audit.*log" if moat_num == 7 else "",
            f"threat.*forecast" if moat_num == 9 else "",
        ]
        
        for indicator in moat_indicators:
            if indicator and re.search(indicator, main_content.lower()):
                moats_in_main.append(moat_num)
                break
    
    print(f"Found references to {len(moats_in_main)} moats in main.py")
    if moats_in_main:
        print(f"Moat numbers: {sorted(moats_in_main)}")
else:
    print("main.py not found")

# Summary
print("\n" + "=" * 60)
print("📊 COMPREHENSIVE MOAT ANALYSIS")
print("=" * 60)

print(f"\n✅ Found {len(found_moats)}/13 moats in codebase")
print(f"❌ Missing {len(missing_moats)}/13 moats: {missing_moats}")

print(f"\n🔍 Audit ledger files found: {len(audit_files_found)}")
for audit_file in audit_files_found:
    print(f"   • {Path(audit_file).relative_to(base_dir)}")

print("\n📋 DETAILED BREAKDOWN:")
for moat_num in range(1, 14):
    status = "✅" if moat_num in found_moats else "❌"
    print(f"{status} Moat {moat_num:2d}: {MOATS[moat_num]}")

print("\n" + "=" * 60)
print("🎯 RECOMMENDATIONS:")
print("=" * 60)

if len(found_moats) >= 10:
    print("✅ Good news! You have 10+ moats implemented.")
    print("Most core functionality is present.")
elif len(found_moats) >= 7:
    print("⚠️  You have 7-9 moats implemented.")
    print("Core system works but some features missing.")
else:
    print("❌ You have less than 7 moats implemented.")
    print("Significant gaps in functionality.")

if audit_files_found:
    print("\n✅ Audit ledger found. Moat 7 is likely implemented.")
else:
    print("\n❌ No audit ledger found. Moat 7 is missing.")
    print("   Check if it's named differently or in a different location.")

# Create a summary report
report_path = base_dir / "moat_analysis_report.txt"
with open(report_path, 'w') as f:
    f.write("KASBAH MOAT ANALYSIS REPORT\n")
    f.write("=" * 40 + "\n\n")
    f.write(f"Total moats found: {len(found_moats)}/13\n\n")
    
    for moat_num in range(1, 14):
        if moat_num in found_moats:
            f.write(f"✅ Moat {moat_num}: {MOATS[moat_num]}\n")
            for match in found_moats[moat_num][:3]:  # First 3 matches
                f.write(f"   - {match['file']}:{match['line']}\n")
        else:
            f.write(f"❌ Moat {moat_num}: {MOATS[moat_num]}\n")
    
    f.write(f"\nAudit files found: {len(audit_files_found)}\n")
    for audit_file in audit_files_found:
        f.write(f"  - {audit_file}\n")

print(f"\n📄 Full report saved to: {report_path.relative_to(base_dir)}")
print(f"\nTime: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
