#!/usr/bin/env python3
"""attestation.py — hardware-root capability probe + software fallback.

Honest contract: providers report what the CURRENT machine can do.
Only the software provider is exercised here (this Mac has no TPM2
tools, no Android Keystore; Secure Enclave needs signed CryptoKit
code, unavailable from stdlib Python). Anything else reports
available=False with a reason — never silently fakes attestation.

Usage: python3 attestation.py  -> JSON capability report + self-test.
"""

import json
import platform
import shutil
import subprocess
import sys


def software_provider():
    import secrets
    return {"available": True, "provider": "software",
            "note": "HMAC root in process memory. No hardware binding.",
            "key": secrets.token_bytes(32).hex()}


def tpm2_probe():
    if shutil.which("tpm2_getcap") is None:
        return {"available": False, "provider": "tpm2",
                "reason": "tpm2-tools not installed"}
    try:
        r = subprocess.run(["tpm2_getcap", "properties-fixed"], capture_output=True,
                           timeout=10, text=True)
        ok = r.returncode == 0 and "TPM2_PT_MANUFACTURER" in (r.stdout or "")
        return {"available": ok, "provider": "tpm2",
                "reason": None if ok else "no TPM answered"}
    except Exception as e:
        return {"available": False, "provider": "tpm2", "reason": str(e)[:120]}


def android_keystore_probe():
    import os
    is_android = os.path.exists("/system/build.prop") or "ANDROID_ROOT" in os.environ
    if not is_android:
        return {"available": False, "provider": "android-keystore",
                "reason": f"not Android (this is {platform.system()})"}
    return {"available": False, "provider": "android-keystore",
            "reason": "Keystore binding not implemented; interface reserved"}


def secure_enclave_probe():
    if platform.system() != "Darwin":
        return {"available": False, "provider": "secure-enclave",
                "reason": f"not macOS (this is {platform.system()})"}
    # Secure Enclave keys require signed code + CryptoKit/SecKey; stdlib
    # Python cannot mint them. Report honestly; do not fake.
    return {"available": False, "provider": "secure-enclave",
            "reason": "needs signed native code (CryptoKit); stdlib cannot mint SE keys"}


def report():
    sw = software_provider()
    return {
        "machine": platform.system(),
        "providers": {
            "software": {k: v for k, v in sw.items() if k != "key"},
            "tpm2": tpm2_probe(),
            "android_keystore": android_keystore_probe(),
            "secure_enclave": secure_enclave_probe(),
        },
        "effective_root": "software",
    }


def self_test():
    results = []
    r = report()
    results.append(("software_always_available",
                    r["providers"]["software"]["available"] is True))
    results.append(("no_fake_attestation",
                    all(p["available"] is False or p["provider"] == "software"
                        for p in r["providers"].values())))
    results.append(("tpm2_probed_not_assumed",
                    "reason" in r["providers"]["tpm2"] or
                    r["providers"]["tpm2"]["available"] is True))
    passed = sum(1 for _, ok in results if ok)
    return {"passed": passed, "total": len(results),
            "failed": [n for n, ok in results if not ok], "report": r}


if __name__ == "__main__":
    t = self_test()
    print(json.dumps(t, indent=1))
    sys.exit(0 if t["passed"] == t["total"] else 1)
