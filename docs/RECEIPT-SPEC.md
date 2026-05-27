# Kasbah Receipt Specification — v2

**Status:** Stable
**Algorithm:** Ed25519 (RFC 8032)
**Canonical encoding:** sorted-key JSON, UTF-8, no whitespace
**Verification:** offline, public-key, vendor-independent

A Kasbah receipt is a portable, cryptographically-signed attestation that the
Kasbah engine made a governance decision at a point in time. Anyone with the
engine's public key can verify a receipt offline — no Kasbah API call, no
network round-trip, no vendor lock-in. Receipts are designed to **outlive the
company that issued them**.

This document is the complete specification. Anyone can implement a verifier
from this document plus the test vectors in §7.

---

## 1. Receipt string format

```
kasbah_receipt:v2:ed25519:<keyId>:<base64url(signature)>
```

| Field | Value |
|---|---|
| literal | `kasbah_receipt` |
| version | `v2` |
| algorithm | `ed25519` |
| `keyId` | first 16 hex chars of `SHA-256(raw 32-byte Ed25519 public key)` |
| signature | 64 raw bytes, base64url-encoded, no padding |

Example:

```
kasbah_receipt:v2:ed25519:9a3f1c2d4e5b6789:Hk7q...sB3aA
```

A receipt MUST be paired with its `payload` (§2) to be verifiable. The
receipt-string alone proves nothing — it is just a signature.

---

## 2. Payload

The payload is a JSON object encoded as **canonical JSON** (§3), then encoded
as base64url (no padding) for transport.

Required fields:

| Field | Type | Description |
|---|---|---|
| `v` | integer | Must be `2`. |
| `id` | string | Globally unique receipt id. |
| `ts` | integer | Unix milliseconds at signing time. |
| `engine` | string | Engine version (e.g. `"1.0.0"`). |
| `keyId` | string | Must match the `keyId` in the receipt string. |
| `verdict` | string | One of `"ALLOW"`, `"WARN"`, `"DENY"`. |
| `risk` | number | 0.0–1.0, 4 decimal places. |
| `requestId` | string | Caller-provided correlation id. |
| `subject` | string \| null | SHA-256 hash (hex) of the governed input, or `null`. |
| `passportId` | string \| null | Agent passport, if any. |

Optional fields (whitelisted — implementations MUST allow any of these):

| Field | Type | Description |
|---|---|---|
| `surface` | string | Where Kasbah ran (e.g. `"mcp"`, `"editor"`, `"api"`). |
| `action` | string | Action being governed (e.g. `"tool_call"`, `"file_write"`). |

Implementations MUST NOT reject a payload because it contains additional
fields. Unknown fields are part of the signed message and are returned to the
verifier as-is.

---

## 3. Canonical JSON

Verification requires byte-exact reproduction of the signed input. Canonical
JSON is defined as follows:

1. Object keys are sorted lexicographically (UTF-16 code unit order, which
   matches both ECMA-262 `Array.prototype.sort` on strings and Python's default
   `sorted()` on ASCII keys).
2. No whitespace anywhere.
3. UTF-8 encoding.
4. Strings escaped per RFC 8259 (`\"`, `\\`, `\/` optional, `\b \f \n \r \t`,
   and `\uXXXX` for control characters below 0x20). No other escapes.
5. Numbers in JSON canonical form: no leading zeros, no trailing zeros after a
   decimal point, no `+` sign, no exponent unless the value cannot be exactly
   represented in fixed notation. Integers are emitted without a decimal point.
6. `null`, `true`, `false` lowercase.
7. Arrays preserve order.
8. Keys with `undefined` values are omitted.

Reference implementation (50 lines of JavaScript) is included at the end of
this document (§8).

---

## 4. Signing

```
canonical    = canonicalJSON(payload)
signature    = Ed25519.sign(privateKey, canonical)        # 64 bytes
receipt      = "kasbah_receipt:v2:ed25519:" + keyId + ":" + base64url(signature)
payloadB64   = base64url(canonical)
```

The output is the pair `(receipt, payloadB64)`. Both are needed for
verification.

---

## 5. Verification

```
1. Parse receipt:
     parts = receipt.split(":")
     assert parts[0] == "kasbah_receipt"
     assert parts[1] == "v2"
     assert parts[2] == "ed25519"
     keyId  = parts[3]
     sigB64 = parts[4]
2. Fetch the public key for keyId (see §6).
3. canonical = base64urlDecode(payloadB64)
4. signature = base64urlDecode(sigB64)
5. Verify: Ed25519.verify(publicKey, canonical, signature) == true
6. Decode JSON: payload = JSON.parse(canonical)
7. Check payload.keyId == keyId
8. Optionally check payload.ts is recent / payload.v == 2
```

If any step fails, the receipt is invalid.

---

## 6. Key distribution

Public keys are published at three well-known locations, in priority order:

1. The engine's own host: `GET /.well-known/kasbah-keys.json`
2. The Kasbah site: `https://bekasbah.com/.well-known/kasbah-keys.json`
3. A static mirror referenced from the Kasbah GitHub README.

Format (JSON Web Key Set, RFC 7517 — minimal):

```json
{
  "issuer": "kasbah",
  "spec":   "https://bekasbah.com/spec/receipt-v2",
  "keys": [
    {
      "kid": "9a3f1c2d4e5b6789",
      "alg": "EdDSA",
      "crv": "Ed25519",
      "use": "sig",
      "x":   "<base64url(32-byte raw public key)>",
      "pem": "-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----",
      "createdAt": "2026-05-27T03:14:00Z"
    }
  ]
}
```

Implementations MUST accept either the `x` field (raw key) or the `pem` field.
Key rotation: future keys are appended to the `keys` array; old keys are kept
for verification of historic receipts.

---

## 7. Test vectors

These vectors let an implementer confirm they have built the spec correctly.
All four vectors use the **same fixed private key** so they are reproducible.

**Private key** (Ed25519, hex, 32 bytes):
```
833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42
```

**Public key** (Ed25519, hex, 32 bytes — derived from the private key):
```
ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf
```

**keyId** = first 16 hex chars of `SHA-256(public_key_bytes)`:
```
5f9b247e2a654719
```

### Vector 1 — minimum payload

Payload (after canonicalization, exact bytes):
```
{"engine":"1.0.0","id":"rcpt_test_001","keyId":"5f9b247e2a654719","passportId":null,"requestId":"req_test_001","risk":0,"subject":null,"ts":1700000000000,"v":2,"verdict":"ALLOW"}
```

Expected receipt:
```
kasbah_receipt:v2:ed25519:5f9b247e2a654719:EQjcc8dBVd4Op6MAuQaioMJsF_GH4040XuLLnRzbkLAVA9kVs_NlbuOn0tG-25FG4g5Dr8kkXQVn-aeeN8oVDA
```

Expected payloadB64:
```
eyJlbmdpbmUiOiIxLjAuMCIsImlkIjoicmNwdF90ZXN0XzAwMSIsImtleUlkIjoiNWY5YjI0N2UyYTY1NDcxOSIsInBhc3Nwb3J0SWQiOm51bGwsInJlcXVlc3RJZCI6InJlcV90ZXN0XzAwMSIsInJpc2siOjAsInN1YmplY3QiOm51bGwsInRzIjoxNzAwMDAwMDAwMDAwLCJ2IjoyLCJ2ZXJkaWN0IjoiQUxMT1cifQ
```

### Vector 2 — DENY with risk

Payload (canonicalized):
```
{"engine":"1.0.0","id":"rcpt_test_002","keyId":"5f9b247e2a654719","passportId":"kp_demo","requestId":"req_test_002","risk":0.9421,"subject":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","ts":1700000000000,"v":2,"verdict":"DENY"}
```

Expected receipt:
```
kasbah_receipt:v2:ed25519:5f9b247e2a654719:1Vix2M-sidACz63ybhT9EBRSB0KQvpXEYUHN7kaNU8u-hz9NkPRKrs10VPqXV72lBJccvwh7nZidI-R_VXRwDQ
```

### Vector 3 — tampered payload (MUST fail)

Take Vector 1's receipt, but change `verdict` from `"ALLOW"` to `"DENY"` in
the payload. Re-canonicalize, re-base64url. Verification MUST return `false`.

### Vector 4 — wrong keyId (MUST fail)

Take Vector 1's receipt and replace the `keyId` field inside the payload with
`"deadbeefdeadbeef"` while leaving the receipt-string's keyId at
`5f9b247e2a654719`. Verification MUST return `false` at step 7 of §5.

(Vectors 1–2 were generated with the reference implementation at
`packages/api-server/src/engine-key.js`. A script that regenerates them is at
`bench/generate-spec-vectors.js`.)

---

## 8. Reference canonical-JSON implementation

```javascript
function canonicalJSON(obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalJSON).join(',') + ']';
  const keys = Object.keys(obj).filter(k => obj[k] !== undefined).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJSON(obj[k])).join(',') + '}';
}
```

Python:

```python
import json
def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)
```

(Both produce byte-identical output for all payloads defined in this spec.)

---

## 9. Backward compatibility (v1)

v1 receipts use HMAC-SHA256 and are NOT publicly verifiable — they require
the engine's shared secret. The v1 format is retained for in-engine
replay-protection only. Any external integration MUST use v2.

Format (v1, deprecated for external use):
```
kasbah_receipt:v1:sha256:<hex hmac>
```

---

## 10. Changelog

- **v2** (this document) — Ed25519 public-key signatures, canonical JSON,
  well-known key distribution, world-proof verification.
- **v1** — HMAC-SHA256 (in-engine only).
