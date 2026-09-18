"""Verify an in-toto-rs ML-DSA signature with securesystemslib.

Closes the second half of the interop loop: `mldsa_interop.rs` checks that Rust
verifies Python's signatures, this checks that Python verifies Rust's.

    cargo run --example emit_mldsa_signature --features mldsa \
      | python tests/data/mldsa/verify_rust_signature.py
"""

import json
import sys

from securesystemslib.signer import Key, Signature, SSlibKey
from securesystemslib.signer._key import KEY_FOR_TYPE_AND_SCHEME

for scheme in ("ml-dsa-44/1", "ml-dsa-65/1", "ml-dsa-87/1"):
    KEY_FOR_TYPE_AND_SCHEME[("ml-dsa", scheme)] = SSlibKey

data = json.load(sys.stdin)

key = Key.from_dict(
    data["keyid"],
    {
        "keytype": data["keytype"],
        "scheme": data["scheme"],
        "keyval": {"public": data["public_pem"]},
    },
)

if key.keyid != data["keyid"]:
    sys.exit(
        f"keyid mismatch:\n  rust:   {data['keyid']}\n  python: {key.keyid}"
    )

key.verify_signature(
    Signature(data["keyid"], data["signature_hex"]),
    data["msg_utf8"].encode(),
)

print("OK: securesystemslib verified the in-toto-rs signature")
print(f"    keyid agreed: {key.keyid}")
