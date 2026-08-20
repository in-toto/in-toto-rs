"""Generate ML-DSA interop fixtures from the Python (securesystemslib) side.

These pin the wire format that the Rust implementation must reproduce byte for
byte: keyid computation, SPKI/PEM key encoding, and the TAP 21 pre-signing
string. Run with a venv that has securesystemslib (main, >= PR #1124) installed.
"""

import hashlib
import json
import pathlib

from securesystemslib.formats import encode_canonical
from securesystemslib.signer import CryptoSigner, SSlibKey
from securesystemslib.signer._key import KEY_FOR_TYPE_AND_SCHEME
from securesystemslib.signer._utils import compute_default_keyid, get_mldsa_payload

from cryptography.hazmat.primitives import serialization

for s in ("ml-dsa-44/1", "ml-dsa-65/1", "ml-dsa-87/1"):
    KEY_FOR_TYPE_AND_SCHEME[("ml-dsa", s)] = SSlibKey

HERE = pathlib.Path(__file__).parent
MSG = b"in-toto interop fixture: the quick brown fox"

signer = CryptoSigner.generate_mldsa(scheme="ml-dsa-65/1")
pub = signer.public_key
priv = signer._private_key  # noqa: SLF001

(HERE / "mldsa65_private.pem").write_bytes(
    priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
)
(HERE / "mldsa65_public.pem").write_bytes(
    priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
)

# --- exactly what securesystemslib hashes to get the keyid ---
keyval = pub.to_dict()["keyval"]
canonical = encode_canonical(
    {"keytype": pub.keytype, "scheme": pub.scheme, "keyval": keyval}
)
assert (
    hashlib.sha256(canonical.encode()).hexdigest()
    == compute_default_keyid(pub.keytype, pub.scheme, keyval)
    == pub.keyid
)

presign = get_mldsa_payload(MSG, 1)
sig = signer.sign(MSG)

fixture = {
    "keytype": pub.keytype,
    "scheme": pub.scheme,
    "keyid": pub.keyid,
    "keyid_canonical_json": canonical,
    "keyid_includes_keyid_hash_algorithms": False,
    "msg_utf8": MSG.decode(),
    "presign_hex": presign.hex(),
    "presign_construction": 'b"tuf" || 0x01 || SHA-512(msg)',
    "signature_hex": sig.signature,
    "signature_len": len(bytes.fromhex(sig.signature)),
}
(HERE / "mldsa65_fixture.json").write_text(json.dumps(fixture, indent=2) + "\n")

print("keyid                :", pub.keyid)
print("canonical json       :", canonical[:120], "...")
print("presign              :", presign[:8].hex(), "... len", len(presign))
print("signature len        :", fixture["signature_len"])
print("verify roundtrip     :", pub.verify_signature(sig, MSG) is None)
