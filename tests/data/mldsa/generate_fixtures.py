"""Generate ML-DSA interop fixtures from the Python (securesystemslib) side.

These pin the wire format that the Rust implementation must reproduce byte for
byte: keyid computation, SPKI/PEM key encoding, and the TAP 21 pre-signing
string. Run with a venv that has securesystemslib (main, >= PR #1124) installed.

Existing key material is reused rather than regenerated, so re-running this does
not churn committed fixtures. Delete a .pem to roll that parameter set.
"""

import hashlib
import json
import pathlib

from cryptography.hazmat.primitives import serialization
from securesystemslib.formats import encode_canonical
from securesystemslib.signer import CryptoSigner, SSlibKey
from securesystemslib.signer._key import KEY_FOR_TYPE_AND_SCHEME
from securesystemslib.signer._utils import compute_default_keyid, get_mldsa_payload

PARAMETER_SETS = {
    "44": "ml-dsa-44/1",
    "65": "ml-dsa-65/1",
    "87": "ml-dsa-87/1",
}

for scheme in PARAMETER_SETS.values():
    KEY_FOR_TYPE_AND_SCHEME[("ml-dsa", scheme)] = SSlibKey

HERE = pathlib.Path(__file__).parent
MSG = b"in-toto interop fixture: the quick brown fox"


def load_or_create(name: str, scheme: str) -> CryptoSigner:
    """Reuse the committed key for this parameter set, or mint a new one."""
    private_pem = HERE / f"mldsa{name}_private.pem"

    if private_pem.exists():
        private_key = serialization.load_pem_private_key(
            private_pem.read_bytes(), password=None
        )
        return CryptoSigner(private_key)

    signer = CryptoSigner.generate_mldsa(scheme=scheme)
    private_key = signer._private_key  # noqa: SLF001
    private_pem.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return signer


for name, scheme in PARAMETER_SETS.items():
    signer = load_or_create(name, scheme)
    pub = signer.public_key
    private_key = signer._private_key  # noqa: SLF001

    assert pub.scheme == scheme, f"{pub.scheme} != {scheme}"

    (HERE / f"mldsa{name}_public.pem").write_bytes(
        private_key.public_key().public_bytes(
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
    pub.verify_signature(sig, MSG)

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
    (HERE / f"mldsa{name}_fixture.json").write_text(
        json.dumps(fixture, indent=2) + "\n"
    )

    print(
        f"ml-dsa-{name}: keyid {pub.keyid[:16]}... "
        f"sig {fixture['signature_len']}B  verified"
    )
