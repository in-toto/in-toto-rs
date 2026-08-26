"""Generate DSSE interop fixtures with securesystemslib, the reference impl.

These pin the wire format: field names, base64 of the payload and of the
signature, and the PAE bytes that are actually signed.
"""

import json
import pathlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from securesystemslib.dsse import Envelope
from securesystemslib.signer import CryptoSigner, SSlibKey

HERE = pathlib.Path(__file__).parent

PAYLOAD = b'{"_type":"link","name":"rebuild example_1.0_all.deb"}'
PAYLOAD_TYPE = "application/vnd.in-toto+json"

private_key = Ed25519PrivateKey.generate()
public_key = SSlibKey.from_crypto(private_key.public_key())
signer = CryptoSigner(private_key, public_key)

envelope = Envelope(PAYLOAD, PAYLOAD_TYPE, {})
signature = envelope.sign(signer)
envelope.verify([public_key], 1)

# in-toto-rs loads ed25519 as seed || public key
raw_private = private_key.private_bytes_raw()
raw_public = private_key.public_key().public_bytes_raw()

(HERE / "envelope.json").write_text(json.dumps(envelope.to_dict(), indent=2) + "\n")
(HERE / "fixture.json").write_text(
    json.dumps(
        {
            "keyid": public_key.keyid,
            "key_ed25519_hex": (raw_private + raw_public).hex(),
            "public_hex": raw_public.hex(),
            "payload_utf8": PAYLOAD.decode(),
            "payload_type": PAYLOAD_TYPE,
            "pae_utf8": envelope.pae().decode("utf-8", "replace"),
            "signature_hex": signature.signature,
        },
        indent=2,
    )
    + "\n"
)

print("keyid  :", public_key.keyid)
print("pae    :", envelope.pae()[:60])
print("wire   :", json.dumps(envelope.to_dict())[:120])
