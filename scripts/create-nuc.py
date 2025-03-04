#!/usr/bin/env -S uv run --script
# /// script
# dependencies = [
#   "requests==2.32.3",
#   "secp256k1==0.14.0",
# ]
# ///


import json
import requests
import secrets
from secp256k1 import PrivateKey


if __name__ == "__main__":
    key = PrivateKey()
    payload = json.dumps(
        {
            "nonce": list(secrets.token_bytes(16)),
        }
    ).encode("utf8")
    signature = key.ecdsa_serialize_compact(key.ecdsa_sign(payload))
    request = {
        "public_key": key.pubkey.serialize(True).hex(),
        "signature": signature.hex(),
        "payload": payload.hex(),
    }
    response = requests.post("http://127.0.0.1:30921/api/v1/nucs/create", json=request)
    response.raise_for_status()
    response = response.json()
    print(json.dumps(response))
