"""
Reworked from fiatjaf's gist:
https://gist.github.com/fiatjaf/e3232bef6d59263b439b97b6d04d1bcc

Derive node private key from the hsm_secret
"""

import hashlib
import logging

import hkdf
import lightning
import secp256k1

from src.util import CustomAdapter

logger = CustomAdapter(logging.getLogger("pkhsm"), None)
nodes = [0, 1, 2]


def get_privkey(ln_dir, known_pubkey: str):
    hsm_secret = open(f"{ln_dir}/hsm_secret", "rb").read()
    logger.debug(f"hsm_secret: {hsm_secret}")

    # To generate the node private key, apply hkdf to string b"nodeid"
    salt = bytes([0]) or b"\x00"
    key = hkdf.Hkdf(salt, hsm_secret, hash=hashlib.sha256).expand(b"nodeid")

    # Small chance of the key produced not being valid to secp256k1 parameters, so test
    # and increase the salt until it is valid.
    i = 0
    privkey = b""
    while True and i < 1000:
        if i == 999:
            logger.error("No valid secp256k1 key found for hsm secret after 1000 salts")
            return False
        try:
            privkey = secp256k1.PrivateKey(key)
        except Exception:
            # invalid key
            i += 1
            salt = bytes([i])
            key = hkdf.Hkdf(salt, hsm_secret, hash=hashlib.sha256).expand(b"nodeid")
        else:
            # Key valid under secp256k1
            break

    # Check public key derived from the private key against node id
    if not privkey.pubkey.serialize().hex() == known_pubkey:
        logger.warning(
            f"Valid secp265k1 derived pubkey doesn't appear to match "
            f"lightning node id:"
        )
        logger.warning(f"generated: {privkey.pubkey.serialize().hex()}")
        logger.warning(f"actual:    {known_pubkey}")
    return key.hex()


def main():
    for node in nodes:
        ln_dir = f"/tmp/l{node + 1}-regtest/regtest"
        ln = lightning.LightningRpc(f"{ln_dir}/lightning-rpc")
        pubkey = ln.getinfo()["id"]
        logger.info(f"Node {node +1}:")
        logger.info(f"privkey: {get_privkey(ln_dir, pubkey)}")
        logger.info(f"pubkey:  {pubkey}")


if __name__ == "__main__":
    main()
