"""
Reworked from fiatjaf's gist:
https://gist.github.com/fiatjaf/e3232bef6d59263b439b97b6d04d1bcc
"""

# derive node private key from the hsm_secret
import hashlib

import secp256k1
from hkdf import Hkdf
from lightning import LightningRpc

import lnproxy.config as config

nodes = [0, 1, 2]


def get_privkey(_node):
    ln_dir = config.NODE_DIR[_node]
    hsm_secret = open(f"{ln_dir}/{config.network}/hsm_secret", "rb").read()

    # To generate the node private key, apply hkdf to string b"nodeid"
    salt = bytes([0]) or b"\x00"
    key = Hkdf(salt, hsm_secret, hash=hashlib.sha256).expand(b"nodeid")

    # Small chance of the key produced not being valid to secp256k1 parameters, so test
    # and increase the salt until it is valid.
    # Maybe secp256k1 will raise an exception if the key is wrong?
    i = 0
    privkey = b""
    while True and i < 1000:
        if i == 999:
            print("No valid secp256k1 key found for hsm secret after 1000 salts")
            return False
        try:
            privkey = secp256k1.PrivateKey(key)
            # valid key
            break
        except:
            # invalid key?
            i += 1
        salt = bytes([i])
        key = Hkdf(salt, hsm_secret, hash=hashlib.sha256).expand(b"nodeid")

    # Check public key derived from the private key against node id
    ln = LightningRpc(f"{ln_dir}/{config.network}/lightning-rpc")
    if not privkey.pubkey.serialize().hex() == ln.getinfo()["id"]:
        print(
            f"Warning, valid secp265k1 derived pubkey doesn't appear to match "
            f"lightning node id"
        )
    return key.hex()


def main():
    for node in nodes:
        print(f"Node l{node} privkey: {get_privkey(node)}")


if __name__ == "__main__":
    main()
