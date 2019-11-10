"""
Borrowed from fiatjaf's gist:
https://gist.github.com/fiatjaf/e3232bef6d59263b439b97b6d04d1bcc
"""

# extracting the node's private key from the hsm_secret file
import hashlib
import sys

import secp256k1
from hkdf import Hkdf
from lightning import LightningRpc


nodes = ["1", "2", "3"]


def print_privkeys(_node):
    # first thing: read the $LIGHTNING_DIR/hsm_secret
    # xxd -p ~/.lightning/hsm_secret | tr -d '\n' && echo ""

    hex_value = "" or sys.argv[-1]

    # if you have it hex-encoded (as given from the xxd line above)
    if hex_value and len(hex_value) > 60:
        # proceed to make it a binary string again
        from binascii import unhexlify

        hsm_secret = unhexlify(hex_value)
    else:
        # or read it directly

        # hsm_secret = open(expanduser("~/.lightning/hsm_secret"), "rb").read()
        hsm_secret = open(f"/tmp/l{_node}-regtest/hsm_secret", "rb").read()

    # to generate the node private key, you must apply this hkdf thing
    # (which is a special way to an hmac) to id

    salt = bytes([0]) or b"\x00"
    key = Hkdf(salt, hsm_secret, hash=hashlib.sha256).expand(b"nodeid")
    # print(key.hex())
    # we're done here.

    # however, in the c-lightning code they say there's a ridiculously small chance of the
    # key produced here not being valid to the secp256k1 parameters, so they test it
    # and increase the salt until it is valid.

    # if for some reason your key is not correct with salt 0 you can just increase it by 1
    # and be fine (in the majority of cases you can just use salt 0 and be fine)

    # how to test? I don't know, maybe secp256k1 will raise an exception if the key is wrong?

    i = 0
    while True:
        salt = bytes([i])
        key = Hkdf(salt, hsm_secret, hash=hashlib.sha256).expand(b"nodeid")
        try:
            secp256k1.PrivateKey(key)
            break
        except:
            i += 1
    # print(key.hex())

    # maybe you want to be extra-sure. in that case you can check the public key generated
    # from the private key obtained here against the public key your node is advertising
    # to everybody.

    ln = LightningRpc(f"/tmp/l{_node}-regtest/lightning-rpc")
    # ln = LightningRpc(expanduser("~/.lightning/lightning-rpc"))

    i = 0
    while True:
        salt = bytes([i])
        key = Hkdf(salt, hsm_secret, hash=hashlib.sha256).expand(b"nodeid")
        try:
            privkey = secp256k1.PrivateKey(key)
            if privkey.pubkey.serialize().hex() == ln.getinfo()["id"]:
                # success!
                break
        except:
            i += 1
    print(f"Node l{_node} privkey: {key.hex()}")


if __name__ == "__main__":
    for node in nodes:
        print_privkeys(node)
