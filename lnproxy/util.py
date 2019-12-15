import logging
import pathlib

# import tempfile

import lnproxy.config as config
import lnproxy.pk_from_hsm as extract_pk_from_hsm

logger = logging.getLogger(f"{'UTIL':<6s}")
rpc = None


def get_my_payment_hashes() -> list:
    """List all payment hashes known to the node to check if invoice is mine
    """
    return [
        invoice["payment_hash"] for invoice in config.rpc.listinvoices()["invoices"]
    ]


def check_onion_tool():
    onion = pathlib.Path(config.ONION_TOOL)
    if onion.exists() and onion.is_file():
        return True
    logger.error(f"Onion tool not found at {config.ONION_TOOL}")
    config.ONION_TOOL = input(
        "Please enter the exact path to C-Lightning onion" "tool:\n"
    )
    return False


# def decode_onion(onion: bytes, priv_keys: list, assoc_data: str):
#     """Takes an onion, an ordered list of private keys, an onion and assoc-data (usually payment
#     hash) and decodes an onion
#     """
#     logger.info("Decoding onion...")
#     logger.debug(f"original onion length: {len(onion)}")
#     logger.debug(f"original onion:\n{onion.hex()}")
#     payloads = []
#     nexts = []
#     i = 0
#
#     # write the onion to a temporary file in hex format
#     onion_file = tempfile.NamedTemporaryFile(mode="w+t", delete=False)
#     with open(onion_file.name, "wt") as f:
#         f.write(onion.hex())
#
#     while True:
#         # keep looping through priv keys until '_next' not in onion
#         # this way we can go A -> B, B -> C and A -> B -> C
#         _next = ""
#         onion_tool = subprocess.run(
#             [
#                 config.ONION_TOOL,
#                 "decode",
#                 onion_file.name,
#                 f"{priv_keys[i % 3]}",
#                 "--assoc-data",
#                 f"{assoc_data}",
#             ],
#             capture_output=True,
#         )
#         if not onion_tool.stderr.decode() == "":
#             logger.error(f"Decode Error: {onion_tool.stderr.decode()}")
#         onion = onion_tool.stdout.decode()
#         logger.debug(f"Decoded onion: {onion}")
#
#         if "next=" not in onion:
#             # last layer of onion, only a payload inside!
#             payload = onion.strip()
#         else:
#             # get payload and next onion layer
#             payload, _next = onion.splitlines()
#             _next = _next.split("=")[1]
#             logger.debug(f"_next: {_next}")
#             nexts.append(_next)
#
#         payload = payload.split("=")[1]
#         logger.debug(f"payload: {payload}")
#         decode_hop_data(bytes.fromhex(payload), i)
#         payloads.append(payload)
#
#         if _next is not "":
#             with open(onion_file.name, "wt") as f:
#                 f.write(_next)
#             i += 1
#         else:
#             break
#     return payloads, nexts


def get_regtest_privkeys(nodes):
    keys = []
    for node in nodes:
        keys.append(extract_pk_from_hsm.get_privkey(node))
    return keys


def hex_dump(data, length=16):
    """Print a hex dump of data
    """
    _filter = "".join([(len(repr(chr(x))) == 3) and chr(x) or "." for x in range(256)])
    lines = []
    digits = 4 if isinstance(data, str) else 2
    for c in range(0, len(data), length):
        chars = data[c : c + length]
        _hex = " ".join(["%0*x" % (digits, x) for x in chars])
        printable = "".join(["%s" % ((x <= 127 and _filter[x]) or ".") for x in chars])
        lines.append("%04x  %-*s  %s\n" % (c, length * 3, _hex, printable))
    result = "\n" + "".join(lines)
    logger.debug(result)
