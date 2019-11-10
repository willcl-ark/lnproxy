import json
import logging
import struct
import subprocess

import config

logger = logging.getLogger(f"{'UTIL':<5}")


def get_l2_pubkey():
    return json.loads(
        subprocess.run(
            [config.LN_CLI, config.L2_DIR, "getinfo"], capture_output=True
        ).stdout.decode()
    )["id"]


def get_l3_pubkey():
    return json.loads(
        subprocess.run(
            [config.LN_CLI, config.L3_DIR, "getinfo"], capture_output=True
        ).stdout.decode()
    )["id"]


def get_next_channel_id():
    """Get the final short channel_ID from CLI. Pack it into correct byte structure
    """
    block_height = tx_index = output_index = ""
    l2_channels = json.loads(
        subprocess.run(
            [config.LN_CLI, config.L2_DIR, "listfunds"], capture_output=True
        ).stdout.decode()
    )["channels"]
    for channel in l2_channels:
        if channel["peer_id"] == get_l3_pubkey():
            block_height, tx_index, output_index = channel["short_channel_id"].split(
                "x"
            )
    if not block_height and tx_index and output_index:
        return False

    block_height = int(block_height)
    tx_index = int(tx_index)
    output_index = int(output_index)

    _id = b""
    # 3 bytes for block height and tx_index
    _id += struct.pack(">L", block_height)[-3:]
    _id += struct.pack(">L", tx_index)[-3:]
    _id += struct.pack(config.be_u16, output_index)
    return _id


def hexdump(data, length=16):
    """Print a hexdump of data
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
