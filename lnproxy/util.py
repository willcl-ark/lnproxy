import contextvars
import itertools
import logging
import pathlib
import time
import struct
import queue

import lnproxy.config as config
# import lnproxy.pk_from_hsm as extract_pk_from_hsm

logger = logging.getLogger(f"{'UTIL':<6s}")
# Global counter for the connection log messages
COUNTER = itertools.count()
# Context variable for the connection log messages
request_info = contextvars.ContextVar("request_info")

def unlink_socket(address):
    """Unlink a Unix Socket at address 'address'.
    """
    socket_path = pathlib.Path(address)
    try:
        socket_path.unlink()
    except OSError:
        # Only print an error if the path exists but we can't unlink it, else ignore
        if socket_path.exists():
            print(f"Couldn't unlink socket {address}")


def get_my_payment_hashes() -> list:
    """List all payment hashes known to the node to check if invoice is mine
    """
    return [
        invoice["payment_hash"] for invoice in config.rpc.listinvoices()["invoices"]
    ]


def get_short_chan_id(source: hex, dest: hex):
    channel = [
        channel
        for channel in config.rpc.listchannels(source=source)["channels"]
        if channel["destination"] == dest
    ][0]["short_channel_id"]
    block_height, tx_index, output_index = channel.split("x")
    if not block_height and tx_index and output_index:
        raise ValueError(
            f"Could not find block_height, tx_index and output_index in " f"channels"
        )

    block_height = int(block_height)
    tx_index = int(tx_index)
    output_index = int(output_index)
    print(f"INFO: Got short channel ID: {block_height}x{tx_index}x{output_index}")

    _id = b""
    # 3 bytes for block height and tx_index
    _id += struct.pack(config.be_u32, block_height)[-3:]
    _id += struct.pack(config.be_u32, tx_index)[-3:]
    _id += struct.pack(config.be_u16, output_index)
    return _id


def check_onion_tool():
    onion = pathlib.Path(config.ONION_TOOL)
    if onion.exists() and onion.is_file():
        return True
    logger.error(f"Onion tool not found at {config.ONION_TOOL}")
    config.ONION_TOOL = input(
        "Please enter the exact path to C-Lightning onion" "tool:\n"
    )
    return False


# def get_regtest_privkeys(nodes):
#     keys = []
#     for node in nodes:
#         keys.append(extract_pk_from_hsm.get_privkey(node))
#     return keys


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


async def receive_exactly(stream, length, timeout=5):
    res = b""
    while len(res) < length and time.time() < (time.time() + timeout):
        res += await stream.receive_some(length - len(res))
    if len(res) == length:
        # log(f"Received exactly {length} bytes!")
        return res
    else:
        log(
            "Didn't receive enough bytes within the timeout, "
            "attempting to continue anyway!!"
        )
        return res
        # raise TimeoutError("Didn't receive enough bytes within the timeout, discarding")


def log(msg, level="debug"):
    """Logs a message using the context var.
    """
    try:
        # Get the appropriate context variable
        request_tag = request_info.get()
        # Log the message
        config.plugin.log(f"Conn {request_tag}: {msg}", level=level)
    # if rpc not configured or request_tag not setup yet, just print
    except (AttributeError, LookupError):
        print(f"{level.upper()}: {msg}")


def create_queue(pubkey: str):
    assert len(pubkey) == 4
    print("Creating new queue...")
    config.QUEUE[pubkey] = {
        "to_send": queue.Queue(),
        "recvd": queue.Queue()
    }
    print(f"Created queues at: config.QUEUE[{pubkey}]")


def chunk_to_list(data, chunk_len, prefix):
    """Adds data of arbitrary length to a queue in a certain chunk size
    """
    for i in range(0, len(data), chunk_len):
        yield (prefix + data[i: i + chunk_len])


def get_GID(pk):
    for key in config.nodes.keys():
        if key.startswith(pk.hex()):
            return config.nodes.get(key)
    print(f"Didnt' locate GID for pk bytes: {pk} hex: {pk.hex()}")




