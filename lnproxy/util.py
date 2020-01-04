import contextvars
import functools
import itertools
import pathlib
import time
import struct
import queue

import lnproxy.config as config

# import lnproxy.pk_from_hsm as extract_pk_from_hsm

# Global counter for the connection log messages
COUNTER = itertools.count()
# Context variable for the connection log messages
request_info = contextvars.ContextVar("request_info")


def unlink_socket(address: str):
    """Unlink a Unix Socket at address 'address'.
    """
    socket_path = pathlib.Path(address)
    try:
        socket_path.unlink()
    except OSError:
        # Only config.log an error if the path exists but we can't unlink it, else ignore
        if socket_path.exists():
            config.log(f"Couldn't unlink socket {address}", level="debug")


def get_my_payment_hashes() -> list:
    """List all payment hashes known to the node to check if invoice is mine
    """
    return [
        invoice["payment_hash"] for invoice in config.rpc.listinvoices()["invoices"]
    ]


def get_short_chan_id(source: hex, dest: hex) -> bytes:
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
    config.log(
        f"Got short channel ID: {block_height}x{tx_index}x{output_index}", level="debug"
    )

    _id = b""
    # 3 bytes for block height and tx_index
    _id += struct.pack(config.be_u32, block_height)[-3:]
    _id += struct.pack(config.be_u32, tx_index)[-3:]
    _id += struct.pack(config.be_u16, output_index)
    return _id


def check_onion_tool() -> bool:
    onion = pathlib.Path(config.ONION_TOOL)
    if onion.exists() and onion.is_file():
        return True
    config.log(f"Onion tool not found at {config.ONION_TOOL}", level="error")
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
    config.log(result, level="debug")


async def receive_exactly(stream, length: int, timeout: int = 30) -> bytes:
    res = b""
    while len(res) < length and time.time() < (time.time() + timeout):
        res += await stream.receive_some(length - len(res))
    if len(res) == length:
        # config.log(f"Received exactly {length} bytes!")
        return res
    else:
        config.log(
            "Didn't receive enough bytes within the timeout, "
            "attempting to continue anyway!!",
            level="warn",
        )
        return res


# def log(msg, level="debug"):
#     """Logs a message using the context var.
#     """
#     try:
#         # Get the appropriate context variable
#         request_tag = request_info.get()
#         # Log the message
#         config.plugin.log(f"Conn {request_tag}: {msg}", level=level)
#     # if rpc not configured or request_tag not setup yet, just print
#     except (AttributeError, LookupError):
#         print(f"{level.upper()}: {msg}")


def create_queue(pubkey: str):
    assert len(pubkey) == 4
    config.QUEUE[pubkey] = {"to_send": queue.Queue(), "recvd": queue.Queue()}
    config.log(f"Created queues at: config.QUEUE[{pubkey}]")


def chunk_to_list(data: bytes, chunk_len: int, prefix: bytes) -> iter:
    """Adds data of arbitrary length to a queue in a certain chunk size
    """
    for i in range(0, len(data), chunk_len):
        yield (prefix + data[i : i + chunk_len])


def get_GID(pk: bytes):
    for key in config.nodes.keys():
        if key.startswith(pk.hex()):
            return config.nodes.get(key)
    config.log(f"Didnt' locate GID for pk bytes: {pk} hex: {pk.hex()}", level="error")


def rate_dec(private=False):
    def rate_limit(func):
        """Smart rate-limiter
        """

        @functools.wraps(func)
        def limit(*args, **kwargs):
            # how many can we send per minute
            if config.UBER:
                per_min = 12
            else:
                per_min = 5  # if not private else 8
            min_interval = 1

            # add this send time to the list
            config.SEND_TIMES.append(time.time())

            # if we've not sent before, send!
            if len(config.SEND_TIMES) <= 1:
                config.log("Not sent before... sending immediately", level="debug")

            # if we've not sent 'per_min' in total, sleep & send!
            elif len(config.SEND_TIMES) < per_min + 1:
                config.log(
                    f"Not sent {per_min}, sleeping {min_interval}s and sending",
                    level="debug",
                )
                time.sleep(min_interval)

            # if our 'per_min'-th oldest is older than 'per_min' secs ago, go!
            elif config.SEND_TIMES[-(per_min + 1)] < (time.time() - 60):
                config.log(
                    f"{per_min}th oldest is older than 60 secs... sending immediately",
                    level="debug",
                )

            # wait the required time
            else:
                wait = int(60 - (time.time() - config.SEND_TIMES[-(per_min + 1)])) + 1
                config.log(f"Waiting {wait}s before send...")
                interval = 1
                for remaining in range(wait, 0, interval * -1):
                    if remaining % 10 == 0:
                        config.log(f"{remaining}s remaining before next mesh send...")
                    time.sleep(1)

            # execute the send
            return func(*args, **kwargs)

        return limit

    return rate_limit
