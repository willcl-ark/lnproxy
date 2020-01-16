import contextvars
import functools
import logging
import pathlib
import re
import struct
import time
import traceback

import trio
import trio.testing

import lnproxy.config as config

# Context variable for the connection log messages
pubkey_var = contextvars.ContextVar("pubkey")
logger = logging.getLogger(__name__)


def unlink_socket(address: str):
    """Unlink a Unix Socket at address 'address'.
    """
    socket_path = pathlib.Path(address)
    try:
        socket_path.unlink()
    except OSError:
        # Only log an error if the path exists but we can't unlink it, else ignore
        if socket_path.exists():
            logger.info(f"Couldn't unlink socket {address}")


def get_my_payment_hashes() -> list:
    """List all payment hashes known to the node to check if invoice is mine
    """
    return [
        invoice["payment_hash"] for invoice in config.rpc.listinvoices()["invoices"]
    ]


def int2bytes(i: int, enc: str) -> bytes:
    return i.to_bytes((i.bit_length() + 7) // 8, enc)


def switch_hex_endianness(str_in: hex, enc1: str, enc2: str):
    return int2bytes(int.from_bytes(bytes.fromhex(str_in), enc1), enc2).hex()


def get_next_pubkey(from_chan_id: bytes):
    """Hack to get next pubkey from the perspective of a routing node.
    Will check its connections, and return the next channel which it didn't just receive
    from.
    """
    # get list of peer pubkeys and their channels
    list_funds = config.rpc.listfunds()["channels"]

    # convert funding_txid to BE
    for channel in list_funds:
        channel["funding_txid"] = switch_hex_endianness(
            channel["funding_txid"], "little", "big"
        )

        # select the first one which isn't from_chan_id
        if channel["funding_txid"] != from_chan_id.hex():
            return channel["peer_id"]


def get_short_chan_id(source: hex, dest: hex) -> bytes:
    """Return a short channel id (bytes) based on source and destination provided.
    """
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
    logger.info(f"Got short channel ID: {block_height}x{tx_index}x{output_index}")

    _id = bytearray()
    # 3 bytes for block height and tx_index
    _id += struct.pack(config.be_u32, block_height)[-3:]
    _id += struct.pack(config.be_u32, tx_index)[-3:]
    _id += struct.pack(config.be_u16, output_index)
    return _id


def check_onion_tool() -> bool:
    onion = pathlib.Path(config.ONION_TOOL)
    if onion.exists() and onion.is_file():
        return True
    logger.error(f"Onion tool not found at {config.ONION_TOOL}")
    return False


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
    logger.info(result)


async def receive_exactly(stream, length: int) -> bytes:
    """Receive an exact number of bytes from a trio.SocketStream or a
    trio.testing.MemoryReceiveStream.
    """
    res = bytearray()
    while len(res) < length:
        try:
            res += await stream.receive_some(length - len(res))
        except Exception:
            logger.info(f"receive_exactly exception: {traceback.format_exc()}")
    return res


def create_queue(pubkey: str):
    """Creates a config.QUEUE entry for each pubkey.
    Each pubkey has an outbound and inbound queue (stream)
    """
    # If this is commented out, socket not closed
    # START
    try:
        config.QUEUE[pubkey] = {
            # We put whole messages as objects into a memory_channel for mesh sending
            "outbound": trio.open_memory_channel(50),
            # "outbound": "hello",
            # We can use a simpler memory_stream for received data as it's often partial
            "inbound": trio.testing.memory_stream_one_way_pair(),
            # "inbound": "world",
        }
    # We skip warning about using "deprecated" (testing) Trio module
    except:
        logger.exception("create_queue():")
    assert pubkey in config.QUEUE
    # END
    logger.info(f"Created queues for {pubkey}")


# def log(msg, level="info"):
#     """Logger which will attempt to log using contextvar and C-Lightning plugin logger.
#     """
#     level = "info"
#     msg = str(msg)
#     if config.logger:
#         try:
#             # Try using C-Lightning plugin logger with contextvar
#             config.logger(f"{pubkey_var.get()} | {msg}", level=level)
#         except (LookupError, NameError):
#             # Contextvar not set yet, try raw plugin logger
#             config.logger(f"{msg}", level=level)
#     else:
#         # Logger not defined yet by plugin
#         print(f"{level.upper()}: {msg}")


def chunk_to_list(data: bytes, chunk_len: int, prefix: bytes) -> iter:
    """Adds data of arbitrary length to a queue in a certain chunk size and yields
    result as an iterator.
    """
    for i in range(0, len(data), chunk_len):
        yield (prefix + data[i : i + chunk_len])


def get_gid(pk: bytes) -> int:
    """Lookup the goTenna GID based on pubkey provided using hardcoded list in config.
    """
    for key in config.nodes.keys():
        if key.startswith(pk.hex()):
            return config.nodes.get(key)
    logger.error(f"Didnt' locate GID for pk bytes: {pk} hex: {pk.hex()}")


def rate_dec():
    """Limits how fast we should send goTenna messages (or at least send them to the
    goTenna API thread.
    We use a base of 5 per minute, with a minimum of 1 second between each transmission.
    """

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
                ...
            # if we've not sent 'per_min' in total, sleep & send!
            elif len(config.SEND_TIMES) < per_min + 1:
                time.sleep(min_interval)
            # if our 'per_min'-th oldest is older than 'per_min' secs ago, go!
            elif config.SEND_TIMES[-(per_min + 1)] < (time.time() - 60):
                time.sleep(min_interval)
            # wait the required time
            else:
                wait = int(60 - (time.time() - config.SEND_TIMES[-(per_min + 1)])) + 1
                logger.info(f"Waiting {wait}s before send...")
                interval = 1
                for remaining in range(wait, 0, interval * -1):
                    if remaining % 10 == 0:
                        logger.info(f"{remaining}s remaining before next mesh send...")
                    time.sleep(1)
            # execute the send
            return func(*args, **kwargs)

        return limit

    return rate_limit


def write_pubkey_to_file():
    """Write lightning node pubkey to file named based on ln_dir
    """
    node_info = config.node_info
    node_id = node_info["id"]
    node_num = int(re.findall("\d+", node_info["lightning-dir"])[0])
    p = pathlib.Path(f"/tmp/l{node_num}-pubkey")
    with open(p, "wt") as s:
        s.write(node_id)
        logger.info(f"Written pubkey {node_id} to {p}")


def read_pubkeys_from_files():
    """Hack to exchange node pubkey info automagically.
    Would usually be done out of band, or could switch to GID-first system.
    """
    l1 = pathlib.Path("/tmp/l1-pubkey")
    l2 = pathlib.Path("/tmp/l2-pubkey")
    l3 = pathlib.Path("/tmp/l3-pubkey")
    nodes = [l1, l2, l3]
    # Wait for all nodes to write to their files
    while True:
        if l1.exists() and l2.exists() and l3.exists():
            break
        else:
            time.sleep(0.1)
    gid = 10000001
    for node in nodes:
        with open(node) as n:
            config.nodes[n.read()] = gid
        gid += 1

    logger.info(f"Read pubkeys from files and written to config")
    logger.info(config.nodes)
