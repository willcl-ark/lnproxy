import contextvars
import hashlib
import logging
import pathlib
import struct
from typing import Union

import trio.testing

from lnproxy_core import config

# Context variable for connection log messages
gid_key = contextvars.ContextVar("gid_key")


class CustomAdapter(logging.LoggerAdapter):
    """
    Prepends contextvar to the log if one exists.
    """

    def process(self, msg, kwargs):
        try:
            return f"GID:{gid_key.get()} | {msg}", kwargs
        # contextvar doesn't exist
        except (LookupError, NameError):
            return f"{msg}", kwargs


logger = CustomAdapter(logging.getLogger("util"), None)


def unlink_socket(address: str):
    """Unlink a Unix Socket at address 'address'.
    """
    socket_path = pathlib.Path(address)
    try:
        socket_path.unlink()
    except OSError:
        # Only log an error if the path exists but we can't unlink it, else ignore
        if socket_path.exists():
            logger.warning(f"Couldn't unlink socket {address}")


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
    logger.debug(f"Got short channel ID: {block_height}x{tx_index}x{output_index}")

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
    """Create a hex dump of data
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
    return result


def msg_hash(msg):
    return hashlib.sha256(msg).hexdigest()


async def receive_exactly(
    stream: Union[trio.SocketStream, trio.testing.MemoryReceiveStream], length: int
) -> bytes:
    """Receive an exact number of bytes from a trio.SocketStream or a
    trio.testing.MemoryReceiveStream.
    """
    if length > 65535:
        logger.warning(
            f"Got message larger than allowed max size. Likely "
            f"deserialisation or transmission error: {length}B"
        )
    res = bytearray()
    while len(res) < length:
        _temp_res = await stream.receive_some(length - len(res))
        if not _temp_res:
            raise trio.ClosedResourceError("Socket was closed")
        else:
            res += _temp_res
    return res


def chunk_to_list(data: bytes, chunk_len: int) -> iter:
    """Iterator to chunk data and append a header.
    """
    for i in range(0, len(data), chunk_len):
        yield data[i : i + chunk_len]


suffixes = {
    "decimal": ("kB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"),
    "binary": ("KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB"),
    "gnu": "KMGTPEZY",
}


def natural_size(value, binary=False, gnu=True, _format="%.1f"):
    """show us sizes nicely formatted
    https://github.com/jmoiron/humanize.git
    """
    if gnu:
        suffix = suffixes["gnu"]
    elif binary:
        suffix = suffixes["binary"]
    else:
        suffix = suffixes["decimal"]

    base = 1024 if (gnu or binary) else 1000
    _bytes = float(value)

    if _bytes == 1 and not gnu:
        return "1 Byte"
    elif _bytes < base and not gnu:
        return "%d Bytes" % _bytes
    elif _bytes < base and gnu:
        return "%dB" % _bytes

    for i, s in enumerate(suffix):
        unit = base ** (i + 2)
        if _bytes < unit and not gnu:
            return (_format + " %s") % ((base * _bytes / unit), s)
        elif _bytes < unit and gnu:
            return (_format + "%s") % ((base * _bytes / unit), s)
    if gnu:
        return (_format + "%s") % ((base * _bytes / unit), s)
    return (_format + " %s") % ((base * _bytes / unit), s)
