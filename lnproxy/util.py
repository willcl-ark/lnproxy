import logging
import pathlib
import struct
import time

from lightning import LightningRpc

import lnproxy.config as config

logger = logging.getLogger(f"{'UTIL':<6s}")
rpc = None


def init_nodes():
    global rpc
    config.my_node_dir = config.NODE_DIR[config.my_node]
    rpc = LightningRpc(f"{config.my_node_dir}/{config.network}/lightning-rpc")
    rpc.logger = logging.getLogger(f"{'LNRPC':<6s}")
    # TODO: remove when not testing
    # this tests the RPC connection
    while True:
        try:
            config.my_node_pubkey = rpc.getinfo()["id"]
            break
        except FileNotFoundError:
            rpc.logger.error(
                f"Can't find node {config.my_node}'s lightning-rpc at "
                f"{config.my_node_dir}/{config.network}/lightning-rpc. Trying again in 2 seconds"
            )
            time.sleep(2)
    next_node_dir = config.NODE_DIR[(config.my_node + 1) % 3]
    rpc2 = LightningRpc(f"{next_node_dir}/{config.network}/lightning-rpc")
    config.next_node_pubkey = rpc2.getinfo()["id"]


def get_my_payment_hashes() -> list:
    all_invoices = rpc.listinvoices()["invoices"]
    inv_hashes = []
    for invoice in all_invoices:
        inv_hashes.append(invoice["payment_hash"])
    return inv_hashes


def get_next_channel_id() -> bytes:
    """Get the next short channel_ID from CLI. Pack it into correct byte structure
    """
    block_height = tx_index = output_index = ""
    # get a list of my channels
    my_channels = rpc.listfunds()["channels"]
    for channel in my_channels:
        if channel["peer_id"] == config.next_node_pubkey:
            block_height, tx_index, output_index = channel["short_channel_id"].split(
                "x"
            )
    if not block_height and tx_index and output_index:
        raise ValueError(
            f"Could not find block_height, tx_index and output_index in " f"channels"
        )

    block_height = int(block_height)
    tx_index = int(tx_index)
    output_index = int(output_index)
    logger.debug(f"Got short channel ID: {block_height}x{tx_index}x{output_index}")

    _id = b""
    # 3 bytes for block height and tx_index
    _id += struct.pack(config.be_u32, block_height)[-3:]
    _id += struct.pack(config.be_u32, tx_index)[-3:]
    _id += struct.pack(config.be_u16, output_index)
    return _id


def set_socks(node):
    """Test code which will set sockets for as appropriate for a 3-node test
    """
    if node not in range(0, 3):
        raise ValueError(f"Node arg passed ({node}) not in range 1 to 3")
    if node == 0:
        config.remote_listen_SOCK = "/tmp/unix_proxy1_remotes"
        config.local_listen_SOCK = "/tmp/unix_proxy1_local"
        config.local_node_addr = "/tmp/l1-regtest/unix_socket"
        config.remote_node_addr = "/tmp/unix_proxy2_remotes"
    elif node == 1:
        config.remote_listen_SOCK = "/tmp/unix_proxy2_remotes"
        config.local_listen_SOCK = "/tmp/unix_proxy2_local"
        config.local_node_addr = "/tmp/l2-regtest/unix_socket"
        config.remote_node_addr = "/tmp/unix_proxy3_remotes"
    elif node == 2:
        config.remote_listen_SOCK = "/tmp/unix_proxy3_remotes"
        config.local_listen_SOCK = "/tmp/unix_proxy3_local"
        config.local_node_addr = "/tmp/l3-regtest/unix_socket"
        config.remote_node_addr = "tmp/unix_proxy1_remotes"
    logger.info(f"remote_list_sock = {config.remote_listen_SOCK}")
    logger.info(f"local_listen_sock = {config.local_listen_SOCK}")
    logger.debug(f"local_node_addr = {config.local_node_addr}")
    logger.debug(f"remote_node_addr = {config.remote_node_addr}")


def check_onion_tool():
    try:
        while True:
            onion = pathlib.Path(config.ONION_TOOL)
            if onion.exists() and onion.is_file():
                break
            logger.error(f"Onion tool not found at {config.ONION_TOOL}")
            config.ONION_TOOL = input(
                "Please enter the exact path to C-Lightning onion" "tool:\n"
            )
        return True
    except KeyboardInterrupt:
        print("Exiting with KeyboardInterrupt")
        logger.error("Exiting with KeyboardInterrupt")
        return False
    except Exception:
        logger.error("Error locating onion tool")
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
    logger.debug(result)
