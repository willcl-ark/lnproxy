#!/usr/bin/env python3
import logging
import uuid
from pathlib import Path

import trio
from pyln.client import Plugin
from secp256k1 import PublicKey

from lnproxy_core import config, network
from lnproxy_core.messages import EncryptedMessage
from lnproxy_core.pk_from_hsm import get_privkey

# Initialise the plugin
plugin = Plugin()

# Initialise the logger
handler = logging.StreamHandler()
bf = logging.Formatter("%(name)7s | %(levelname)8s | %(message)s")
handler.setFormatter(bf)
logging.basicConfig(level=logging.DEBUG, handlers=[handler])
logger = logging.getLogger("lnproxy")

# Initialise the plugin router, the router is not currently persisted to disk
config.router = network.Router()

# Set how many bytes to use for GID shortening. GID will be shortened using:
# GID % (256 * send_id_len) which is equivalent to send_id_len bytes.
# e.g. 1 byte is good for 256 unique GIDs (less collisions)
send_id_len = config.user.getint("message", "SEND_ID_LEN")


plugin.add_option(
    name="onion-tool-path",
    default="~/src/lightning/devtools/onion",
    description='Path to C-Lightning\'s onion tool (in "lightning/devtools" folder)',
    opt_type="string",
)


@plugin.method("show-router")
def show_router(plugin=None):
    """Returns the current view of the plugins router.
    """
    logger.debug(f"show_router: {str(config.router)}")
    return str(config.router)


@plugin.method("node-addr")
def node_addr(pubkey, plugin=None):
    """Returns the nodes' address in host:port format.
    """
    try:
        _node = config.router.by_pubkey[pubkey]
    except LookupError:
        return f"Node {pubkey} not found in router. Run `show-router` to see router."
    logger.debug(f"Node address: {_node.host_remote}:{_node.port_remote}")
    return f"{_node.host_remote}:{_node.port_remote}"


@plugin.method("add-node")
def add_node(remote_node, listen_port, plugin=None):
    """Add a node to the plugin routing table.
    arg: remote_node: string: <pubkey>@<address>:<port> used to connect to the remote node e.g. "<pubkey>@127.0.0.1:9735"
    arg: listen_port: the port this node will listen for incoming connections from the remote_node
    """
    pubkey, remote_address = remote_node.split("@")
    _host, _port = remote_address.split(":")
    gid = int(pubkey, 16) % (send_id_len * 256)

    print(f"pubkey={pubkey}")
    print(f"remote_host={_host}")
    print(f"remote_port={_port}")
    print(f"local_listen_port={listen_port}")
    print(f"generated_gid={gid}")
    # Check that GID and pubkey are valid according to config.MAX_GID
    if not 0 <= gid <= config.MAX_GID:
        return f"GID {gid} not in range 0 <= GID <= {config.MAX_GID}"
    # Test the pubkey is valid
    try:
        _pubkey = PublicKey(pubkey=bytes.fromhex(pubkey), raw=True)
    except Exception as e:
        logger.exception("Error converting to valid pubkey from hex string")
        return f"Error with pubkey: {e}"

    # Check for dupes
    # Generate a unique GID if it already exists.
    # TODO: could cause issues
    while gid in config.router:
        gid = gid + 1
    if pubkey in config.router:
        return (
            f"Pubkey {pubkey} already in router, remove before adding again: "
            f"{config.router.by_pubkey[pubkey]}"
        )

    # Create the node
    _node = network.Node(gid, str(pubkey), _host, int(_port), listen_port)
    # Add to the router
    config.router.add(_node)
    return (
        f"{_node.pubkey} added to plugin router and "
        f"listening for incoming connections on port: {_node.inbound_port}"
    )


@plugin.method("remove-node")
def remove_node(pubkey, plugin=None):
    """Remove a node from the plugin router by pubkey
    """
    if pubkey not in config.router:
        return f"Node {pubkey} not found in router."
    try:
        config.router.remove(pubkey)
    except Exception as e:
        return f"Error removing node from router: {e}"
    else:
        return f"Node {pubkey} removed from router."


@plugin.method("proxy-connect")
def proxy_connect(pubkey, plugin=None):
    """Connect to a remote node via lnproxy.
    :param pubkey: str: pubkey of node in router to connect to
    """
    try:
        node = config.router.by_pubkey[pubkey]
    except LookupError as e:
        return f"Could not find GID {pubkey} in router.\n{e}"
    logger.debug(f"proxy-connect to node {node.pubkey} via lnproxy plugin")

    node.rpc = plugin.rpc
    node.outbound = True

    # Setup the listening server for C-Lightning to connect to
    trio.from_thread.run_sync(config.nursery.start_soon, node.serve_outbound)
    return "Connection scheduled in trio main loop"


@plugin.method("message")
def message(
    pubkey, message_string, msatoshi: int = 100_000, plugin=None,
):
    """Send a message via the remote, paid for using key-send (non-interactive)
    args: pubkey, message_string, msatoshi: default=100000
    """
    # Get a unique "sender_id" which receiver can use to lookup sender pubkey
    sender_id = config.gid.to_bytes(send_id_len, "big")

    # Create the encrypted message payload
    _message = EncryptedMessage(
        send_sk=config.node_secret_key,
        send_id=sender_id,
        recv_pk=pubkey,
        plain_text=message_string,
    )
    try:
        _message.encrypt()
    except LookupError:
        logger.exception("Can't find pubkey or nonce needed for encryption in router")
        return "Send message failed. Check logs for details."
    except TypeError:
        logger.exception("Invalid public key type for encryption")
        return "Send message failed. Check logs for details."
    else:
        logger.debug(f"Encrypted message:\n{_message.encrypted_msg.hex()}")

    # Create a pseudo-random description to satisfy C-Lightning's accounting system
    description = f"Encrypted message for {_message.recv_pk}: {uuid.uuid4().hex}"

    # Store message object for later.
    # The proxy will add the encrypted message onto the outbound htlc_add_update message
    # after lookup using payment_hash.
    config.key_sends[_message.payment_hash] = _message
    logger.debug(f"Stored message in config.key_sends[{_message.payment_hash}]")

    # Get first peer in route
    # TODO: Improve routing here; tap into outourced routing table.
    peer = config.rpc.listfunds()["channels"][0]["peer_id"]
    logger.debug(f"Got first peer: {peer}")

    # As we don't presume to have the full network graph here, we must guesstimate the
    # fees and CLTV somewhat here.
    # We add 10 satoshis to amount (10 hops max x 1 satoshi fee each)
    # We add 60 to cltv (10 hops max, CLTV of 6 each)
    amt_msat = int(msatoshi) + 10
    cltv = 9 + 60

    # Get the route to the next hop.
    route = config.rpc.getroute(peer, msatoshi=amt_msat, riskfactor=10, cltv=cltv)[
        "route"
    ]
    logger.info(f"Got route to {peer}, executing sendpay command.")

    return config.rpc.sendpay(route, _message.payment_hash.hex(), description, amt_msat)


def check_onion_tool(_plugin):
    """Basic check to determine that onion-tool-path is pointing to a file
    """
    _path = Path(_plugin.get_option("onion-tool-path"))
    config.onion_tool_path = _path.expanduser() if "~" in str(_path) else _path
    if not config.onion_tool_path.is_file():
        raise FileNotFoundError(
            f"onion-tool-path={str(config.onion_tool_path)} set in C-Lightning config "
            f"does not point to a file."
        )


@plugin.init()
# Parameters used by gotenna_plugin() internally
def init(options, configuration, plugin):
    logger.info("Starting lnproxy plugin")

    # Check the onion tool path is a valid file
    check_onion_tool(plugin)

    # Store the RPC in config to be accessible by all modules.
    config.rpc = plugin.rpc

    # Get the local lightning node info to avoid multiple lookups.
    config.node_info = plugin.rpc.getinfo()
    logger.debug(config.node_info)

    # Add ourselves to the routing table
    config.gid = int(config.node_info["id"], 16) % (send_id_len * 256)
    _node = network.Node(
        gid=int(config.gid), pubkey=str(config.node_info["id"]), listen=False,
    )
    trio.from_thread.run_sync(config.router.add, _node)

    logger.debug(config.router)

    # ======= WARNING =======
    # Store our node private key in memory for message decryption
    config.node_secret_key = str(
        get_privkey(config.node_info["lightning-dir"], config.node_info["id"])
    )
    logger.debug(f"Node private key: {config.node_secret_key}")
    # ===== END WARNING =====

    # Suppress all C-Lightning gossip messages for newly-connected peers.
    plugin.rpc.dev_suppress_gossip()

    # Show the user the new RPCs available
    commands = list(plugin.methods.keys())
    commands.remove("init")
    commands.remove("getmanifest")
    logger.info(f"lnproxy plugin initialised. Added RPC commands: {commands}")


async def main():
    """Main function that is run when the plugin is loaded (and run) by C-Lightning.
    Function decorated with @plugin.init() will be run when `plugin.run()` is called
    which must be at startup.
    """
    # This nursery will run our main tasks for us:
    try:
        async with trio.open_nursery() as config.nursery:
            # We run the plugin itself in a synchronous thread so trio.run() maintains
            # overall control of the runtime.
            config.nursery.start_soon(trio.to_thread.run_sync, plugin.run)
    except (Exception, trio.MultiError):
        logger.exception("Exception in lnproxy.main():")
    logger.info("lnproxy plugin exited.")


trio.run(main)
