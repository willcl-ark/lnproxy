#!/usr/bin/env python3
import logging
import uuid

import src.config as config
import src.network as network
import trio
from pyln.client import Plugin
from secp256k1 import PublicKey
from src.messages import EncryptedMessage
from src.pk_from_hsm import get_privkey

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
send_id_len = config.user["message"].getint("SEND_ID_LEN")


plugin.add_option(
    name="gid",
    default=None,
    description="A GID for the transport layer to use",
    opt_type="int",
)


@plugin.method("show-router")
def show_router(plugin=None):
    """Returns the current view of the plugins router.
    """
    logger.debug(f"show_router: {str(config.router)}")
    return str(config.router)


@plugin.method("gid")
def get_gid(plugin=None):
    """Returns the GID used by this node.
    """
    return plugin.get_option("gid")


@plugin.method("add-node")
def add_node(gid, pubkey, plugin=None):
    """Add a node to the plugin routing table.
    arg: gid: integer (within 0 < n < MAX_GID range from config.ini)
    arg: pubkey: a lightning pubkey
    arg: tcp_port: the TCP port this node can be connected to with
    """
    _gid = int(gid)
    # Check that GID and pubkey are valid according to config.MAX_GID
    if not 0 <= _gid <= config.MAX_GID:
        return f"GID {_gid} not in range 0 <= GID <= {config.MAX_GID}"
    # Test the pubkey is valid
    try:
        _pubkey = PublicKey(pubkey=bytes.fromhex(pubkey), raw=True)
    except Exception as e:
        logger.exception("Error converting to valid pubkey from hex string")
        return f"Error with pubkey: {e}"

    # Check for dupes
    if _gid in config.router:
        return (
            f"GID {_gid} already in router, remove before adding again: "
            f"{config.router.get_node(_gid)}"
        )
    elif pubkey in config.router:
        return (
            f"Pubkey {pubkey} already in router, remove before adding again: "
            f"{config.router.get_node(config.router.get_gid(pubkey))}"
        )

    # Create the node
    _node = network.Node(_gid, str(pubkey))
    # Add to the router
    config.router.add(_node)
    return (
        f"{_node.gid} added to plugin router and "
        f"listening for incoming connections on port: {_node.port_remote_listen}"
    )


@plugin.method("remove-node")
def remove_node(gid, plugin=None):
    """Remove a node from the plugin router by GID
    """
    if gid not in config.router:
        return f"GID {gid} not found in router."
    try:
        config.router.remove(gid)
    except Exception as e:
        return f"Error removing node from router: {e}"
    else:
        return f"Node with GID {gid} removed from router."


# noinspection PyIncorrectDocstring
@plugin.method("proxy-connect")
def proxy_connect(gid, tcp_port, plugin=None):
    """Connect to a remote node via lnproxy.

    :param gid: int: gid of node in router to connect to
    :param tcp_port: int: tcp port the onward connection will connect to
    """
    try:
        node = config.router.get_node(int(gid))
    except LookupError as e:
        return f"Could not find GID {gid} in router, try adding first.\n{e}"
    logging.debug(f"proxy-connect to gid {node.gid} via lnproxy plugin")

    # Warn if it outside "safe" range
    if int(tcp_port) not in range(49152, 65535):
        logger.warning(
            f"TCP port selected for node not within recommended range: 49152 - 65535"
        )

    node.port_remote_out = int(tcp_port)
    node.listen_addr = f"/tmp/0{uuid.uuid4().hex}"
    node.rpc = plugin.rpc
    node.outbound = True

    # Setup the listening server for C-Lightning to connect to
    trio.from_thread.run_sync(config.nursery.start_soon, node.serve_outbound)
    return "Connection scheduled in trio main loop"


@plugin.method("message")
def message(
    gid, message_string, msatoshi: int = 100_000, plugin=None,
):
    """Send a message via the remote, paid for using key-send (non-interactive)
    args: gid, message_string, msatoshi: default=100000
    """
    # Get the destination pubkey from the router
    dest_pubkey = config.router.get_pubkey(gid)

    # Get a unique "sender_id" which receiver can use to lookup sender pubkey
    # sender_id will be 1 byte long as this allows 256 GID values, enough for now
    sender_id = (int(plugin.get_option("gid")) % 256).to_bytes(send_id_len, "big")

    # Create the encrypted message payload
    _message = EncryptedMessage(
        send_sk=config.node_secret_key,
        send_id=sender_id,
        recv_pk=dest_pubkey,
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
    description = f"{uuid.uuid4().hex} encrypted message to {_message.recv_pk}"

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


@plugin.init()
# Parameters used by gotenna_plugin() internally
def init(options, configuration, plugin):
    logger.info("Starting lnproxy plugin")

    # Store the RPC in config to be accessible by all modules.
    config.rpc = plugin.rpc

    # Get the local lightning node info to avoid multiple lookups.
    config.node_info = plugin.rpc.getinfo()
    logger.debug(config.node_info)

    # Add ourselves to the routing table
    _node = network.Node(
        int(plugin.get_option("gid")), str(config.node_info["id"]), listen=False
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
