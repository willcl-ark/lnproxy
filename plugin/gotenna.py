#!/usr/bin/env python3
import logging
import pathlib
import time
import uuid

import lightning
import trio
from goTenna.constants import GID_MAX
from secp256k1 import PublicKey

import lnproxy.config as config
import lnproxy.network as network
from lnproxy.mesh import connection_daemon
from lnproxy.messages import EncryptedMessage
from lnproxy.pk_from_hsm import get_privkey
from lnproxy.proxy import serve_outbound

gotenna_plugin = lightning.Plugin()
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("plugin")
router = network.router


gotenna_plugin.add_option(
    name="gid",
    default=None,
    description="A GID for connected goTenna device to use",
    opt_type="int",
)


@gotenna_plugin.method("show-router")
def show_router(plugin=None):
    """Returns the current view of the goTenna plugin's router.
    """
    return str(router)


@gotenna_plugin.method("gid")
def get_gid(plugin=None):
    """Returns the goTenna GID used by this node.
    """
    return plugin.get_option("gid")


@gotenna_plugin.method("add-node")
def add_node(gid, pubkey, plugin=None):
    """Add a mesh-connected node to the routing table.
    arg: gid: integer within valid goTenna GID range
    arg: pubkey: a node's lightning pubkey
    """
    # Check that GID and pubkey are valid
    if not 0 <= int(gid) <= GID_MAX:
        return f"GID {gid} not in range 0 <= n <= {GID_MAX}"
    try:
        _pubkey = PublicKey(pubkey=bytes.fromhex(pubkey), raw=True)
    except Exception as e:
        logger.exception("Error with pubkey")
        return f"Error with pubkey: {e}"
    # Add to router
    _node = network.Node(int(gid), str(pubkey))
    # Check for dupes
    if gid in router:
        return (
            f"GID {gid} already in router, remove before adding again: "
            f"{router.get_node(gid)}"
        )
    elif pubkey in router:
        return (
            f"Pubkey {pubkey} already in router, remove before adding again: "
            f"{router.get_node(router.lookup_gid(pubkey))}"
        )
    else:
        router.add(_node)
        return f"{_node} added to gotenna plugin router."


@gotenna_plugin.method("remove-node")
def remove_node(gid, plugin=None):
    """Remove a node from the network router using GID
    """
    if gid not in router:
        return f"GID {gid} not found in router."
    try:
        router.remove(gid)
    except Exception as e:
        return f"Error removing node from router: {e}"
    else:
        return f"Node with GID {gid} removed from router."


@gotenna_plugin.method("proxy-connect")
def proxy_connect(gid, plugin=None):
    """Connect to a remote node via goTenna mesh proxy.
    """
    try:
        pubkey = router.lookup_pubkey(gid)
    except LookupError as e:
        return f"Could not find GID {gid} in router, try adding first.\n{e}"
    logging.debug(f"proxy-connect to gid {gid} via goTenna mesh connection")
    # Generate a random fd to listen on for this outbound connection.
    listen_addr = f"/tmp/0{uuid.uuid4().hex}"
    # Setup the listening server for C-Lightning to connect through, started in the
    # main shared nursery.
    trio.from_thread.run(config.nursery.start, serve_outbound, f"{listen_addr}", gid)
    # Confirm the socket is created and listening.
    while not pathlib.Path(listen_addr).is_socket():
        time.sleep(0.1)
    # Instruct C-Lightning RPC to connect to remote via the socket after it has been
    # established.
    # TODO: Use trio to add a timeout for the connect?
    return plugin.rpc.connect(str(pubkey), f"{listen_addr}")


@gotenna_plugin.method("message")
def message(
    gid, message_string, msatoshi: int = 100_000, plugin=None,
):
    """Send a message via the mesh connection paid for using key-send (non-interactive)
    args: (goTenna) gid, msatoshi, msatoshi
    """
    # Get the destination pubkey
    dest_pubkey = network.router.lookup_pubkey(gid)
    _message = EncryptedMessage(
        gid=gid, plain_text=message_string, dest_pubkey=dest_pubkey,
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
    description = f"{uuid.uuid4().hex} encrypted message to {_message.dest_pubkey}"

    # Store message for later.
    # The traffic proxy will add the encrypted message onto the outbound
    # htlc_add_update message.
    config.key_sends[_message.payment_hash.digest()] = _message
    logger.debug(
        f"Stored message in config.key_sends[{_message.payment_hash.digest()}]"
    )

    # Get next peer in route
    # TODO: Improve routing here; tap into gotenna routing table.
    peer = config.rpc.listfunds()["channels"][0]["peer_id"]
    logger.debug(f"Got next peer {peer}")

    # We add 10 satoshis to amount (10 hops max x 1 satoshi fee each)
    # We add 60 to cltv (10 hops max, CLTV of 6 each)
    amt_msat = int(msatoshi) + 10
    cltv = 9 + 60

    # Get the route to the next hop.
    route = config.rpc.getroute(peer, msatoshi=amt_msat, riskfactor=10, cltv=cltv)[
        "route"
    ]
    logger.info(f"Got route to {peer}, executing sendpay command.")

    return config.rpc.sendpay(
        route, _message.payment_hash.hexdigest(), description, amt_msat
    )


@gotenna_plugin.init()
# Parameters used by gotenna_plugin() internally
def init(options, configuration, plugin):
    logger.info("Starting goTenna plugin")
    # Store the RPC in config to be accessible by all modules.
    config.rpc = plugin.rpc
    # Get the local lightning node info to avoid multiple lookups.
    config.node_info = plugin.rpc.getinfo()
    logger.debug(config.node_info)
    # Add ourselves to the routing table
    router.add(network.Node(int(plugin.get_option("gid")), str(config.node_info["id"])))
    logger.debug(router)
    # ======= WARNING =======
    # Store our node private key for message decryption
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
    logger.info(f"goTenna plugin initialised. Added RPC commands: {commands}")


async def main():
    """Main function that is run when the plugin is loaded (and run) by C-Lightning.
    Function decorated with @plugin.init() will be run when `plugin.run()` is called
    which must be at startup.
    """
    # This nursery will run our main tasks for us:
    async with trio.open_nursery() as config.nursery:
        # We run the plugin itself in a synchronous thread so trio.run() maintains
        # overall control of the app.
        config.nursery.start_soon(trio.to_thread.run_sync, gotenna_plugin.run)
        # Start the goTenna connection daemon.
        config.nursery.start_soon(connection_daemon)
    logger.info("goTenna plugin exited.")


trio.run(main)
