#!/usr/bin/env python3
import time
import traceback
import uuid
from hashlib import sha256
from pathlib import Path

import trio
from lightning import Plugin

import lnproxy.config as config
import lnproxy.mesh_connection as mesh
from lnproxy.proxy import serve_outbound, send_queue_daemon
from lnproxy.util import log

# autopatch=True monkey patches stdout and stderr
plugin = Plugin(autopatch=True)


async def connection_daemon():
    """Load the goTenna mesh connection object (to persistent config.mesh_conn).
    Start the send_queue_daemon in the main nursery.
    """
    # Wait for node info to populate.
    while config.node_info is None:
        await trio.sleep(0.1)
    # start the mesh connection
    config.mesh_conn = mesh.Connection()
    # start the send_queue_daemon:
    while config.mesh_conn.active is False:
        await trio.sleep(0.1)
    config.nursery.start_soon(send_queue_daemon)
    log("Connection and send_queue_daemon started successfully")


@plugin.method("proxy-connect")
def proxy_connect(pubkey, plugin=None):
    """Connect to a remote node via goTenna mesh proxy.
    """
    plugin.log(f"proxy-connect to pubkey {pubkey} via goTenna mesh connection")
    # Generate a random fd to listen on for this outbound connection.
    listen_addr = f"/tmp/0{uuid.uuid1().hex}"
    # Setup the listening server for C-Lightning to connect through, stated in the
    # main shared nursery.
    trio.from_thread.run(config.nursery.start, serve_outbound, f"{listen_addr}", pubkey)
    # Confirm the socket is created and listening.
    while not Path(listen_addr).is_socket():
        time.sleep(0.1)
    # Instruct C-Lightning RPC to connect to remote via the socket after it has been
    # established.
    return plugin.rpc.connect(pubkey, f"{listen_addr}")


@plugin.method("keysend-mesh")
def keysend_mesh(
    dest_pubkey, msatoshi, description=None, plugin=None,
):
    """sendpay via the mesh connection using key-send (non-interactive)
    args: dest_pubkey, msatoshi, [label]
    """
    log(f"keysend-mesh to {dest_pubkey} of {msatoshi} msatoshi")

    # create a random label if none given
    if not description:
        description = f"{uuid.uuid1().hex} keysend to {dest_pubkey} of {msatoshi}"

    # First we need to generate the secret data == first 64B of dest_pubkey
    preimage = bytes.fromhex(dest_pubkey[:64])
    log(f"preimage set as {preimage}")

    # Next we communicate the preimage back to a temp storage location for later
    config.key_sends[dest_pubkey] = preimage
    log(f"Stored preimage in config.key_sends[{dest_pubkey}] = {preimage}")

    # Now we generate the payment_hash to be used in the sendpay
    payment_hash = sha256(preimage).hexdigest()
    log(f"payment_hash set as {payment_hash}")

    # Get next peer in route
    # TODO: this should be listfunds in case we are not connected?
    peer = config.rpc.listpeers()["peers"][0]["id"]
    log(f"Got next peer {peer}")

    # we add 10 satoshis to amount (10 hops max x 1 satoshi fee each)
    # we add 60 to cltv (10 hops max, CLTV of 6 each)
    amt_msat = msatoshi + 10
    cltv = 9 + 60

    route = config.rpc.getroute(peer, msatoshi=amt_msat, riskfactor=10, cltv=cltv)[
        "route"
    ]
    log(f"Got route to {peer}, executing sendpay command.")

    return config.rpc.sendpay(route, payment_hash, description, amt_msat)


@plugin.init()
# Unused parameters used by lightning.plugin() internally
def init(options, configuration, plugin):
    # Store the RPC in config to be accessible by all.
    config.rpc = plugin.rpc
    # Get the local lightning node info.
    config.node_info = plugin.rpc.getinfo()
    # Set config.logger as the monkey-patched plugin logger
    # Will log to the C-Lightning log file (e.g. /tmp/l1-regtest/regtest/log) without
    # upsetting STDOUT or STDERR, used to communicate between C-Lightning and this
    # plugin.
    config.logger = plugin.log
    # Suppress all gossip messages from C-Lightning node.
    plugin.rpc.dev_suppress_gossip()
    log("goTenna plugin initialized")


async def main():
    """Main function that is run when the plugin is loaded (and run) by C-Lightning.
    Function decorated with @plugin.init() will be run when `plugin.run()` is called
    which must be at startup.
    """
    # This nursery will run our main tasks for us:
    # https://trio.readthedocs.io/en/stable/reference-core.html#tasks-let-you-do-multiple-things-at-once
    try:
        async with trio.open_nursery() as config.nursery:
            # We run the plugin itself in a synchronous thread so trio.run() maintains
            # overall control of the app.
            config.nursery.start_soon(trio.to_thread.run_sync, plugin.run)
            # # Start the goTenna connection daemon.
            config.nursery.start_soon(connection_daemon)
    except Exception:
        print(traceback.format_exc())
    finally:
        log("goTenna plugin finished.")


trio.run(main)
