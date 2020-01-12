#!/usr/bin/env python3
import os.path
import time
import traceback
from uuid import uuid4

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
    plugin.log(f"Proxy connect to pubkey: {pubkey}")
    # Generate a random fd to listen on for this outbound connection.
    listen_addr = f"/tmp/{uuid4().hex}"
    # Setup the listening server for C-Lightning to connect through, stated in the
    # main shared nursery.
    trio.from_thread.run(config.nursery.start, serve_outbound, f"{listen_addr}", pubkey)
    # Confirm the socket is created and listening.
    log("Waiting for socket to be created")
    while not os.path.exists(listen_addr):
        time.sleep(0.1)
    # Instruct C-Lightning RPC to connect to remote via the socket after it has been
    # established.
    log(f"Running command `rpc connect {pubkey}@{listen_addr}")
    return plugin.rpc.connect(pubkey, f"{listen_addr}")


@plugin.init()
# Parameters used by lightning.plugin()
def init(options, configuration, plugin):
    # Store the RPC in config to be accessible by all.
    config.rpc = plugin.rpc
    # Get the local lightning node info.
    config.node_info = plugin.rpc.getinfo()
    # Set config.logger as the monkey-patched plugin logger
    # Will log to the C-Lightning log file (e.g. /tmp/l1-regtest/regtest/log) without
    # upsetting STDOUT or STDERR, used to communicate between C-Lightning and (this)
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
    # Save the trio_token. This can be used if a function, not started by Trio, wants to
    # run something in the main trio thread e.g:
    # https://trio.readthedocs.io/en/stable/reference-core.html#trio.from_thread.run_sync
    config.trio_token = trio.hazmat.current_trio_token()
    # This nursery will run all our tasks for us:
    # https://trio.readthedocs.io/en/stable/reference-core.html#tasks-let-you-do-multiple-things-at-once
    try:
        async with trio.open_nursery() as config.nursery:
            # We run the plugin itself in a synchronous thread wrapper so trio.run
            # maintains control of the app.
            config.nursery.start_soon(trio.to_thread.run_sync, plugin.run)
            # # Start the goTenna connection daemon.
            config.nursery.start_soon(connection_daemon)
            # Sleep ensures the main nursery will never be closed down (e.g. if all
            # tasks complete).
            # config.nursery.start_soon(trio.sleep_forever)
    except Exception:
        print(traceback.format_exc())
        return


trio.run(main)
