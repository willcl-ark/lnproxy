#!/usr/bin/env python3
import os.path
import time
from uuid import uuid4

import trio

from lightning import Plugin
from lnproxy.proxy import serve_outbound
import lnproxy.config as config
from lnproxy.mesh_connection import Connection

# autopatch=True monkey patches stdout and stderr
plugin = Plugin(autopatch=True)


async def connection_daemon():
    """Load the goTenna mesh connection and sleep forever in a non-blocking way
    """
    # Wait for node info to populate.
    while config.node_info is None:
        await trio.sleep(0.1)
    # start the mesh connection
    Connection()
    # Keep the daemon alive indefinitely.
    while True:
        await trio.sleep_forever()


@plugin.method("proxy-connect")
def proxy_connect(pubkey, plugin=None):
    """Connect to a remote node via goTenna mesh proxy.
    """
    plugin.log(f"Proxy connect to pubkey: {pubkey}")
    # Generate a random fd to listen on.
    listen_addr = f"/tmp/{uuid4().hex}"

    # Setup the listening server socket for C-Lightning to connect through.
    trio.from_thread.run_sync(
        config.nursery.start_soon, serve_outbound, f"{listen_addr}", pubkey
    )

    # Wait until the socket is created and listening.
    while not os.path.exists(listen_addr):
        time.sleep(0.1)
    # Instruct C-Lightning RPC to connect to remote via the socket.
    return plugin.rpc.connect(pubkey, f"{listen_addr}")


@plugin.method("proxy-addr")
def proxy_addr(plugin=None):
    """Return the node's listening proxy (unix) socket.
    """
    node_info = plugin.rpc.getinfo()
    return {"addr": f"/tmp/{node_info['id']}"}


@plugin.init()
def init(options, configuration, plugin):
    config.rpc = plugin.rpc
    # Get the local lightning node info.
    config.node_info = plugin.rpc.getinfo()
    config.logger = plugin.log
    # Suppress all gossip.
    plugin.rpc.dev_suppress_gossip()
    plugin.log("goTenna plugin initialized")


async def main():
    config.trio_token = trio.hazmat.current_trio_token()
    # This nursery will run all our tasks for us.
    try:
        async with trio.open_nursery() as config.nursery:
            # We run the plugin itself in a synchronous thread wrapper so trio.run
            # maintains control of the app.
            config.nursery.start_soon(trio.to_thread.run_sync, plugin.run)
            # # Start the goTenna connection daemon.
            config.nursery.start_soon(connection_daemon)
            # Sleep ensures the main nursery will never be closed down (e.g. if all
            # tasks complete).
            config.nursery.start_soon(trio.sleep_forever)
    except Exception as e:
        print(e)
    print("config.nursery dead")


trio.run(main)
