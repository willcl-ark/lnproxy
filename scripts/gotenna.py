#!/usr/bin/env python3
import os.path
import time
from uuid import uuid4

import trio

from lightning import Plugin
from lnproxy.proxy import serve_outbound
import lnproxy.config as config
from lnproxy.mesh_connection import Connection

plugin = Plugin()
listen_addr = ""


async def connection_daemon():
    """Load the goTenna mesh connection and sleep forever in a non-blocking way
    """
    # wait for node info to populate
    while config.node_info is None:
        await trio.sleep(0.1)
    # start the mesh connection
    c = Connection()
    # keep the daemon alive indefinitely
    while True:
        await trio.sleep_forever()


def proxy_connect(pubkey, plugin=None):
    """Connect to a remote node via the proxy.
    """
    plugin.log(f"Proxy connect to pubkey: {pubkey}")
    # Generate a random (file name) address to listen on.
    listen_addr = f"/tmp/{uuid4().hex}"

    # Setup the listening server socket for C-Lightning to connect through.
    # We wrap in trio.from_thread_run_sync() to start the server in the main nursery.
    trio.from_thread.run_sync(
        config.nursery.start_soon, serve_outbound, f"{listen_addr}", pubkey
    )
    # Wait until the socket is created and listening
    while not os.path.exists(listen_addr):
        plugin.log(f"Can't see unix socket at {listen_addr} yet")
        time.sleep(0.1)
    # Instruct C-Lightning RPC to connect to remote via the socket.
    return plugin.rpc.connect(pubkey, f"{listen_addr}")


def proxy_addr(plugin=None):
    """Return the node's listening proxy (unix) socket
    """
    node_info = plugin.rpc.getinfo()
    return {"addr": f"/tmp/{node_info['id']}"}


plugin.add_method(name="proxy-connect", func=proxy_connect, background=False)
plugin.add_method(name="proxy-addr", func=proxy_addr, background=False)


@plugin.init()
def init(options, configuration, plugin):
    config.rpc = plugin.rpc
    # Get the local node info
    config.node_info = plugin.rpc.getinfo()
    config.logger = plugin.log
    # suppress gossip
    plugin.rpc.dev_suppress_gossip()
    # start the connection daemon in main trio loop after we have node info
    plugin.log("goTenna plugin initialized")


async def main():
    config.trio_token = trio.hazmat.current_trio_token()
    # This nursery will run all our tasks for us.
    async with trio.open_nursery() as config.nursery:
        # We run the plugin itself in a synchronous thread wrapper so trio.run maintains
        # control of the app
        config.nursery.start_soon(trio.to_thread.run_sync, plugin.run)
        config.nursery.start_soon(connection_daemon)
        # Sleep ensures the main nursery will never be closed down (e.g. if all tasks
        # complete)
        config.nursery.start_soon(trio.sleep_forever)


trio.run(main)
