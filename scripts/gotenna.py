#!/usr/bin/env python3
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
    # global listen_addr

    print(f"Proxy connect to pubkey: {pubkey}")
    # Generate a random address to listen on (with Unix Socket).
    listen_addr = f"/tmp/{uuid4().hex}"
    print(f"listen_addr: {listen_addr}")

    # Setup the listening server socket for C-Lightning to connect through.
    # Again we wrap in trio.from_thread_run_sync() to start the server calling back to
    # the global nursery.
    trio.from_thread.run_sync(
        config.nursery.start_soon, serve_outbound, f"{listen_addr}", pubkey
    )

    # Instruct C-Lightning RPC to connect to remote via the socket.
    time.sleep(0.5)
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
    # Start serving the primary listening socket to receive all incoming connections.
    # Wrap in a trio.from_thread_sync() to call back to the main thread using the
    # nursery from the global scope.
    # trio.from_thread.run_sync(
    #     config.nursery.start_soon,
    #     serve,
    #     f"/tmp/{node_info['id']}",
    #     node_info["binding"][0]["socket"],
    #     True,
    #     False,
    # )

    # suppress gossip
    plugin.rpc.dev_suppress_gossip()
    # start the connection daemon in main trio pool after we have node info
    plugin.log("goTenna plugin initialized", level="info")


async def main():
    config.trio_token = trio.hazmat.current_trio_token()
    # This nursery will run all our tasks for us.
    async with trio.open_nursery() as config.nursery:
        # We run the plugin itself in a synchronous thread wrapper so trio.run maintains
        # control of the app
        config.nursery.start_soon(trio.to_thread.run_sync, plugin.run)
        print("Started plugin.run")
        config.nursery.start_soon(connection_daemon)
        # Sleep ensures the main nursery will never be closed down (e.g. if all tasks
        # complete)
        config.nursery.start_soon(trio.sleep_forever)


trio.run(main)
