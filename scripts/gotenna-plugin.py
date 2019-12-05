#!/usr/bin/env python3
import time
from uuid import uuid4

import trio

from lightning import Plugin
from lnproxy.proxy import serve
import lnproxy.config

plugin = Plugin()
nursery = None


def proxy_connect(pubkey, outbound_addr, plugin=None):
    """Connect to a remote node via the proxy.
    """
    global nursery

    print(f"pubkey: {pubkey}, outbound_addr: {outbound_addr}")
    # Generate a random address to listen on (with Unix Socket).
    listen_addr = uuid4().hex
    print(f"listen_addr: {listen_addr}")

    # Setup the listening server socket for C-Lightning to connect through.
    # Again we wrap in trio.from_thread_run_sync() to start the server calling back to
    # the global nursery.
    trio.from_thread.run_sync(
        nursery.start_soon, serve, f"/tmp/{listen_addr}", outbound_addr, True
    )
    plugin.log(
        f"Now listening on {listen_addr}, ready to proxy out to {outbound_addr}",
        level="info",
    )

    # Instruct C-Lightning RPC to connect to remote via the socket.
    time.sleep(1)
    return plugin.rpc.connect(pubkey, f"/tmp/{listen_addr}")


plugin.add_method(name="proxy-connect", func=proxy_connect, background=False)


@plugin.init()
def init(options, configuration, plugin):
    global nursery
    lnproxy.config.rpc = plugin.rpc

    # Get the local node info
    node_info = plugin.rpc.getinfo()

    # Start serving the primary listening socket to receive all incoming connections.
    # Wrap in a trio.from_thread_sync() to call back to the main thread using the
    # nursery from the global scope.
    trio.from_thread.run_sync(
        nursery.start_soon,
        serve,
        f"/tmp/{node_info['id']}",
        node_info["binding"][0]["socket"],
        False,
    )
    plugin.log("goTenna plugin initialized", level="info")


async def main():
    global nursery
    # This nursery will run all our tasks for us.
    async with trio.open_nursery() as _nursery:
        # Pass reference to global scope so that plugin can easily add tasks to it.
        nursery = _nursery
        # We run the plugin itself in a synchronous thread wrapper so trio.run maintains
        # control of the app
        await trio.to_thread.run_sync(plugin.run)
        # Sleep ensures the main nursery will never be closed down (e.g. if all tasks
        # complete)
        await trio.sleep_forever()


trio.run(main)
