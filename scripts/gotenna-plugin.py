#!/usr/bin/env python3
import threading
import time
from os.path import join
from uuid import uuid4

import trio
from lightning import LightningRpc, Plugin


from lnproxy.proxy import serve

plugin = Plugin()
rpc_interface = None
trio_token = None
nursery = None


# class Conn:
#     def __init__(self, listen_addr, outbound_addr):
#         self.listen_addr = listen_addr
#         self.outbound_addr = outbound_addr
#
#     def __str__(self):
#         return f"{self.listen_addr} {self.outbound_addr}"
#
#
# def proxy_connect(pubkey, outbound_addr, plugin=None):
#     global rpc_interface
#     print(f"pubkey: {pubkey}, outbound_addr: {outbound_addr}")
#     listen_addr = uuid4().hex
#     print(f"listen_addr: {listen_addr}")
#     _conn = Conn(f"/tmp/{listen_addr}", outbound_addr)
#     # send a tuple with connection information to the trio process
#     config.socket_queue.put(_conn)
#     print("Put the conn onto the socket_queue")
#     # instruct rpc to connect via that server
#     time.sleep(1)
#     return rpc_interface.connect(pubkey, f"/tmp/{listen_addr}")
#
#
# plugin.add_method(name="proxy-connect", func=proxy_connect, background=False)


@plugin.init()
def init(options, configuration, plugin):
    global nursery
    global rpc_interface
    global trio_token

    # configure rpc interface
    basedir = configuration["lightning-dir"]
    rpc_filename = configuration["rpc-file"]
    path = join(basedir, rpc_filename)
    plugin.log(f"rpc interface located at {path}")
    rpc_interface = LightningRpc(path)
    local_node = rpc_interface.getinfo()

    # start serving the primary listening socket within the main trio nursery
    trio.from_thread.run_sync(
        nursery.start_soon,
        serve,
        f"/tmp/{local_node['id']}-in",
        local_node["binding"][0]["socket"],
    )
    plugin.log("goTenna plugin initialized", level="info")


async def main():
    global nursery
    async with trio.open_nursery() as _nursery:
        nursery = _nursery
        await trio.to_thread.run_sync(plugin.run)
        # ensures the main nursery will never be closed down (if all tasks complete)
        await trio.sleep_forever()


trio.run(main)
