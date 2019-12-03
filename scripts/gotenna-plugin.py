#!/usr/bin/env python3
import threading
import time
from os.path import join
from uuid import uuid4

import trio
from lightning import LightningRpc, Plugin

import lnproxy.config as config
from lnproxy.proxy import main

plugin = Plugin()
rpc_interface = None
trio_thread = threading.Thread(target=trio.run, args=[main])
trio_token = None


class Conn:
    def __init__(self, listen_addr, outbound_addr):
        self.listen_addr = listen_addr
        self.outbound_addr = outbound_addr

    def __str__(self):
        return f"{self.listen_addr} {self.outbound_addr}"


def proxy_connect(pubkey, outbound_addr, plugin=None):
    global rpc_interface
    print(f"pubkey: {pubkey}, outbound_addr: {outbound_addr}")
    listen_addr = uuid4().hex
    print(f"listen_addr: {listen_addr}")
    _conn = Conn(f"/tmp/{listen_addr}", outbound_addr)
    # send a tuple with connection information to the trio process
    config.socket_queue.put(_conn)
    print("Put the conn onto the socket_queue")
    # instruct rpc to connect via that server
    time.sleep(1)
    return rpc_interface.connect(pubkey, f"/tmp/{listen_addr}")


plugin.add_method(name="proxy-connect", func=proxy_connect, background=False)


@plugin.init()
def init(options, configuration, plugin):
    global rpc_interface
    global trio_thread
    global trio_token

    # configure rpc interface
    basedir = configuration["lightning-dir"]
    rpc_filename = configuration["rpc-file"]
    path = join(basedir, rpc_filename)
    plugin.log(f"rpc interface located at {path}")
    rpc_interface = LightningRpc(path)
    local_node = rpc_interface.getinfo()

    # put the first listening server details onto the queue
    _conn = Conn(
        listen_addr=f"/tmp/{local_node['id']}-in",
        outbound_addr=local_node["binding"][0]["socket"],
    )
    config.socket_queue.put(_conn)

    # start the main trio server thread
    trio_thread.start()
    # the trio_token allows you to send jobs into the trio process
    trio_token = trio.hazmat.TrioToken
    plugin.log("goTenna plugin initialized", level="info")


plugin.run()
