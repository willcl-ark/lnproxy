#!/usr/bin/env python3
from os.path import join
from uuid import uuid4
from lightning import Plugin, LightningRpc
from lnproxy.proxy_final import main
import lnproxy.config as config
import threading
import trio

plugin = Plugin()
rpc_interface = None
trio_thread = threading.Thread(target=trio.run, args=[main])


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
    # rpc_interface.connect(pubkey, f"/tmp/{listen_addr}")
    return


plugin.add_method(name="proxy-connect", func=proxy_connect, background=True)


@plugin.init()
def init(options, configuration, plugin):
    global rpc_interface
    global trio_thread

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
    plugin.log("goTenna plugin initialized", level="info")


plugin.run()
