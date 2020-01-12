import argparse
import os.path
import time
import traceback
from uuid import uuid4

import trio
from lightning import LightningRpc

import lnproxy.config as config
import lnproxy.mesh_connection as mesh
import lnproxy.util as util
from lnproxy.proxy import serve_outbound


next_node = None


def proxy_connect(pubkey):
    """Connect to a remote node via goTenna mesh proxy.
    """
    time.sleep(10)
    util.log(f"Proxy connect to pubkey: {pubkey}")
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
    return config.rpc.connect(pubkey, f"{listen_addr}")


def connect_to_clightning():
    # connect to node RPC based on folder path
    config.rpc_s[1] = LightningRpc(f"/tmp/l1-regtest/regtest/lightning-rpc")
    config.rpc_s[2] = LightningRpc(f"/tmp/l2-regtest/regtest/lightning-rpc")
    config.rpc_s[3] = LightningRpc(f"/tmp/l3-regtest/regtest/lightning-rpc")
    config.rpc = config.rpc_s[args.node_id]
    config.node_info = config.rpc.getinfo()
    util.log(config.node_info)
    config.rpc.dev_suppress_gossip()
    util.log("Connected to C-Lightning. Gossip suppressed")


async def connection_daemon():
    """Load the goTenna mesh connection and sleep forever in a non-blocking way
    """
    # Wait for node info to populate.
    while config.node_info is None:
        await trio.sleep(0.1)
    # start the mesh connection
    config.mesh_conn = mesh.Connection()
    # Keep the daemon alive indefinitely.
    while True:
        await trio.sleep_forever()


async def main():
    connect_to_clightning()
    config.trio_token = trio.hazmat.current_trio_token()
    # This nursery will run all our tasks for us.
    try:
        async with trio.open_nursery() as config.nursery:
            # Start the goTenna connection daemon.
            config.nursery.start_soon(connection_daemon)
            if args.node_id == 1:
                config.nursery.start_soon(
                    trio.to_thread.run_sync, proxy_connect, next_node
                )
            # Sleep ensures the main nursery will never be closed down (e.g. if all
            # tasks complete).
            config.nursery.start_soon(trio.sleep_forever)
    except Exception:
        print(f"Exception caught in config.nursery:\n{traceback.format_exc()}")
    print("config.nursery dead")


parser = argparse.ArgumentParser(description="Establish C-Lightning connection")
parser.add_argument("node_id", type=int, help="node_id to connect to")
args = parser.parse_args()
if args.node_id == 1:
    next_node = "03512298acad7fb9b6d2a8096cfe231ead64ae81cc29c78e23329f745d633a5590"
elif args.node_id == 2:
    next_node = "026e962239a803c0f005751e60ac1e09772fcce206d0a1b666319423017142d879"
elif args.node_id == 3:
    next_node = "02492bb1fb0eca426af73c189d115fcda79fa9a2f77783e8d9bda4c64e5716af94"
else:
    print(f"Could not get next_node using arg {args.node_id}")

trio.run(main)
