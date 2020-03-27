"""Proxy between two TCP servers.
"""

import argparse

import trio

parser = argparse.ArgumentParser(description="proxy two tcp sockets")
parser.add_argument("port1", type=int, help="port of node A")
parser.add_argument("port2", type=int, help="port of node B")
args = parser.parse_args()


async def main():
    """Make an outbound connection to two TCP servers, and proxy the streams.
    """
    stream_a = await trio.open_tcp_stream("127.0.0.1", args.port1)
    stream_b = await trio.open_tcp_stream("127.0.0.1", args.port2)

    async def a_to_b(a: trio.SocketStream, b: trio.SocketStream):
        async for data in a:
            await b.send_all(data)

    async def b_to_a(b: trio.SocketStream, a: trio.SocketStream):
        async for data in b:
            await a.send_all(data)

    async with stream_a, stream_b:
        async with trio.open_nursery() as nursery:
            nursery.start_soon(a_to_b, stream_a, stream_b)
            nursery.start_soon(b_to_a, stream_b, stream_a)


trio.run(main)
