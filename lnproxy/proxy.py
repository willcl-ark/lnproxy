import functools
import trio

import lnproxy.config as config
import lnproxy.util as util


log = config.log


async def queue_to_stream(queue, stream):
    """Read from a queue and write to a stream
    """
    while True:
        if queue.empty():
            await trio.sleep(5)
        else:
            msg = queue.get()
            await stream.send_all(msg)


async def stream_to_queue(stream, queue):
    """Read from a stream and write to a queue
    """
    async for message in stream:
        queue.put(message)


async def proxy_streams(stream, _pubkey):
    log(f"Proxying between stream and queue {_pubkey}")
    try:
        async with trio.open_nursery() as nursery:
            nursery.start_soon(
                stream_to_queue, stream, config.QUEUE[_pubkey]["to_send"],
            )
            nursery.start_soon(
                queue_to_stream, config.QUEUE[_pubkey]["recvd"], stream,
            )
    except trio.ClosedResourceError as e:
        log(f"Attempted to use resource after we closed:\n{e}")
    finally:
        await stream.aclose()


async def handle_inbound(_pubkey):
    log(f"Handling new incoming connection from pubkey: {_pubkey}")
    # first connect to our local C-Lightning node
    stream = await trio.open_unix_socket(config.node_info["binding"][0]["socket"])
    log("Connection made to local C-Lightning node")
    # next proxy between the queue and the socket
    await proxy_streams(stream, _pubkey)


async def handle_outbound(stream, pubkey: str):
    """Started for each outbound connection.
    """
    _pubkey = pubkey[0:4]
    log(f"Handling new outbound connection to {_pubkey}")
    if pubkey not in config.QUEUE:
        util.create_queue(_pubkey)
    log(f"Created mesh queue for {_pubkey}")
    await proxy_streams(stream, _pubkey)


async def serve_outbound(listen_addr, pubkey: str):
    """Serve a listening socket at listen_addr.
    Start a handler for each new connection.
    """
    # Setup the listening socket
    sock = trio.socket.socket(trio.socket.AF_UNIX, trio.socket.SOCK_STREAM)
    await sock.bind(listen_addr)
    sock.listen()
    log(f"Listening for new outbound connections on {listen_addr}")
    # Start a new handle_connection() for each new connection
    try:
        await trio.serve_listeners(
            functools.partial(handle_outbound, pubkey=pubkey),
            [trio.SocketListener(sock)],
        )
    except Exception as e:
        log(f"proxy.serve_outbound error:\n{e}")
