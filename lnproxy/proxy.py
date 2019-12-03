import contextvars
import functools
import itertools
import socket

import trio

# Global counter for the connection log messages
cont = itertools.count()
# Context variable for the connection log messages
request_info = contextvars.ContextVar("request_info")


def log(msg):
    """Logs a message using the context var.
    We rely on the C-Lightning plugin monkey patch to catch regular print statements
    """
    # Get the appropriate context variable
    request_tag = request_info.get()
    # Log the message
    print(f"Conn {request_tag}: {msg}")


async def unlink_socket(address):
    """Unlink a Unix Socket at address 'address'.
    """
    socket_path = trio.Path(address)
    try:
        await socket_path.unlink()
    except OSError:
        # Only raise an error if the path exists but we can't unlink it, else ignore
        if await socket_path.exists():
            raise


async def proxy_stream(read_stream, write_stream):
    """Proxy two streams.
    """
    while True:
        # Currently we just read and write from the streams alternately, writing data
        # after we read it.
        try:
            data = await read_stream.receive_some()
            await write_stream.send_all(data)
        except trio.BrokenResourceError:
            log("Remote closed the connection")
            return


async def handle_connection(inbound_stream, addr=None):
    """Create the outbound connection to addr and proxy inbound and outbound streams.
    """
    global cont
    # Get a new context var for the connection logs
    request_info.set(next(cont))
    # Open the outbound connection
    outbound_stream = await trio.open_unix_socket(addr)
    log(f"Proxying connection between {inbound_stream} and {outbound_stream}")
    try:
        # We run the proxies in a nursery so they can run simultaneously
        async with trio.open_nursery() as nursery:
            nursery.start_soon(proxy_stream, outbound_stream, inbound_stream)
            nursery.start_soon(proxy_stream, inbound_stream, outbound_stream)
    except ValueError as e:
        log(f"Error from handle_connection():\n{e}")
    except trio.ClosedResourceError as e:
        log(f"Attempted to use resource after we closed:\n{e}")
    finally:
        await inbound_stream.aclose()
        await outbound_stream.aclose()


async def serve(listen_addr, outbound_addr):
    """Serve a listening socket at listen_addr.
    Start a handler for each new connection.
    """
    # Setup the listening socket
    sock = trio.socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    await sock.bind(listen_addr)
    sock.listen()
    print(f"Listening on socket {listen_addr}")
    # Start a new handle_connection() for each new connection
    try:
        await trio.serve_listeners(
            # We wrap in a partial so that we can pass outbound_addr to
            # handle_connection because serve_listeners() doesn't support passing args.
            functools.partial(handle_connection, addr=outbound_addr),
            [trio.SocketListener(sock)],
        )
    except Exception as e:
        print(f"server error:\n{e}")
    finally:
        # Unlink the socket if it gets closed.
        await unlink_socket(listen_addr)
