import contextvars
import itertools
import socket

import trio

# TODO: remove hack
addr = ""

cont = itertools.count()
request_info = contextvars.ContextVar("request_info")


def log(msg):
    request_tag = request_info.get()
    print(f"Conn {request_tag}: {msg}")


async def unlink_socket(sock):
    """Unlink a Unix Socket
    """
    socket_path = trio.Path(sock)
    try:
        await socket_path.unlink()
    except OSError:
        if await socket_path.exists():
            raise


async def proxy_stream(read_stream, write_stream):
    """Proxy two streams
    """
    while True:
        try:
            data = await read_stream.receive_some()
            await write_stream.send_all(data)
        except trio.BrokenResourceError:
            log("Remote closed the connection")
            return


async def handle_connection(inbound_stream):
    """Create the outbound stream and proxy inbound and outbound
    """
    # TODO: remove hack to receive addr from serve()
    global addr
    global cont
    request_info.set(next(cont))
    outbound_stream = await trio.open_unix_socket(addr)
    log(f"Proxying connection between {inbound_stream} and {outbound_stream}")
    try:
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
    """Serve a listener for the connection
    Pass outbound addr to handle_connection via global `addr`
    """
    # TODO: remove hack to pass addr to handle_connection()
    global addr

    addr = outbound_addr
    sock = trio.socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    await sock.bind(listen_addr)
    sock.listen()
    print(f"Listening on socket {listen_addr}")
    try:
        await trio.serve_listeners(handle_connection, [trio.SocketListener(sock)])
    except Exception as e:
        print(f"server error:\n{e}")
    finally:
        # Unlink the socket if it gets closed.
        await unlink_socket(listen_addr)
