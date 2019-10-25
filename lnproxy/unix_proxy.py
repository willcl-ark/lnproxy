import logging
import socket

import trio
from util import hexdump


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("PROXYSRV")

SRV_SOCK = "/tmp/unix_proxy"
CLIENT_SOCK = "/tmp/l2-regtest/unix_socket"
RECV_BUF = 210


async def unlink_socket(sock):
    """Unlink a Unix Socket
    """
    p = trio.Path(sock)
    try:
        await p.unlink()
    except OSError:
        if await p.exists():
            raise


async def proxy(read_stream, write_stream, direction):
    """Proxy traffic from one stream to another
    """
    logger.debug(f"{direction} proxy started")
    while True:
        try:
            # for data in read_stream:
            data = await read_stream.receive_some(RECV_BUF)
            if not data:
                logger.debug("Connection closed by remote")
                break
            await write_stream.send_all(data)
            logger.debug(f"{direction}: {len(data)}B ")
            hexdump(data)
        except:
            raise


async def socket_handler(server_stream):
    """Handles a listening socket. Makes outbound connection to proxy traffic with.
    :arg server_stream: a trio.SocketStream for the listening socket
    """
    client_stream = await trio.open_unix_socket(CLIENT_SOCK)
    try:
        # We run both proxies in a nursery as stream.send_all() can be blocking
        async with trio.open_nursery() as nursery:
            nursery.start_soon(proxy, server_stream, client_stream, "Outbound")
            nursery.start_soon(proxy, client_stream, server_stream, "Inbound")
    except Exception as exc:
        print(f"unix_handler: crashed: {exc}")


async def serve_unix_socket():
    await unlink_socket(SRV_SOCK)

    # Create the listening socket
    sock = trio.socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    await sock.bind(SRV_SOCK)
    sock.listen()
    logger.debug(f"Listening on Unix Socket: {SRV_SOCK}")
    listener = trio.SocketListener(sock)

    # Manage the listening with the handler
    try:
        await trio.serve_listeners(socket_handler, [listener])
    except Exception as exc:
        print(f"serve_unix_socket: crashed: {exc}")
    finally:
        await trio.Path.unlink(SRV_SOCK)


trio.run(serve_unix_socket)
