"""C-lightning mesh proxy.

Usage:
    proxy.py [--debug R_ADDR] L_PUBKEY R_PUBKEY R_GID

Arguments:
    L_PUBKEY        Local node pubkey
    R_PUBKEY        Remote node pubkey
    R_GID           Remote node goTenna GID

Options:
    --debug=R_ADDR  If in debug mode, specify the remote node Unix Socket to connect to
"""
from docopt import docopt
import logging
import socket
import struct
import time

import trio

import lnproxy.ln_msg as ln_msg

logger = logging.getLogger(f"{'PROXY':<6s}")
logging.basicConfig(level=logging.DEBUG)

MSG_LEN: int = 2
MSG_LEN_MAC: int = 16
MSG_HEADER: int = MSG_LEN + MSG_LEN_MAC
MSG_MAC: int = 16
_args = {}
_plugin = None


async def unlink_socket(sock):
    """Unlink a Unix Socket
    """
    socket_path = trio.Path(sock)
    try:
        await socket_path.unlink()
    except OSError:
        if await socket_path.exists():
            raise


async def receive_exactly(stream, length, timeout=500):
    res = b""
    end = time.time() + timeout
    while len(res) < length and time.time() < end:
        res += await stream.receive_some(length - len(res))
    if len(res) == length:
        logger.debug(res)
        return res
    else:
        raise TimeoutError("Didn't receive enough bytes within the timeout, discarding")


async def proxy(read_stream, write_stream, initiator):
    """Proxy message traffic from one stream to another.
    Handle and parse certain lightning messages.
    """
    while True:
        try:
            data = await read_stream.receive_some()
            print(f"Got data: {data}")
            await write_stream.send_all(data)
        except TimeoutError:
            break
        except Exception:
            logger.exception("Exception inside proxy.proxy")
            break


async def socket_handler_local(stream):
    """Handles a listening socket.
    Passes the stream to proxy() which will proxy it with a mesh memory_channel
    :arg stream: a trio.SocketStream for the listening socket
    """
    global _args
    if _args["--debug"]:
        # if we are debugging, open a direct unix socket to next host
        remote_stream = await trio.open_unix_socket(_args["--debug"])
        send_to_mesh = remote_stream
        receive_from_mesh = remote_stream
    else:
        send_to_mesh, receive_from_server = trio.testing.memory_stream_pair()
        send_to_server, receive_from_mesh = trio.testing.memory_stream_pair()
    try:
        async with trio.open_nursery() as nursery:
            nursery.start_soon(proxy, stream, send_to_mesh, True)
            nursery.start_soon(proxy, receive_from_mesh, stream, False)
    except Exception:
        logger.exception(f"Local socket_handler: crashed")
    finally:
        await stream.aclose()


async def serve_unix_socket(socket_address):
    """Serve a listening unix socket on 'socket_address'
    Handles the socket using socket_handler_local
    """
    await unlink_socket(socket_address)
    listeners = []

    # Create the listening socket, bind to it and listen
    sock = trio.socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    await sock.bind(socket_address)
    sock.listen()
    listeners.append(trio.SocketListener(sock))

    try:
        # Manage the listening with the handler
        await trio.serve_listeners(socket_handler_local, listeners)
    except Exception:
        logger.exception("serve_unix_socket: crashed")
    finally:
        # unlink the socket if it gets closed
        await unlink_socket(socket_address)


def main():
    global _args
    _args = docopt(__doc__, version="Lightning mesh proxy 0.2.1")
    socket_address = f"/tmp/{_args['R_PUBKEY']}"
    try:
        trio.run(serve_unix_socket, socket_address)
    except Exception:
        logger.exception("Main thread stopped")


def plugin_main(local_pubkey, remote_pubkey, remote_gid, request=None, plugin=None):
    global _args
    global _plugin
    _plugin = plugin

    _args["--debug"] = "/tmp/l2-regtest/unix_socket"
    _args["L_PUBKEY"] = local_pubkey
    _args["R_PUBKEY"] = remote_pubkey
    _args["R_GID"] = remote_gid
    socket_address = f"/tmp/{_args['R_PUBKEY']}"
    _plugin.log(
        "_arg dict is: ".join(
            ["%s:%s\n" % (key, value) for (key, value) in _args.items()]
        )
    )
    plugin.log(f"Socket address is: {socket_address}")
    request.set_result("Proxy Started")
    try:
        trio.run(serve_unix_socket, socket_address)
    except Exception:
        logger.exception("Main thread stopped")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Stopping Proxy")
