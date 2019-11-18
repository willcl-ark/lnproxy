"""C-lightning mesh proxy.

Usage:
    proxy.py NODE_ID

Arguments:
    NODE_ID     an int (1, 2, 3) determining node number this proxy will run for
"""
from docopt import docopt
import logging
import socket
import struct

import trio

import lnproxy.config as config
import lnproxy.ln_msg as ln_msg
import lnproxy.util as util


logger = logging.getLogger(f"{'PROXY':<6s}")


MAX_PKT_LEN: int = 65569
MSG_LEN: int = 2
MSG_LEN_MAC: int = 16
MSG_HEADER: int = MSG_LEN + MSG_LEN_MAC
MSG_MAC: int = 16
args = {}


async def unlink_socket(sock):
    """Unlink a Unix Socket
    """
    socket_path = trio.Path(sock)
    try:
        await socket_path.unlink()
    except OSError:
        if await socket_path.exists():
            raise


async def proxy(read_stream, write_stream, initiator, direction):
    """Proxy lightning message traffic from one stream to another.
    Handle and parse certain lightning messages.
    """
    # Bolt #8: The handshake proceeds in three acts, taking 1.5 round trips.
    hs_acts = 2 if initiator else 1
    hs_pkt_size = {"outbound": [50, 66], "inbound": [50]}
    i = 0

    while True:
        try:
            if i < hs_acts:
                # during handshake pass full 50 / 66 B messages transparently for now
                req_len = hs_pkt_size[direction][i]
                # TODO: mock these!
                logger.debug(f"{direction:<15s} | handshake message {i + 1}")
                message = b""
                while len(message) < req_len:
                    message += await read_stream.receive_some(req_len - len(message))

            else:
                # Bolt #8: Read exactly 18 bytes from the network buffer.
                header = await read_stream.receive_some(MSG_HEADER)

                if len(header) != MSG_HEADER:
                    logger.debug(
                        f"{direction} could not get full header length: 18 != "
                        f"{len(header)}"
                    )
                    break

                # Bolt #8: 2-byte encrypted message length
                body_len = struct.unpack(">H", header[:MSG_LEN])[0]

                # Bolt #8: 16-byte MAC of the encrypted message length
                body_len_mac = struct.unpack("16s", header[-16:])[0]

                # Bolt #8: (de)encrypted Lightning message
                body = await read_stream.receive_some(body_len)

                # parse the message
                body = ln_msg.parse(body, direction)

                # Bolt #8: 16 Byte MAC of the Lightning message
                body_mac = await read_stream.receive_some(MSG_MAC)
                # we can add a fake MAC on here during full mesh operation
                # body_mac = 16 * (bytes.fromhex("00"))

                # re-constitute the header and body
                # if direction == "from_local":
                #     message = header + body
                # else:
                message = header + body + body_mac

            # send to remote
            logger.debug(f"Sending message {direction:<15s} | {len(message)}")
            await write_stream.send_all(message)

            # increment handshake counter
            i += 1
        except:
            raise


async def socket_handler_local(local_stream):
    """Handles a listening socket for local connections.
    Makes outbound connection to proxy traffic with.
    :arg local_stream: a trio.SocketStream for the listening socket
    """
    logger.debug(f"Starting proxy for a local inbound connection")
    # When we receive a new connection from a local node, open a new connection to
    # the remote node & proxy the streams
    logger.debug("Making outbound connection to remote node")
    remote_stream = await trio.open_unix_socket(config.remote_node_addr)
    try:
        # We run both proxies in a nursery as stream.send_all() can be blocking
        async with trio.open_nursery() as nursery:
            nursery.start_soon(proxy, local_stream, remote_stream, True, "outbound")
            nursery.start_soon(proxy, remote_stream, local_stream, False, "inbound")
    except Exception:
        logger.exception(f"Local socket_handler: crashed")
    finally:
        await remote_stream.aclose()


async def socket_handler_remote(remote_stream):
    """Handles a listening socket for remote connections.
    :arg remote_stream: a trio.SocketStream for the listening socket
    """
    logger.debug(f"Starting proxy for a remote inbound connection")
    # When we receive a new connection from a remote node, open a new connection to
    # the local node & proxy the streams
    logger.debug(f"Making outbound connection to local node")
    local_stream = await trio.open_unix_socket(config.local_node_addr)
    try:
        # We run both proxies in a nursery as stream.send_all() can be blocking
        async with trio.open_nursery() as nursery:
            nursery.start_soon(proxy, local_stream, remote_stream, False, "inbound")
            nursery.start_soon(proxy, remote_stream, local_stream, True, "outbound")
    except Exception:
        logger.exception(f"Remote socket_handler: crashed")
    finally:
        await local_stream.aclose()


async def serve_unix_socket(socket_address, local):
    """Serve a listening socket
    """
    loc = "local" if local is True else "remote"
    await unlink_socket(socket_address)
    listeners = []

    # Create the listening socket
    sock = trio.socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    await sock.bind(socket_address)
    sock.listen()
    logger.debug(f"Listening for {loc} connections on Unix Socket: {socket_address}")
    listeners.append(trio.SocketListener(sock))

    # Manage the listening with the handler
    try:
        if local:
            await trio.serve_listeners(socket_handler_local, listeners)
        else:
            await trio.serve_listeners(socket_handler_remote, listeners)
    except Exception:
        logger.exception("serve_unix_socket: crashed")
    finally:
        await trio.Path.unlink(config.local_listen_SOCK)


async def serve_sockets():
    """Start two listening unix socket servers, one for remote and one for local nodes
    """
    try:
        async with trio.open_nursery() as nursery:
            logger.debug("Starting serve_unix_socket nursery")
            nursery.start_soon(serve_unix_socket, config.remote_listen_SOCK, False)
            nursery.start_soon(serve_unix_socket, config.local_listen_SOCK, True)

    except Exception:
        logger.exception("socket_handler: crashed")
    finally:
        await unlink_socket(config.remote_listen_SOCK)
        await unlink_socket(config.local_listen_SOCK)


if __name__ == "__main__":
    args = docopt(__doc__, version="Lightning mesh proxy 0.1")
    config.my_node = int(args["NODE_ID"]) - 1
    util.init_nodes()
    util.set_socks(int(config.my_node))
    logger.debug(f"config.my_node = {config.my_node}")
    logger.debug(f"Running for node {config.my_node_pubkey}")
    logger.debug(f"Next node pubkey {config.next_node_pubkey}")
    try:
        trio.run(serve_sockets)
    except KeyboardInterrupt:
        print("Stopping proxy")
    except Exception:
        logger.exception("Main thread stopped")
