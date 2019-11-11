import logging
import socket
import struct

import trio

import ln_msg

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(f"{'PROXY':<5}")

SRV_SOCK = "/tmp/unix_proxy"
CLIENT_SOCK = "/tmp/l2-regtest/unix_socket"
MAX_PKT_LEN = 65569
MSG_LEN = 2
MSG_LEN_MAC = 16
MSG_HEADER = MSG_LEN + MSG_LEN_MAC
MSG_MAC = 16


async def unlink_socket(sock):
    """Unlink a Unix Socket
    """
    socket_path = trio.Path(sock)
    try:
        await socket_path.unlink()
    except OSError:
        if await socket_path.exists():
            raise


async def proxy(read_stream, write_stream, direction):
    """Proxy traffic from one stream to another
    """

    # Bolt #8: The handshake proceeds in three acts, taking 1.5 round trips.
    handshake_acts = 2 if direction == "Outbound" else 1
    i = 0

    while True:
        try:
            if i < handshake_acts:

                # during handshake pass full 50 / 66 B messages transparently for now
                # TODO: mock these!
                logger.debug(f"{direction:9s} | handshake message {i + 1}")
                message = await read_stream.receive_some(MAX_PKT_LEN)

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

                # re-constitute the header and body
                message = header + body + body_mac

            # send to remote
            await write_stream.send_all(message)

            # increment handshake counter
            i += 1
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
            logger.debug(f"Starting proxy")
            # remote lightning node
            nursery.start_soon(proxy, server_stream, client_stream, "Outbound")
            # local lightning node
            nursery.start_soon(proxy, client_stream, server_stream, "Inbound")
    except Exception as exc:
        print(f"socket_handler: crashed: {exc}")
    finally:
        await client_stream.aclose()


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
