import contextvars
import functools
import itertools
import socket
import struct
import time

import trio

from lnproxy import ln_msg

# Global counter for the connection log messages
COUNTER = itertools.count()
# Context variable for the connection log messages
request_info = contextvars.ContextVar("request_info")


MAX_PKT_LEN: int = 65569
MSG_LEN: int = 2
MSG_LEN_MAC: int = 16
MSG_HEADER: int = MSG_LEN + MSG_LEN_MAC
MSG_TYPE: int = 2
ONION_SIZE: int = 1366
MSG_MAC: int = 16


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


async def receive_exactly(stream, length, timeout=500):
    res = b""
    end = time.time() + timeout
    while len(res) < length and time.time() < end:
        res += await stream.receive_some(length - len(res))
    if len(res) == length:
        return res
    else:
        raise TimeoutError("Didn't receive enough bytes within the timeout, discarding")


async def proxy_stream(read_stream, write_stream, initiator, to_mesh, logger=log):
    """Proxy lightning message traffic from one stream to another.
    Handle and parse certain lightning messages.
    """
    # Bolt #8: The handshake proceeds in three acts, taking 1.5 round trips.
    hs_acts = 2 if initiator else 1
    hs_pkt_size = {True: [50, 66], False: [50]}
    i = 0
    while True:
        try:
            # if a handshake message
            if i < hs_acts:
                # pass full 50 / 66 B messages transparently
                req_len = hs_pkt_size[initiator][i]
                message = b""
                message += await receive_exactly(read_stream, req_len)
            # all non-handshake messages
            else:
                # Bolt #8: Read exactly 18 bytes from the network buffer.
                header = await receive_exactly(read_stream, MSG_HEADER)

                if len(header) != MSG_HEADER:
                    break

                # Bolt #8: 2-byte message length
                body_len = struct.unpack(">H", header[:MSG_LEN])[0]

                # Bolt #8: 16-byte MAC of the message length
                # body_len_mac = struct.unpack("16s", header[-16:])[0]
                # TODO: we can add a fake MAC on here during full mesh operation
                # body_len_mac = 16 * (bytes.fromhex("00"))

                # Bolt #8: Lightning message
                body = await read_stream.receive_some(body_len)

                # parse the message
                header, body = ln_msg.parse(header, body, to_mesh, logger)

                # Bolt #8: 16 Byte MAC of the Lightning message
                body_mac = await read_stream.receive_some(MSG_MAC)
                # TODO: we can add a fake MAC on here during full mesh operation
                # body_mac = 16 * (bytes.fromhex("00"))

                message = header + body + body_mac

            # send to remote
            # _logger.debug(f"Sending message {direction:<15s} | {len(message)}")
            await write_stream.send_all(message)

            # increment handshake counter
            i += 1
        except trio.BrokenResourceError:
            log("Remote closed the connection")
            return
        except Exception as e:
            log(f"Exception inside proxy.proxy\n{e}")
            return


async def handle_connection(inbound_stream, addr=None, proxy_connect=False):
    """Create the outbound connection to addr and proxy inbound and outbound streams.
    """
    global COUNTER
    # Get a new context var for the connection logs
    request_info.set(next(COUNTER))
    # Communicate to the proxy which stream is the connection initiator
    init_a = True if proxy_connect else False
    init_b = False if proxy_connect else True
    # Open the outbound connection
    outbound_stream = await trio.open_unix_socket(addr)
    log(f"Proxying connection between {inbound_stream} and {outbound_stream}")
    try:
        # We run the proxies in a nursery so they can run simultaneously
        async with trio.open_nursery() as nursery:
            nursery.start_soon(
                proxy_stream, outbound_stream, inbound_stream, init_a, True
            )
            nursery.start_soon(
                proxy_stream, inbound_stream, outbound_stream, init_b, False
            )
    except ValueError as e:
        log(f"Error from handle_connection():\n{e}")
    except trio.ClosedResourceError as e:
        log(f"Attempted to use resource after we closed:\n{e}")
    finally:
        await inbound_stream.aclose()
        await outbound_stream.aclose()


async def serve(listen_addr, outbound_addr, proxy_connect=False):
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
            functools.partial(
                handle_connection, addr=outbound_addr, proxy_connect=proxy_connect
            ),
            [trio.SocketListener(sock)],
        )
    except Exception as e:
        print(f"server error:\n{e}")
    finally:
        # Unlink the socket if it gets closed.
        await unlink_socket(listen_addr)
