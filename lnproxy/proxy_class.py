import logging
import socket
import struct
import time

import trio


logging.basicConfig(level=logging.DEBUG)

MSG_LEN: int = 2
MSG_LEN_MAC: int = 16
MSG_HEADER: int = MSG_LEN + MSG_LEN_MAC
MSG_MAC: int = 16


class Proxy:
    def __init__(self):
        self.logger = logging.getLogger(f"{'PROXY':<6s}")
        self.lightning_listen_sock = ""
        self.outbound_sock_addr = ""
        self.listen_for_incoming = False

    @staticmethod
    async def unlink_socket(sock):
        """Unlink a Unix Socket
        """
        socket_path = trio.Path(sock)
        try:
            await socket_path.unlink()
        except OSError:
            if await socket_path.exists():
                raise

    async def receive_exactly(self, stream, length, timeout=500):
        res = b""
        end = time.time() + timeout
        while len(res) < length and time.time() < end:
            res += await stream.receive_some(length - len(res))
        if len(res) == length:
            self.logger.debug(res)
            return res
        else:
            raise TimeoutError(
                "Didn't receive enough bytes within the timeout, discarding"
            )

    async def proxy(self, read_stream, write_stream):
        """Proxy message traffic from one stream to another.
        Handle and parse certain lightning messages.
        """
        self.logger.debug(f"starting proxy between {read_stream} and {write_stream}")
        while True:
            try:
                data = await read_stream.receive_some()
                # self.logger.debug(f"Got data: {data}")
                await write_stream.send_all(data)
            except TimeoutError:
                break
            except Exception:
                self.logger.exception(f"Exception inside proxy.proxy")
                break

    async def handle_listeners(self, inbound_stream):
        """Handles a listening socket for C-Lightning.
        If self.listen_for_incoming is True, then we are starting a server to receive
        arbitrary incoming connections from remote nodes.
        If self.listen_for_incoming is False, then we are starting a listener for
        C-Lightning to connect _out_ via.

        :arg inbound_stream: a trio.SocketStream for the listening socket
        """
        self.logger.debug(f"starting a socket handler")

        # remote inbound connections, connect in to C-Lightning
        if self.listen_for_incoming:
            addr = self.lightning_listen_sock
        # outbound connection from C-Lightning, make the outbound connection to remote
        else:
            addr = self.outbound_sock_addr
            # delete the attr ref to outbound sock addr to avoid future sync mishaps
            self.outbound_sock_addr = ""

        # open a connection to the other stream
        outbound_stream = await trio.open_unix_socket(addr)
        self.logger.debug(f"opened a connection to address {addr}")
        try:
            async with trio.open_nursery() as nursery:
                nursery.start_soon(self.proxy, outbound_stream, inbound_stream)
                nursery.start_soon(self.proxy, inbound_stream, outbound_stream)
        except Exception:
            self.logger.exception(f"Local socket_handler: crashed")
        finally:
            # try to close the listening server
            await inbound_stream.aclose()

    async def serve_unix_socket(self, listen_addr):
        """Serve a listening unix socket on 'listen_addr'
        Handles the socket using socket_handler
        """
        self.logger.debug(f"serving unix socket with at address: {listen_addr}")
        # unlink the socket in case it's busy
        await self.unlink_socket(listen_addr)
        listeners = []

        # Create the listening socket, bind to it and listen
        sock = trio.socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        await sock.bind(listen_addr)
        sock.listen()
        listeners.append(trio.SocketListener(sock))
        self.logger.debug(f"Opened a listening socket")

        try:
            # Manage the listening with the handler
            await trio.serve_listeners(self.handle_listeners, listeners)
        except Exception:
            self.logger.exception("serve_unix_socket: crashed")
        finally:
            # try to unlink the socket if it gets closed by remote
            await self.unlink_socket(listen_addr)
