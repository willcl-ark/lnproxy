import functools
import logging

import trio

import src.config as config
import src.messages as msg
import src.util as util

logger = util.CustomAdapter(logging.getLogger("proxy"), None)


class Proxy:
    """A proxy between a stream (from C-Lightning) and a node.
    """

    def __init__(self, stream, node, stream_init: bool, q_init: bool):
        self.stream = stream
        self.node = node
        self.stream_init = stream_init
        self.q_init = q_init
        self.router = config.router
        self.count_to_remote = 0
        self.bytes_to_remote = 0
        self.bytes_from_remote = 0

    async def read_message(
        self,
        stream,
        i,
        hs_acts: int,
        initiator: bool,
        to_remote: bool,
        cancel_scope=None,
    ) -> bytes:
        """A stream reader which reads a handshake or lightning message parses it and
        returns it.
        """
        if i < hs_acts:
            message = await msg.HandshakeMessage.from_stream(stream, i, initiator)
            logger.debug(f"Read HS message {i}")
            return bytes(message.message)
        else:
            if to_remote:
                message = await msg.LightningMessage.from_stream(
                    stream, to_remote, self.stream, cancel_scope
                )
            else:
                message = await msg.LightningMessage.from_stream(
                    stream, to_remote, self.stream, None
                )
            if await message.parse():
                return bytes(message.returned_msg)
            return b""

    async def _to_remote(self, read, write, initiator: bool):
        """Read from Local SocketStream and write to the node's outbound_send
        MemoryStream.

        * Will automatically try to batch messages according to the BATCH_DELAY found in
        config.ini.

        * Should not be called directly, instead use Proxy.start().
        """
        logger.debug(f"Starting proxy to_remote, initiator={initiator}")
        i = 0
        hs_acts = 2 if initiator else 1
        while True:
            message = bytearray()
            batched = 0

            # Read one message from the socket
            message += await self.read_message(read, i, hs_acts, initiator, True)
            i += 1

            # After we've got one, check to see if more can be batched
            with trio.move_on_after(config.user["message"].getint("BATCH_DELAY")) as cs:
                while True:
                    message += await self.read_message(
                        read, i, hs_acts, initiator, True, cs
                    )
                    i += 1
                    logger.debug(f"Read message: {message.hex()}")
                    batched += 1
            if batched:
                logger.info(f"Batched {batched + 1} messages")
            self.bytes_to_remote += len(message)

            # Chunk the message
            for _msg in util.chunk_to_list(
                bytes(message), config.user["message"].getint("CHUNK_SIZE"),
            ):
                await write(_msg)
                self.count_to_remote += 1
            logger.debug(
                f"Sent | "
                f"read: {i}, "
                f"sent: {self.count_to_remote}, "
                f"total_size: {self.bytes_to_remote}B"
            )

    async def _from_remote(self, read, write, init: bool):
        """Read from a SocketStream and write to a trio.MemorySendChannel
        (the receive "queue") or a trio.SocketStream.
        Should not be called directly, instead use Proxy.start().
        """
        logger.debug(f"Starting proxy from_remote, initiator={init}")
        i = 0
        hs_acts = 2 if init else 1
        while True:
            message = await self.read_message(read, i, hs_acts, init, False)
            await write(message)
            i += 1
            self.bytes_from_remote += len(message)
            logger.debug(
                f"Rcvd | "
                f"read: {i}, "
                f"sent: {i}, "
                f"total_size: {self.bytes_from_remote}B"
            )

    async def start(self):
        logger.info(f"Proxying between local node and GID {self.node.gid}")
        # Use the GID as a contextvar for this proxy session
        util.gid_key.set(self.node.gid)
        try:
            async with trio.open_nursery() as nursery:
                nursery.start_soon(
                    self._to_remote,
                    self.stream,
                    self.node.outbound_send.send,
                    self.stream_init,
                )
                nursery.start_soon(
                    self._from_remote,
                    self.node.inbound_recv,
                    self.stream.send_all,
                    self.q_init,
                )
        except msg.UnknownMessage:
            logger.exception("Received an unknown message, closing connection")
        except trio.MultiError:
            logger.exception(f"Exception in Proxy.start() for node: {self.node.gid}")
        except Exception:
            logger.exception(
                f"Unhandled exception in Proxy.start() for node {self.node.gid}"
            )
            # cleanup after connection closed
        finally:
            config.router.cleanup(self.node.gid)
            with trio.fail_after(2):
                await self.stream.aclose()
            logger.warning(f"Proxy for GID {self.node.gid} exited")


async def check_node_gid(gid):
    # Check if the node is in the router already:
    if gid not in config.router:
        logger.error(
            f"GID {gid} not found in network router, aborting. Please add Node"
            f"to router before trying to reconnect"
        )
        return
    # Get the node for this connection
    return config.router.get_node(gid)


async def handle_inbound(gid: int, task_status=trio.TASK_STATUS_IGNORED):
    """Handle a new inbound connection.
    Will open a new connection to local C-Lightning node and then proxy with the queue.
    """
    node = await check_node_gid(gid)
    logger.info(f"Handling new incoming connection from GID: {node.gid}")
    # First connect to our local C-Lightning node.
    stream = await trio.open_unix_socket(config.node_info["binding"][0]["socket"])
    logger.info("Connection made to local C-Lightning node")
    # Report back to Trio that we've made the connection and are ready to receive
    task_status.started()
    # Next proxy between the queue and the node.
    # q_init is True because remote is handshake initiator.
    proxy = Proxy(stream, node, stream_init=False, q_init=True)
    await proxy.start()


async def handle_outbound(stream: trio.SocketStream, node):
    """Handles an outbound connection, creating the required queues if necessary
    and then proxying the connection with the queue.
    """
    logger.info(f"Handling new outbound connection to GID: {node.gid}")
    # Proxy between the stream and the node.
    # stream_init is True because we are handshake initiator.
    proxy = Proxy(stream, node, stream_init=True, q_init=False)
    await proxy.start()


async def serve_outbound(listen_addr, gid: int, task_status=trio.TASK_STATUS_IGNORED):
    """Serve a listening socket at listen_addr.
    Start a single handle_outbound for the first connection received to this socket.
    This will be run once per outbound connection made by C-Lightning (using rpc
    `proxy-connect`) so that each connection has it's own socket address.
    """
    # Get the node from the router
    node = await check_node_gid(gid)
    # Setup the listening socket.
    sock = trio.socket.socket(trio.socket.AF_UNIX, trio.socket.SOCK_STREAM)
    await sock.bind(listen_addr)
    sock.listen()
    logger.debug(f"Listening for new outbound connection on {listen_addr}")
    # Report back to Trio that we've made the connection and are ready to receive
    # This releases the block of the calling function
    task_status.started()
    # Start only a single handle_outbound for this connection.
    # TODO: If we keep this open, will it allow re-connects?
    await trio.serve_listeners(
        functools.partial(handle_outbound, node=node),
        [trio.SocketListener(sock)],
        handler_nursery=None,
        # task_status=trio.TASK_STATUS_IGNORED,
    )
    logger.info(f"serve_outbound for GID {node.gid} finished.")
