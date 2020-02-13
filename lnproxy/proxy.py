import functools
import logging

import trio

import lnproxy.config as config
import lnproxy.messages as msg
import lnproxy.network as network
import lnproxy.util as util


logger = util.CustomAdapter(logging.getLogger("proxy"), None)
router = network.router


class Proxy:
    """A proxy between a stream and a gid.
    """

    def __init__(self, stream, gid: int, stream_init: bool, q_init: bool):
        self.stream = stream
        self.gid = gid
        self.stream_init = stream_init
        self.q_init = q_init
        self.router = router
        self.node = router.get_node(gid)
        self.count_to_mesh = 0
        self.bytes_to_mesh = 0
        self.bytes_from_mesh = 0

    async def read_message(
        self,
        stream,
        i,
        hs_acts: int,
        initiator: bool,
        to_mesh: bool,
        cancel_scope=None,
    ) -> bytes:
        """A stream reader which reads a handshake or lightning message and returns it.
        """
        if i < hs_acts:
            message = await msg.HandshakeMessage.read(stream, i, initiator)
            logger.debug(f"Read HS message {i}")
            return bytes(message.message)
        else:
            if to_mesh:
                message = await msg.LightningMessage.from_stream(
                    stream, to_mesh, self.stream, cancel_scope
                )
            else:
                message = await msg.LightningMessage.from_stream(
                    stream, to_mesh, self.stream, None
                )
            if await message.parse():
                return bytes(message.returned_msg)
            return b""

    async def _to_mesh(self, read, write, initiator: bool):
        """Read from Local SocketStream and write to a MemoryStream.
        Will try to batch messages.
        Should not be called directly, instead use start().
        """
        logger.debug(f"Starting proxy to_mesh, initiator={initiator}")
        i = 0
        hs_acts = 2 if initiator else 1
        while True:
            message = bytearray()
            batched = 0

            # Read one message from the socket
            message += await self.read_message(read, i, hs_acts, initiator, True)
            i += 1

            # After we've got one, check to see if more can be batched
            with trio.move_on_after(config.user["gotenna"].getint("BATCH_DELAY")) as cs:
                while True:
                    message += await self.read_message(
                        read, i, hs_acts, initiator, True, cs
                    )
                    i += 1
                    batched += 1
            if batched:
                logger.info(f"Batched {batched + 1} messages")
            self.bytes_to_mesh += len(message)

            # Chunk the message and send them to the mesh
            for _msg in util.chunk_to_list(
                bytes(message),
                config.user["gotenna"].getint("CHUNK_SIZE"),
                self.gid.to_bytes(8, "big"),
            ):
                await write(_msg)
                self.count_to_mesh += 1
            logger.debug(
                f"Sent | "
                f"read: {i}, "
                f"sent: {self.count_to_mesh}, "
                f"total_size: {self.bytes_to_mesh}B"
            )

    async def _from_mesh(self, read, write, init: bool):
        """Read from a SocketStream and write to a trio.MemorySendChannel
        (the mesh "queue") or a trio.SocketStream.
        Should not be called directly, instead use start().
        """
        logger.debug(f"Starting proxy from_mesh, initiator={init}")
        i = 0
        hs_acts = 2 if init else 1
        while True:
            message = await self.read_message(read, i, hs_acts, init, False)
            await write(message)
            i += 1
            self.bytes_from_mesh += len(message)
            logger.debug(
                f"Rcvd | "
                f"read: {i}, "
                f"sent: {i}, "
                f"total_size: {self.bytes_from_mesh}B"
            )

    async def start(self):
        logger.info(f"Proxying between local node and GID {self.gid}")
        # Use the GID as a contextvar for this proxy session
        util.gid_key.set(self.gid)
        try:
            async with trio.open_nursery() as nursery:
                nursery.start_soon(
                    self._to_mesh,
                    self.stream,
                    self.node.outbound.send,
                    self.stream_init,
                )
                nursery.start_soon(
                    self._from_mesh,
                    self.node.inbound[1],
                    self.stream.send_all,
                    self.q_init,
                )
        except msg.UnknownMessage:
            logger.exception("Received an unknown message, closing connection")
        except Exception:
            logger.exception(f"Exception in proxy for GID {self.gid}")
            # cleanup after connection closed
        finally:
            router.cleanup(self.gid)
            with trio.fail_after(2):
                await self.stream.aclose()
            logger.warning(f"Proxy for GID {self.gid} exited")


async def handle_inbound(gid: int, task_status=trio.TASK_STATUS_IGNORED):
    """Handle a new inbound connection from the mesh.
    Will open a new connection to local C-Lightning node and then proxy the connections.
    """
    logger.info(f"Handling new incoming connection from GID: {gid}")
    # First connect to our local C-Lightning node.
    stream = await trio.open_unix_socket(config.node_info["binding"][0]["socket"])
    logger.info("Connection made to local C-Lightning node")
    # Report back to Trio that we've made the connection and are ready to receive
    task_status.started()
    # Next proxy between the queue and the node.
    # q_init is True because remote is handshake initiator.
    proxy = Proxy(stream, gid, False, True)
    await proxy.start()


async def handle_outbound(stream: trio.SocketStream, gid: int):
    """Handles an outbound connection, creating the required (mesh) queues if necessary
    and then proxying the connection with the mesh queue.
    """
    logger.info(f"Handling new outbound connection to GID: {gid}")
    # First we check if the node is in the router already:
    if gid not in router:
        logger.error(
            f"GID {gid} not found in network router, aborting. Please add Node"
            f"to router before trying to reconnect"
        )
        return
    # Next proxy between the stream and the node.
    # stream_init is True because we are handshake initiator.
    router.init_node(gid)
    proxy = Proxy(stream, gid, True, False)
    await proxy.start()


async def serve_outbound(listen_addr, gid: int, task_status=trio.TASK_STATUS_IGNORED):
    """Serve a listening socket at listen_addr.
    Start a single handle_outbound for the first connection received to this socket.
    This will be run once per outbound connection made by C-Lightning (using rpc
    `proxy-connect`) so that each connection has it's own socket address.
    """
    # Setup the listening socket.
    sock = trio.socket.socket(trio.socket.AF_UNIX, trio.socket.SOCK_STREAM)
    await sock.bind(listen_addr)
    sock.listen()
    logger.debug(f"Listening for new outbound connection on {listen_addr}")
    # Report back to Trio that we've made the connection and are ready to receive
    task_status.started()
    # Start only a single handle_outbound for this connection.
    # TODO: If we keep this open, will it allow re-connects?
    await trio.serve_listeners(
        functools.partial(handle_outbound, gid=gid),
        [trio.SocketListener(sock)],
        handler_nursery=None,
        task_status=trio.TASK_STATUS_IGNORED,
    )
    logger.info(f"serve_outbound for GID {gid} finished.")
