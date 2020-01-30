import functools
import logging

import trio

import lnproxy.config as config
import lnproxy.messages as msg
import lnproxy.network as network
import lnproxy.util as util


logger = util.CustomAdapter(logging.getLogger(__name__), None)
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

    async def read_message(
        self, stream, i, hs_acts: int, initiator: bool, to_mesh: bool
    ) -> bytes:
        """A stream reader which reads a handshake or lightning message and returns it.
        """
        if i < hs_acts:
            message = await msg.HandshakeMessage.read(stream, i, initiator)
            return bytes(message.message)
        else:
            message = await msg.LightningMessage.read(stream, to_mesh, self.stream)
            if await message.parse():
                return bytes(message.header + message.body + message.body_mac)
            return b""

    async def _run_proxy(self, read, write, initiator: bool, to_mesh: bool):
        """Read from a SocketStream and write to a trio.MemorySendChannel
        (the mesh "queue") or a trio.SocketStream.
        Should not be called directly, instead use start().
        """
        logger.debug(f"Starting proxy(), initiator={initiator}")
        # There are 3 handshake messages in a lightning node opening handshake act:
        # Initiator 50B >> Recipient 50B >> Initiator 66B
        # Here we set a counter so that we know whether to expect to process a handshake
        # or lightning message.
        i = 0
        hs_acts = 2 if initiator else 1
        # Main proxy loop
        while True:
            message = await self.read_message(read, i, hs_acts, initiator, to_mesh)
            if message:
                if to_mesh:
                    for _msg in util.chunk_to_list(
                        message, 200, self.gid.to_bytes(8, "big")
                    ):
                        await write(_msg)
                else:
                    await write(message)
                i += 1

    async def start(self):
        logger.info(f"Proxying between local node and GID {self.gid}")
        # Use the GID as a contextvar for this proxy session
        util.gid_key.set(self.gid)
        try:
            async with trio.open_nursery() as nursery:
                nursery.start_soon(
                    self._run_proxy,
                    self.stream,
                    self.node.outbound.send,
                    self.stream_init,
                    True,
                )
                nursery.start_soon(
                    self._run_proxy,
                    self.node.inbound[1],
                    self.stream.send_all,
                    self.q_init,
                    False,
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
            logger.debug(f"Proxy for GID {self.gid} exited")


async def handle_inbound(gid: int, task_status=trio.TASK_STATUS_IGNORED):
    """Handle a new inbound connection from the mesh.
    Will open a new connection to local C-Lightning node and then proxy the connections.
    """
    logger.info(f"Handling new incoming connection from GID: {gid}")
    # TODO: is this accounted for?
    # Add it to the list of handle_inbounds running
    # First connect to our local C-Lightning node.
    stream = await trio.open_unix_socket(config.node_info["binding"][0]["socket"])
    logger.debug("Connection made to local C-Lightning node")
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
    logger.debug(f"serve_outbound for GID {gid} finished.")
