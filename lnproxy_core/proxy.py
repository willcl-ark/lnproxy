import logging

import trio

from lnproxy_core import config, messages as msg, util

logger = util.CustomAdapter(logging.getLogger("proxy"), {})


class Proxy:
    """A proxy for a node.
    """

    def __init__(
        self, node, stream_init: bool, q_init: bool,
    ):
        self.node = node
        self.stream_init = stream_init
        self.q_init = q_init
        self.router = config.router
        self.count_to_remote = 0
        self.bytes_to_remote = 0
        self.bytes_from_remote = 0
        self.cancel_scope = trio.CancelScope()

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

        :param stream: SocketStream to read from.
        :param i: Which message number we are on.
        :param hs_acts: How many hs_acts we are expecting to do in this direction.
        :param initiator: Whether we initiated the connection.
        :param to_remote: If this is "to_remote" (we will try to batch if so).
        :param cancel_scope: A trio.CancelScope optionally used for batching timer
        :return: the message read from the SocketStream.
        """
        if i < hs_acts:
            message = await msg.HandshakeMessage.from_stream(stream, i, initiator)
            _direction = "Sent" if to_remote else "Rcvd"
            _c = 0
            if initiator and i == 0:
                _c = 1
            elif initiator and i == 1:
                _c = 3
            elif not initiator and i == 0:
                _c = 2
            logger.debug(f"{_direction} HS message {_c}")
            return bytes(message.message)
        else:
            if to_remote:
                message = await msg.LightningMessage.from_stream(
                    stream, to_remote, self.node.stream_c_lightning, cancel_scope
                )
            else:
                message = await msg.LightningMessage.from_stream(
                    stream, to_remote, self.node.stream_c_lightning, None
                )
            if await message.parse():
                return bytes(message.returned_msg)
            return b""

    async def _to_remote(self, read, write, initiator: bool):
        """Proxy between local node and remote node.
        Should not be called directly, instead use Proxy.start().

        :param read: Local node Unix SocketStream
        :param write: Remote node TCP SocketStream
        :param initiator: Whether we initiated this connection
        :return:
        """
        logger.debug(f"Starting proxy to_remote, initiator={initiator}")
        i = 0
        hs_acts = 2 if initiator else 1
        while True:
            message = bytearray()
            message += await self.read_message(read, i, hs_acts, initiator, True)
            i += 1
            # This if handles the case that we reflect a ping and don't want to count it
            if message:
                await write(message)
                self.bytes_to_remote += len(message)
                self.count_to_remote += 1
            logger.debug(
                f"SEND | "
                f"read: {i}, "
                f"sent: {self.count_to_remote}, "
                f"total_size: {self.bytes_to_remote}B"
            )

    async def _from_remote(self, read, write, init: bool):
        """Proxy between remote node and local node.
        Should not be called directly, instead use Proxy.start().

        :param read: Remote node TCP socket stream.
        :param write: Local node Unix socket stream.
        :param init: Whether we initiated this connection.
        :return:
        """
        logger.debug(f"Starting proxy from_remote, initiator={init}")
        i = 0
        hs_acts = 2 if init else 1
        while True:
            message = await self.read_message(read, i, hs_acts, init, False)
            i += 1
            # Handle ping as above
            if message:
                await write(message)
                self.bytes_from_remote += len(message)
            logger.debug(
                f"RECV | "
                f"read: {i}, "
                f"sent: {i}, "
                f"total_size: {self.bytes_from_remote}B"
            )

    async def start(self):
        logger.info(f"Proxying between C-Lightning and node: {str(self.node)}")
        # Use the GID as a contextvar for this proxy session
        util.gid_key.set(self.node.gid)

        # Proxy the connections
        with self.cancel_scope:
            async with trio.open_nursery() as nursery:
                nursery.start_soon(
                    self._to_remote,
                    self.node.stream_c_lightning,
                    self.node.stream_remote.send_all,
                    self.stream_init,
                )
                nursery.start_soon(
                    self._from_remote,
                    self.node.stream_remote,
                    self.node.stream_c_lightning.send_all,
                    self.q_init,
                )

    def stop(self):
        trio.from_thread.run_sync(self.cancel_scope.cancel)
