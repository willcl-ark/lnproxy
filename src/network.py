import logging
import pathlib
from random import randint

import trio

import src.config as config
from src.proxy import Proxy
from src.util import CustomAdapter

logger = CustomAdapter(logging.getLogger("network"), None)


class Node:
    """A Node in the routing table.

    """

    def __init__(
        self,
        gid: int,
        pubkey: str,
        port_remote=randint(49152, 65535),
        shared_key=None,
        listen=True,
    ):
        self.cancel_scope = None
        self.gid = gid
        self.header = self.gid.to_bytes(1, "big")
        self.inbound_connected = False
        self.listen_addr = None
        self.local_connected = False
        self.outbound = False
        self.outbound_count = 0
        if port_remote == 0:
            self.port_remote = randint(49152, 65535)
        else:
            self.port_remote = port_remote
        self.proxy = None
        self.pubkey = pubkey
        self.rpc = None
        self.shared_key = shared_key
        self.short_gid = gid % (256 * config.user.getint("message", "SEND_ID_LEN"))
        self.stream_c_lightning = None
        self.stream_remote = None
        # if listen:
        #     trio.from_thread.run_sync(
        #         config.nursery.start_soon, self.serve_inbound,
        #     )

    def __str__(self):
        return (
            f"GID: {self.gid}, pubkey: [{self.pubkey[:4]}...{self.pubkey[-4:]}], "
            f"tcp_port: {self.port_remote}"
        )

    def __repr__(self):
        return (
            f"{self.__class__.__name__}(gid={self.gid}, pubkey={self.pubkey}, "
            f"tcp_port{self.port_remote}, shared_key{self.shared_key})"
        )

    def __eq__(self, other):
        return self.gid == other.gid and self.pubkey == other.pubkey

    async def _handle_inbound(self, stream_remote: trio.SocketStream):
        """Handles an incoming TCP stream.
        Determines whether it's inbound or outbound based on if we are already connected
        locally to C-Lightning.

        :param stream_remote: the TCP connection stream passed in automatically
        :return: None
        """
        if self.inbound_connected:
            logger.info(
                f"Node {self.gid} already connected to from port {self.port_remote}"
            )
            await stream_remote.send_all(b"Already one connection to node.\n")
            return
        self.stream_remote = stream_remote
        self.inbound_connected = True
        logger.debug(f"Accepted TCP connection relating to node {self.gid}")

        # If outbound we just sleep forever here to prevent the socket from closing
        # while we wait for the local connection to be made
        if self.outbound:
            await trio.sleep_forever()

        # If not, then this is an inbound connection, so start handle_inbound()
        # for this node.
        else:
            logger.info(f"Handling new incoming connection from GID: {self.gid}")
            # First connect to our local C-Lightning node.
            self.stream_c_lightning = await trio.open_unix_socket(
                config.node_info["binding"][0]["socket"]
            )
            logger.info("Connection made to local C-Lightning node")
            # Next proxy between the queue and the node.
            # q_init is True because remote is handshake initiator.
            self.proxy = Proxy(self, stream_init=False, q_init=True)
            try:
                async with trio.open_nursery() as nursery:
                    nursery.start_soon(self.proxy.start)
            except:
                logger.exception("Exception in serve_node_tcp()")
            finally:
                with trio.move_on_after(2):
                    await self.stream_c_lightning.aclose()
                    await self.stream_remote.aclose()
                self.inbound_connected = False

    async def serve_inbound(self):
        """Listens on node.tcp_port for IPV4 connections and passes connections to
        handler.
        """
        await trio.serve_tcp(self._handle_inbound, self.port_remote)

    async def _handle_local(self, stream_c_lightning: trio.SocketStream):
        """Handles an outbound connection, creating the required queues if necessary
        and then proxying the connection with the queue.

        :param stream_c_lightning: The Unix SocketStream to (local) C-Lightning
        :param self: the node (network.Node) this relates to
        :return: None
        """
        logger.debug(
            f"Handling new outbound connection to GID {self.gid} on port {self.port_remote}"
        )
        self.local_connected = True

        # Check the Unix socket is listening, tell CL to connect in to it
        while not pathlib.Path(self.listen_addr).is_socket():
            await trio.sleep(0.2)
        self.rpc.connect(self.pubkey, self.listen_addr)
        # Assign the SocketStream to the node
        self.stream_c_lightning = stream_c_lightning

        # Next make outbound connection to remote port
        self.stream_remote = await trio.open_tcp_stream("127.0.0.1", self.port_remote)
        self.inbound_connected = True

        # Proxy the streams.
        # stream_init is True because we are handshake initiator.
        self.proxy = Proxy(self, stream_init=True, q_init=False)
        try:
            # await self.proxy.start()
            pass
        except:
            logger.exception(f"Exception in _handle_outbound() for node {self.gid}")
        finally:
            with trio.move_on_after(2):
                await self.stream_c_lightning.aclose()
                await self.stream_remote.aclose()
            # Cancel serve_local when we drop a connection
            self.cancel_scope.cancel()

    async def serve_local(self):
        """Serve a listening socket at listen_addr.
        Start a single handle_outbound for the first connection received to this socket.
        This will be run once per outbound connection made by C-Lightning (using rpc
        `proxy-connect`) so that each connection has it's own socket address.

        :param listen_addr: Unix Socket address
        :param self: the node (network.Node) this relates to
        :param task_status: Used to register with Trio when the task has "started"
        :return: None
        """
        # Setup the listening socket C-Lightning will connect to
        try:
            sock = trio.socket.socket(trio.socket.AF_UNIX, trio.socket.SOCK_STREAM)
            await sock.bind(self.listen_addr)
            sock.listen()
        except:
            logger.exception(
                f"Exception setting up listening unix socket for node {self.gid}"
            )
            return
        logger.debug(
            f"Listening for local connection from C-Lightning on {self.listen_addr}"
        )

        try:
            with trio.CancelScope() as self.cancel_scope:
                await trio.serve_listeners(
                    self._handle_local, [trio.SocketListener(sock)]
                )
        except:
            logger.exception("Exception in Node.serve_outbound()")
        finally:
            if self.cancel_scope.cancelled_caught:
                logger.info(f"serve_local for node {self.gid} cancelled")


class Router:
    """Holds the routing information for nodes.
    """

    def __init__(self):
        self.nodes = []
        self.by_pubkey = {}
        self.by_gid = {}
        self.by_short_gid = {}

    def __len__(self):
        return len(self.nodes)

    def __iter__(self):
        return iter(self.nodes)

    def __contains__(self, item):
        return item in self.by_gid or item in self.by_pubkey

    def __str__(self):
        return f"Router with {self.__len__()} Nodes:\n{self.nodes}"

    def add(self, node: Node):
        """Add a node to the Router and make some handy lookup dicts.
        """
        self.nodes.append(node)
        self.by_pubkey[str(node.pubkey)] = node
        self.by_gid[int(node.gid)] = node
        self.by_short_gid[node.short_gid] = node
        logger.info(f"Added node {node} to router.")

    def remove(self, gid: int):
        """Remove a node from the router by gid or pubkey.
        """
        for node in self.nodes:
            if node.gid == gid:
                self.nodes.remove(node)
                del self.by_gid[gid]
                del self.by_pubkey[node.pubkey]
                return
        raise LookupError(f"GID {gid} not found in Router")

    def get_pubkey(self, gid: int):
        """Returns pubkey of first GID matched in self.nodes.
        """
        try:
            return self.by_gid[int(gid)].pubkey
        except LookupError:
            print(self.by_gid)
            raise LookupError(f"GID {gid} not found in Router for lookup_pubkey.")

    def get_gid(self, pubkey: str):
        """Returns GID of first pubkey matched in self.nodes.
        """
        return self.by_pubkey[pubkey].gid

    def get_node(self, gid):
        """Returns the first node found in the router with matching GID.
        """
        return self.by_gid[gid]

    def cleanup(self, gid):
        self.by_gid[gid].outbound = None
        self.by_gid[gid].inbound = None
