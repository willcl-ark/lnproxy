import logging

import trio

from lnproxy_core import config, proxy
from lnproxy_core.util import CustomAdapter

logger = CustomAdapter(logging.getLogger("network"), None)


class Node:
    """A Node in the routing table.
    """

    def __init__(
        self,
        gid: int,
        pubkey: str,
        remote_host=None,
        remote_port=None,
        inbound_port=None,
        shared_key=None,
        listen=True,
    ):
        self.gid = gid
        self.header = self.gid.to_bytes(1, "big")
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.inbound_port = inbound_port
        self.outbound_port = 0
        self.proxy = None
        self.pubkey = pubkey
        self.rpc = None
        self.shared_key = shared_key
        self.short_gid = gid % (256 * config.user.getint("message", "SEND_ID_LEN"))
        self.stream_c_lightning = None
        self.stream_remote = None
        if listen:
            trio.from_thread.run_sync(config.nursery.start_soon, self.serve_inbound)

    def __str__(self):
        return (
            f"GID: {self.gid}, pubkey: [{self.pubkey[:4]}...{self.pubkey[-4:]}], "
            f"listening port: {self.inbound_port}"
        )

    def __repr__(self):
        return (
            f"{self.__class__.__name__}(gid={self.gid}, pubkey={self.pubkey}, "
            f"port_listen={self.inbound_port}, shared_key={self.shared_key})"
        )

    def __eq__(self, other):
        return self.gid == other.gid and self.pubkey == other.pubkey

    async def cleanup(self):
        """Cleans up sockets and self.proxy after we finish.
        """
        # Try to close the sockets, but don't get hung up on it
        with trio.move_on_after(5):
            await self.stream_c_lightning.aclose()
            await self.stream_remote.aclose()
        self.proxy = None
        self.stream_remote = None
        logger.debug("Cleanup complete")

    async def _handle_inbound(self, stream_remote: trio.SocketStream):
        """Handles an incoming TCP stream.
        Determines whether it's inbound or outbound based on if we are already connected
        locally to C-Lightning.

        :param stream_remote: the TCP connection stream passed in automatically
        :return: None
        """
        if self.proxy:
            logger.warning(
                f"Node {self.gid} already connected to from port {self.inbound_port}"
            )
            await stream_remote.send_all(b"Already one proxy running to this node.\n")
            return
        self.stream_remote = stream_remote
        logger.info(f"Handling new incoming connection from GID: {self.gid}")

        # First connect to our local C-Lightning node.
        self.stream_c_lightning = await trio.open_unix_socket(
            config.node_info["binding"][0]["socket"]
        )
        logger.info(f"Connection made to local C-Lightning node for GID: {self.gid}")

        # Next proxy between the queue and the node.
        # q_init is True because remote is handshake initiator.
        self.proxy = proxy.Proxy(self, stream_init=False, q_init=True)
        try:
            await self.proxy.start()
        except trio.ClosedResourceError:
            logger.error(f"We closed the connection on node {self.gid}")
        except (Exception, trio.MultiError):
            logger.exception(f"Exception in serve_inbound() for {self.gid}")
        finally:
            await self.cleanup()

    async def serve_inbound(self):
        """Listens on node.port_remote for IPV4 connections and passes connections to
        handler.
        """
        await trio.serve_tcp(self._handle_inbound, self.inbound_port)

    async def _handle_outbound(self, stream_c_lightning: trio.SocketStream):
        """Handles an outbound connection, creating the required queues if necessary
        and then proxying the connection with the queue.

        :param stream_c_lightning: The Unix SocketStream to (local) C-Lightning
        :param self: the node (network.Node) this relates to
        :return: None
        """
        if self.proxy:
            logger.warning("Already handling a connection for this node")
            return
        logger.debug(
            f"Handling new outbound connection to GID {self.gid} on {self.remote_host}:{self.remote_port}"
        )
        # Assign the received SocketStream to this node
        self.stream_c_lightning = stream_c_lightning

        # Next make outbound connection to remote port, fail if we can't do this
        self.stream_remote = await trio.open_tcp_stream(
            self.remote_host, self.remote_port
        )

        # Proxy the streams.
        # stream_init is True because we are handshake initiator.
        self.proxy = proxy.Proxy(self, stream_init=True, q_init=False)
        try:
            await self.proxy.start()
        except trio.ClosedResourceError:
            logger.error(f"Remote peer of node {self.gid} closed the connection")
        except (Exception, trio.MultiError):
            logger.exception(f"Unhandled exception in handle_outbound() for {self.gid}")
        finally:
            await self.cleanup()

    async def serve_outbound(self):
        """Serve a listening socket at listen_addr.
        Start a single handle_outbound for the first connection received to this socket.
        This will be run once per outbound connection made by C-Lightning (using rpc
        `proxy-connect`) so that each connection has it's own socket address.
        """
        listeners = await trio.open_tcp_listeners(
            self.outbound_port, host="127.0.0.1", backlog=None
        )
        self.outbound_port = listeners[0].socket.getsockname()[1]
        logger.debug(
            f"Listening on 127.000.0.001:{self.outbound_port} for outbound connections to node {self.gid}"
        )
        await trio.sleep(0.2)

        # Tell C-Lightning RPC to call connect
        config.nursery.start_soon(
            trio.to_thread.run_sync,
            self.rpc.connect,
            f"{self.pubkey}@127.0.0.1:{self.outbound_port}",
        )
        # For each connection received at the socket, pass to self._handle_local()
        await trio.serve_listeners(self._handle_outbound, listeners)


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
                logger.info(f"Removed node {node} from router.")
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
