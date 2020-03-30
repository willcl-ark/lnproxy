import errno
import functools
import logging
from random import randint

import trio

import src.config as config
from src.proxy import handle_inbound
from src.util import CustomAdapter

logger = CustomAdapter(logging.getLogger("network"), None)

SLEEP_TIME = 0.100
# Errors that accept(2) can return, and which indicate that the system is
# overloaded
ACCEPT_CAPACITY_ERRNOS = {
    errno.EMFILE,
    errno.ENFILE,
    errno.ENOMEM,
    errno.ENOBUFS,
}


async def node_handle_tcp(stream_remote, node):
    """Handles an incoming TCP stream.
    Determines whether it's inbound or outbound based on if we are already connected
    locally to C-Lightning.

    :param stream_remote: the TCP connection stream passed in automatically
    :param node: the node this connection relates to
    :return: None
    """
    node.stream_remote = stream_remote
    node.tcp_connected = True
    logger.debug(f"Accepted TCP connection for node {node.gid}")

    # If we are already connected to C-Lightning, this is an outbound
    # connection, so just sleep forever to prevent the socket from closing.
    if node.stream_c_lightning:
        await trio.sleep_forever()
    # If not, then this is an inbound connection, so start handle_inbound()
    # for this node.
    else:
        await handle_inbound(node)


async def node_serve_tcp(node):
    """Listens on node.tcp_port for IPV4 connections and passes connections to handler.

    :param node: the node this tcp server relates to
    :return: None
    """
    try:
        async with trio.open_nursery() as nursery:
            nursery.start_soon(
                trio.serve_tcp,
                functools.partial(node_handle_tcp, node=node),
                node.tcp_port,
            )
    except Exception:
        logger.exception("Exception in serve_node_tcp()")


class Node:
    """A Node in the routing table.

    """

    def __init__(
        self,
        gid: int,
        pubkey: str,
        tcp_port=randint(49152, 65535),
        shared_key=None,
        listen=True,
    ):
        # gid and short_gid
        self.gid = gid
        # Short GID will be represented as GID modulo 256 * no. bytes allowed
        self.short_gid = gid % (256 * config.user.getint("message", "SEND_ID_LEN"))

        # Lightning pubkey
        self.pubkey = pubkey

        # Unique node message header is GID as Big Endian 8 bytestring
        self.header = self.gid.to_bytes(1, "big")

        # DH shared key for ourselves and this node
        self.shared_key = shared_key

        # Misc connection details
        self.stream_c_lightning = None
        self.stream_remote = None
        if tcp_port == 0:
            self.tcp_port = randint(49152, 65535)
        else:
            self.tcp_port = tcp_port
        self.outbound_count = 0
        self.tcp_connected = False
        # Whether we open a listening TCP port for the node. We won't for ourselves,
        # but will for all other added nodes
        if listen:
            trio.from_thread.run_sync(
                config.nursery.start_soon, node_serve_tcp, self,
            )

    def __str__(self):
        return (
            f"GID: {self.gid}, pubkey: [{self.pubkey[:4]}...{self.pubkey[-4:]}], "
            f"tcp_port: {self.tcp_port}"
        )

    def __repr__(self):
        return (
            f"{self.__class__.__name__}(gid={self.gid}, pubkey={self.pubkey}, "
            f"tcp_port{self.tcp_port}, shared_key{self.shared_key})"
        )

    def __eq__(self, other):
        return self.gid == other.gid and self.pubkey == other.pubkey


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

    async def add(self, node: Node):
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
