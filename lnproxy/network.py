import itertools
import logging

import trio
import trio.testing

from lnproxy.util import CustomAdapter


logger = CustomAdapter(logging.getLogger(__name__), None)


class Node:
    """A Node in the routing table.
    """

    def __init__(self, gid: int, pubkey: str, nonce=None, outbound=None, inbound=None):
        self.gid = gid
        self.pubkey = pubkey
        self._nonce = nonce if nonce else itertools.count(0)
        self.outbound = outbound
        self.inbound = inbound
        # Node message header is GID as Big Endian 8 bytestring
        self.header = self.gid.to_bytes(8, "big")

    def __str__(self):
        return f"GID: {self.gid}, PUBKEY: {self.pubkey}"

    def __repr__(self):
        return (
            f"{self.__class__.__name__}({self.gid}, {self.pubkey}, {self.nonce}, "
            f"{self.outbound}, {self.inbound})"
        )

    def __eq__(self, other):
        return self.gid == other.gid and self.pubkey == other.pubkey

    @property
    def nonce(self):
        """Returns the current nonce value we are using for encrypted messages with this
         node.
        """
        return self._nonce.__next__()

    def init_queues(self):
        self._nonce = itertools.count()
        self.outbound = trio.open_memory_channel(50)
        self.inbound = trio.testing.memory_stream_one_way_pair()


class Router:
    """Holds the routing information for nodes.
    """

    def __init__(self):
        self.nodes = []
        self.by_pubkey = {}
        self.by_gid = {}

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

    def lookup_pubkey(self, gid: int):
        """Returns pubkey of first GID matched in self.nodes.
        """
        try:
            return self.by_gid[int(gid)].pubkey
        except LookupError:
            print(self.by_gid)
            raise LookupError(f"GID {gid} not found in Router for lookup_pubkey.")

    def lookup_gid(self, pubkey: str):
        """Returns GID of first pubkey matched in self.nodes.
        """
        try:
            return self.by_pubkey[pubkey].gid
        except LookupError:
            raise LookupError(f"Pubkey {pubkey} not found in Router for lookup_gid.")

    def get_node(self, gid):
        """Returns the first node found in the router with matching GID.
        """
        return self.by_gid[gid]

    def get_nonce(self, gid):
        for node in self.nodes:
            if node.gid == gid:
                return node.nonce
        raise LookupError(f"GID {gid} not found in Router for get_nonce.")

    def init_node(self, gid):
        for node in self.nodes:
            if node.gid == gid:
                node.init_queues()


router = Router()
