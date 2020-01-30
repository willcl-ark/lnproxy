import logging

import trio
import trio.testing

import lnproxy.config as config
from lnproxy.util import CustomAdapter


logger = CustomAdapter(logging.getLogger(__name__), None)


class Node:
    """A Node in the routing table.
    """

    def __init__(self, gid: int, pubkey: str, outbound=None, inbound=None):
        self.gid = gid
        self.pubkey = pubkey
        self.outbound = outbound
        self.inbound = inbound
        # Node message header is GID as Big Endian 8 bytestring
        self.header = self.gid.to_bytes(8, "big")

    def __str__(self):
        return f"GID: {self.gid}, PUBKEY: [{self.pubkey[:4]}...{self.pubkey[-4:]}]"

    def __repr__(self):
        return (
            f"{self.__class__.__name__}({self.gid}, {self.pubkey}, "
            f"{self.outbound}, {self.inbound})"
        )

    def __eq__(self, other):
        return self.gid == other.gid and self.pubkey == other.pubkey

    def init_queues(self):
        self.outbound = config.mesh_conn.to_mesh_send.clone()
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
        return self.by_pubkey[pubkey].gid

    def get_node(self, gid):
        """Returns the first node found in the router with matching GID.
        """
        return self.by_gid[gid]

    def init_node(self, gid):
        self.by_gid[gid].init_queues()

    def cleanup(self, gid):
        self.by_gid[gid].outbound = None
        self.by_gid[gid].inbound = None


router = Router()
