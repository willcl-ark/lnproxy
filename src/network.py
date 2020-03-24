import logging
import queue

import trio
import trio.testing

import src.config as config
import src.proxy as proxy
from src.util import CustomAdapter

logger = CustomAdapter(logging.getLogger("network"), None)


class Node:
    """A Node in the routing table.
    """

    def __init__(
        self, gid: int, pubkey: str, shared_key=None, sync_connection=False,
    ):
        # gid and short_gid
        self.gid = gid
        # Short GID will be represented as GID modulo 256 * no. bytes allowed
        self.short_gid = gid % (256 * config.user.getint("message", "SEND_ID_LEN"))

        # Lightning pubkey
        self.pubkey = pubkey

        # Node's send/recv streams and queues
        self.outbound_send, self.outbound_recv = trio.open_memory_channel(50)
        self.inbound_send, self.inbound_recv = trio.testing.memory_stream_one_way_pair()
        self.outbound_queue = queue.Queue()
        self.inbound_queue = queue.Queue()

        # Unique node message header is GID as Big Endian 8 bytestring
        self.header = self.gid.to_bytes(1, "big")

        # DH shared key for ourselves and this node
        self.shared_key = shared_key

        # Misc connection details
        self.sync_connection = sync_connection
        self.outbound_count = 0

        if sync_connection:
            trio.from_thread.run_sync(config.nursery.start_soon, self.patch_to_queue)

    def __str__(self):
        return f"GID: {self.gid}, PUBKEY: [{self.pubkey[:4]}...{self.pubkey[-4:]}]"

    def __repr__(self):
        return (
            f"{self.__class__.__name__}"
            f"("
            f"{self.gid}, "
            f"{self.pubkey}, "
            f"sync_connection={self.sync_connection}"
            f")"
        )

    def __eq__(self, other):
        return self.gid == other.gid and self.pubkey == other.pubkey

    async def _patch_inbound(self, nursery):
        """Patches inbound messages from the queue to a MemoryChannel.
        """
        logger.debug("Starting patch_inbound")
        while True:
            try:
                msg = self.inbound_queue.get_nowait()
            except queue.Empty:
                await trio.sleep(1)
                continue
            # If we've not sent an outbound message before, this must be a new inbound
            if self.outbound_count == 0:
                # Therefore setup a new Proxy via handle_inbound
                nursery.start_soon(proxy.handle_inbound, self.gid)
            await self.inbound_send.send_all(bytes.fromhex(msg))

    async def _patch_outbound(self):
        """Patches outbound messages from the MemoryStream to a queue"""
        logger.debug("Starting patch_outbound")
        while True:
            msg = await self.outbound_recv.receive()
            self.outbound_queue.put(msg.hex())
            # We also print to the terminal for manual copy/paste
            logger.info(f"Send message to node {self.gid}:\n{msg.hex()}")
            self.outbound_count += 1

    async def patch_to_queue(self):
        # In the case our transport connection prefers synchronous queues
        logger.debug(f"Patching node {self.gid}'s streams to queues...")
        try:
            async with trio.open_nursery() as nursery:
                nursery.start_soon(self._patch_inbound, nursery)
                nursery.start_soon(self._patch_outbound)
                logger.debug(f"Node {self.gid}'s stream patching complete")
        except trio.MultiError:
            logger.exception("Exception in patch_to_queue")
        except Exception:
            logger.exception("Unhandled exception in patch_to_queue")


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
