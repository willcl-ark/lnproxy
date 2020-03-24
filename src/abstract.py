from abc import ABC, abstractmethod

import trio

import src.config as config
import src.proxy as proxy


async def transport_comm_daemon():
    """An example transport_comm_daemon function.
    This function will be called by the primary plugin module with no arguments.
    It should initialise an instance of the Connection class (below) which will live for
    the life of the plugin.
    It will store the Connection object in the global `config.connection` variable.
    """
    # Wait for node info to populate.
    i = 0
    while config.node_info is None:
        if i > 5:
            print("Waiting for node info in config.node_info")
        await trio.sleep(0.25)
        i += 1
    print("Got node info, starting connection")
    # start the connection daemon and run forever
    async with trio.open_nursery() as nursery:
        config.connection = Connection(nursery=nursery, router=config.router)
        print("connection_daemon started successfully")
        await trio.sleep_forever()


class Message:
    def __init__(self, text: str, from_gid: int):
        self.text: str = text
        self.from_gid: int = from_gid


class Connection(ABC):

    """This connection class should be sub-classed.
    :arg: router: the global instance of lnproxy.network.Router.
    :arg: nursery: the shared trio.Nursery as instantiated by the connection_daemon()
                   who spawns this Connection object (see above).

    To provide the Channel interface, a send/receive pair of objects should be opened
    using `send, recv = trio.open_memory_channel(50)`, where the `send` channel gets
    passed in as the `to_remote_send` parameter of this class
    """

    def __init__(self, nursery, router=config.router):
        self.router = router
        self.gid = self.router.get_gid(config.node_info["id"])
        self.nursery = nursery
        self.to_remote_send, self.to_remote_recv = trio.open_memory_channel(50)
        self.from_remote_send, self.from_remote_recv = trio.open_memory_channel(50)
        super().__init__()

    @abstractmethod
    async def send(self, to_gid, msg):
        """Send a message to a GID
        """
        pass

    async def lookup_and_send(self, msg):
        """Extract GID from the message header, then send it to that GID using `send()`
        """
        _to_gid = int.from_bytes(msg[:8], "big")
        await self.send(_to_gid, msg[8:])

    async def send_handler(self):
        """Monitor the `to_remote` send queue for messages we should send using our
        transport.
        """
        async for msg in self.to_remote_recv:
            await self.lookup_and_send(msg)
            await trio.sleep(1)

    @staticmethod
    async def new_inbound(node, from_gid, task_status=trio.TASK_STATUS_IGNORED):
        """Starts a new inbound proxy for the new connection.
        """
        node.init_queues()
        # Report back to trio that the node is activated
        task_status.started()
        async with trio.open_nursery() as nursery:
            # Start the proxy in it's own nursery.
            await nursery.start(proxy.handle_inbound, from_gid)

    async def parse_recv_msg(self, msg: Message):
        """Parse a received message.
        If a node does not exist for this pubkey, then it should create the node in the
        router and init the various queues.
        It will also start a new `handle_inbound` (in the main nursery) which will
        monitor this node.
        Puts the received message in the correct queue (stream) with header stripped.
        """
        # check if we already have a handle_inbound running, if so continue
        try:
            node = self.router.get_node(msg.from_gid)
        except LookupError:
            print(f"Node {msg.from_gid} not found in router")
            # Create the new node in the router automagically here potentially?
            # Might be tough as node won't send a special first packet with
            # GID:lightning pubkey pair currently...
            raise
        except Exception as e:
            print(f"Exception getting node: {e}")
            raise
        else:
            # If the node is not activated, activate it
            if (node.outbound or node.inbound) is None:
                await self.nursery.start(self.new_inbound, node, msg.from_gid)
            # Send the message to the send side of the inbound channel
            try:
                await node.inbound[0].send_all(msg)
            except Exception as e:
                print(f"Exception in await node.inbound[0].send_all(msg):\n {e}")
                raise

    async def recv_handler(self):
        """Handles received messages.
        Messages added to the `from_remote_send` side of the channel must include sender
        GID for later processing into the correct node.
        I have included a sample class `Message` of how this could be implemented.
        """
        async for msg in self.from_remote_recv:
            await self.parse_recv_msg(msg)
