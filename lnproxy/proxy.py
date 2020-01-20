import functools
import logging

import trio

import lnproxy.config as config
import lnproxy.ln_msg as ln_msg
import lnproxy.util as util


logger = util.CustomAdapter(logging.getLogger(__name__), None)


async def send_queue_daemon():
    """Monitors all send queues in config.QUEUE splits messages to 200B length, appends
    header and puts messages in general mesh send queue.
    Should be run continuously in it's own thread/task.
    """
    logger.info("Started send_queue_daemon")
    while True:
        if len(config.QUEUE) == 0:
            # No connections yet
            await trio.sleep(0.1)
        else:
            # We can't modify a dictionary during iteration so cast to a list each time
            # and iterate over that.
            queues = list(config.QUEUE.items())
            # We have connections to check
            for pubkey in queues:
                try:
                    msg = pubkey[1]["outbound"][1].receive_nowait()
                except trio.WouldBlock:
                    await trio.sleep(0.1)
                except:
                    logger.exception("send_queue_daemon():")
                else:
                    # Message headers are first 4B of TO and FROM pubkeys
                    header = pubkey[0][0:4] + config.node_info["id"][0:4]
                    # Split it into 200B chunks and add header
                    msg_iter = util.chunk_to_list(msg, 200, bytes.fromhex(header))
                    # Add it to send_mesh memory_channel
                    for message in msg_iter:
                        await config.mesh_conn.send_mesh_send.send(message)


async def read_message(
    stream, i, hs_acts: int, initiator: bool, to_mesh: bool
) -> bytes:
    """A stream reader which reads a handshake or lightning message and returns it.
    """
    if i < hs_acts:
        message = await ln_msg.read_handshake_msg(stream, i, initiator)
    else:
        message = await ln_msg.read_lightning_msg(stream, to_mesh)
    return message


async def proxy(read: trio.SocketStream, write, initiator: bool, to_mesh: bool):
    """Read from a SocketStream and write to a trio.MemorySendChannel (the mesh "queue")
    or a trio.SocketStream.
    """
    logger.info(f"Starting proxy(), initiator={initiator}")
    i = 0
    # There are 3 handshake messages in a lightning node opening handshake act:
    # Initiator 50B >> Recipient 50B >> Initiator 66B
    # Here we set a counter so that we know whether to expect to process a handshake or
    # lightning message.
    hs_acts = 2 if initiator else 1
    while True:
        try:
            message = await read_message(read, i, hs_acts, initiator, to_mesh)
        except (trio.BusyResourceError, trio.Cancelled):
            pass
        except:
            logger.exception(f"proxy():")
        else:
            if type(write) == trio.MemorySendChannel:
                await write.send(message)
            elif type(write) == trio.SocketStream:
                await write.send_all(message)
            else:
                logger.warning(
                    f"Unexpected write stream type in stream_to_memory_channel()\n"
                    f"{type(write)}"
                )
            i += 1


async def proxy_nursery(stream, _pubkey: str, stream_init: bool, q_init: bool):
    """Helper that runs each proxy operation (pair) in it's own nursery.
    This means that an error with a single connection won't crash the whole program.
    """
    logger.info(f"Proxying between local node and {_pubkey}")

    async with trio.open_nursery() as nursery:
        nursery.start_soon(
            proxy, stream, config.QUEUE[_pubkey]["outbound"][0], stream_init, True
        )
        nursery.start_soon(
            proxy, config.QUEUE[_pubkey]["inbound"][1], stream, q_init, False
        )


async def handle_inbound(pubkey: str, task_status=trio.TASK_STATUS_IGNORED):
    """Handle a new inbound connection from the mesh.
    Will open a new connection to local C-Lightning node and then proxy the connections.
    """
    logger.info(f"Handling new incoming connection from pubkey: {pubkey}")
    util.pubkey_var.set(pubkey)
    # First connect to our local C-Lightning node.
    try:
        stream = await trio.open_unix_socket(config.node_info["binding"][0]["socket"])
    except:
        logger.exception("handle_inbound():")
    else:
        logger.info("Connection made to local C-Lightning node")
        # Report back to Trio that we've made the connection and are ready to receive
        task_status.started()
        # Next proxy between the queue and the socket.
        # q_init is True because remote is handshake initiator.
        await proxy_nursery(stream, pubkey, stream_init=False, q_init=True)


async def handle_outbound(stream: trio.SocketStream, pubkey: str):
    """Handles an outbound connection, creating the required (mesh) queues if necessary
    and then proxying the connection with the mesh queue.
    """
    util.pubkey_var.set(pubkey[0:4])
    _pubkey = pubkey[0:4]
    logger.info(f"Handling new outbound connection to pubkey: {_pubkey}")
    if _pubkey not in config.QUEUE:
        try:
            util.create_queue(_pubkey)
        except:
            logger.exception("util.create_queue():")
        # Next proxy between the queue and the socket.
        # stream_init is True because we are handshake initiator.
    try:
        await proxy_nursery(stream, _pubkey, stream_init=True, q_init=False)
    except:
        logger.exception("handle_outbound():")


async def serve_outbound(
    listen_addr, pubkey: str, task_status=trio.TASK_STATUS_IGNORED
):
    """Serve a listening socket at listen_addr.
    Start a single handle_outbound for the first connection received to this socket.
    This will be run once per outbound connection made by C-Lightning (using rpc
    `proxy-connect`) so that each connection has it's own socket address.
    """
    # Setup the listening socket.
    sock = trio.socket.socket(trio.socket.AF_UNIX, trio.socket.SOCK_STREAM)
    await sock.bind(listen_addr)
    sock.listen()
    logger.info(f"Listening for new outbound connection on {listen_addr}")
    # Report back to Trio that we've made the connection and are ready to receive
    task_status.started()
    # Start only a single handle_outbound for this connection.
    async with trio.open_nursery() as nursery:
        # noinspection PyProtectedMember
        await trio._highlevel_serve_listeners._serve_one_listener(
            trio.SocketListener(sock),
            nursery,
            functools.partial(handle_outbound, pubkey=pubkey),
        )
