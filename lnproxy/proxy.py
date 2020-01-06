import functools
import trio

import lnproxy.config as config
import lnproxy.ln_msg as ln_msg
import lnproxy.util as util


log = config.log


async def queue_to_stream(queue, stream, initiator: bool):
    """Read from a queue and write to a stream
    Will handle lightning message parsing for inbound messages.
    Will put the messages from the queue into a one-way memory stream
    """
    i = 0
    hs_acts = 2 if initiator else 1
    send_stream, recv_stream = trio.testing.memory_stream_one_way_pair()

    async def q_2_stream(_queue, _stream):
        """Sends to a temporary stream so that we can retrieve it by num bytes with
        the parser.
        """
        try:
            while True:
                if _queue.empty():
                    await trio.sleep(5)
                else:
                    log("q_2_stream: got message in queue")
                    msg = _queue.get()
                    await _stream.send_all(msg)
                    log("Sent from queue to memory_stream_pair: send")
        except Exception as e:
            log(f"q_2_stream: {e}", level="error")

    async def parse_stream(read_stream, write_stream, _i, _initiator: bool):
        """A parser which sits in-between two streams and decodes the lightning messages
        """
        try:
            while True:
                if _i < hs_acts:
                    log(f"parse_stream: HS message {_i}", level="debug")
                    message = await ln_msg.handshake(read_stream, _i, _initiator)
                else:
                    log(f"parse_stream: lightning message {_i}", level="debug")
                    message = await ln_msg.read_lightning_message(read_stream)
                await write_stream.send_all(message)
                log(f"parse_stream: written message to write_stream")
                _i += 1
        except Exception as e:
            log(f"parse_stream: {e}", level="error")

    async with trio.open_nursery() as nursery:
        try:
            nursery.start_soon(q_2_stream, queue, send_stream)
            nursery.start_soon(parse_stream, recv_stream, stream, i, initiator)
        except Exception as e:
            log(f"parse_stream: {e}", level="error")


async def stream_to_queue(stream, queue, initiator: bool):
    """Read from a stream and write to a queue.
    Will handle lightning message parsing for outbound messages.
    """
    log(f"Starting stream_to_queue, initiator={initiator}")
    i = 0
    hs_acts = 2 if initiator else 1
    try:
        while True:
            if i < hs_acts:
                log(f"stream_to_queue: HS message {i}", level="debug")
                message = await ln_msg.handshake(stream, i, initiator)
            else:
                log(f"stream_to_queue: lightning message {i}", level="debug")
                message = await ln_msg.read_lightning_message(stream)
            queue.put(message)
            log("stream_to_queue: put message onto queue")
            i += 1
    except Exception as e:
        log(f"stream_to_queue: {e}", level="error")


async def proxy_streams(stream, _pubkey: str, stream_init: bool, q_init: bool):
    log(f"Proxying between stream and queue {_pubkey}")
    try:
        async with trio.open_nursery() as nursery:
            nursery.start_soon(
                stream_to_queue, stream, config.QUEUE[_pubkey]["to_send"], stream_init
            )
            nursery.start_soon(
                queue_to_stream, config.QUEUE[_pubkey]["recvd"], stream, q_init
            )
    except trio.ClosedResourceError as e:
        log(f"Attempted to use resource after we closed:\n{e}", level="error")
    except Exception as e:
        config.log(f"proxy_streams: {e}", level="error")
    finally:
        await stream.aclose()


async def handle_inbound(_pubkey):
    try:
        log(f"Handling new incoming connection from pubkey: {_pubkey}")
        # first connect to our local C-Lightning node.
        stream = await trio.open_unix_socket(config.node_info["binding"][0]["socket"])
        log("Connection made to local C-Lightning node")
        # next proxy between the queue and the socket.
        await proxy_streams(stream, _pubkey, stream_init=False, q_init=True)
    except Exception as e:
        print(f"handle_outbound: {e}")


async def handle_outbound(stream, pubkey: str):
    """Started for each outbound connection.
    """
    try:
        _pubkey = pubkey[0:4]
        log(f"Handling new outbound connection to {_pubkey}")
        if pubkey not in config.QUEUE:
            util.create_queue(_pubkey)
            log(f"Created mesh queue for {_pubkey}")
        await proxy_streams(stream, _pubkey, stream_init=True, q_init=False)
    except Exception as e:
        print(f"handle_outbound: {e}")


async def serve_outbound(listen_addr, pubkey: str):
    """Serve a listening socket at listen_addr.
    Start a handler for each new connection.
    """
    # Setup the listening socket.
    sock = trio.socket.socket(trio.socket.AF_UNIX, trio.socket.SOCK_STREAM)
    await sock.bind(listen_addr)
    sock.listen()
    log(f"Listening for new outbound connection on {listen_addr}")
    # Start a single handle_outbound for each connection.
    try:
        async with trio.open_nursery() as nursery:
            nursery.start_soon(
                trio._highlevel_serve_listeners._serve_one_listener,
                trio.SocketListener(sock),
                nursery,
                functools.partial(handle_outbound, pubkey=pubkey),
            )
    except Exception as e:
        log(f"proxy.serve_outbound error:\n{e}", level="error")
