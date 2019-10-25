import asyncio
import logging
import os


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("PRXSRV")
logging.getLogger("asyncio").setLevel(logging.WARNING)


SRV_SOCK = "/tmp/proxy_sock"
# CLIENT_SOCK = "/tmp/l2-regtest/unix_socket"
CLIENT_SOCK = "/tmp/server_sock"
RECV_BUF = 210


def unlink_socket():
    """Unlink SRV_SOCK Unix Socket
    """
    try:
        os.unlink(SRV_SOCK)
    except OSError:
        if os.path.exists(SRV_SOCK):
            raise


async def proxy(reader, writer):
    """Proxy traffic from one asyncio.StreamReader to an asyncio.StreamWriter
    """
    logger.debug(f"Proxy started")
    while True:
        try:
            data = await reader.read(RECV_BUF)
            if not data:
                break
            logger.debug(f"Read {len(data)}B data")
            writer.write(data)
            await writer.drain()
            logger.debug(f"Written {len(data)}B data")
        except:
            raise


async def unix_client(socket):
    """Connect out to a local Unix Socket
    """
    reader, writer = await asyncio.open_unix_connection(socket)
    logger.debug(f"Client connected to {socket}")
    return reader, writer


async def server_handler(server_reader, server_writer):
    """For a new inbound connection (stream), make a new outbound connection.
    Proxy the Read and Write streams.
    """
    client_reader, client_writer = await unix_client(CLIENT_SOCK)
    while True:
        await asyncio.gather(
                await proxy(server_reader, client_writer),
                await proxy(client_reader, server_writer)
        )


async def unix_server(handler, socket):
    """Start a socket server with a local Unix Socket
    """
    server = await asyncio.start_unix_server(handler, socket)
    addr = server.sockets[0].getsockname()
    logger.debug(f"Server listening on {addr}")
    async with server:
        await server.serve_forever()


async def main():
    """Unlink old socket and run the server and client in the loop
    """
    unlink_socket()
    await unix_server(server_handler, SRV_SOCK)


asyncio.run(main())
