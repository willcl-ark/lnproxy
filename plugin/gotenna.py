#!/usr/bin/env python3
import logging
import time
import uuid
import hashlib
import pathlib

import lnproxy.crypto as crypto
import trio
import lightning

import lnproxy.config as config
import lnproxy.mesh_connection as mesh
import lnproxy.pk_from_hsm as pk_from_hsm
import lnproxy.proxy as proxy
import lnproxy.util as util


gotenna_plugin = lightning.Plugin()
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("plugin")


@gotenna_plugin.method("proxy-connect")
def proxy_connect(gid, plugin=None):
    """Connect to a remote node via goTenna mesh proxy.
    """
    logging.info(f"proxy-connect to gid {gid} via goTenna mesh connection")
    # Generate a random fd to listen on for this outbound connection.
    listen_addr = f"/tmp/0{uuid.uuid1().hex}"
    # Setup the listening server for C-Lightning to connect through, started in the
    # main shared nursery.
    trio.from_thread.run(
        config.nursery.start, proxy.serve_outbound, f"{listen_addr}", gid
    )
    # Confirm the socket is created and listening.
    while not pathlib.Path(listen_addr).is_socket():
        time.sleep(0.1)
    # Instruct C-Lightning RPC to connect to remote via the socket after it has been
    # established.
    pubkey = util.get_pk_from_router(gid)
    return plugin.rpc.connect(str(pubkey), f"{listen_addr}")


@gotenna_plugin.method("message")
def message(
    gid, message_string, plugin=None,
):
    """sendpay via the mesh connection using key-send (non-interactive)
    args: (goTenna) gid, msatoshi, [label]
    """
    # We will use 100 satoshis as base payment amount
    msatoshi = 100_000

    # Lookup the dest_pubkey from our routing table
    dest_pubkey = util.get_pk_from_router(gid)
    logger.info(f"Message to {dest_pubkey}. Body: {message_string}")
    if not dest_pubkey:
        return 1

    # Create a pseudo-random description to satisfy C-Lightning's accounting system
    description = f"{uuid.uuid1().hex} encrypted message to {dest_pubkey}"

    # Generate the preimage for the payment: sha256(decrypted_message).
    # If you can decrypt the message, you can generate the preimage.
    preimage = hashlib.sha256(message_string.encode())
    logger.info(f"Preimage set as {preimage.hexdigest()}")

    # Generate payment_hash from the preimage
    payment_hash = hashlib.sha256(preimage.digest())
    logger.info(f"payment_hash set as {payment_hash.hexdigest()}")

    # Next retrieve the next nonce to use for encryption
    nonce = config.nodes[gid]["nonce"].__next__().to_bytes(16, "big")

    # Encrypt the message using recipient lightning node_id (pubkey)
    encrypted_msg = crypto.encrypt(dest_pubkey, message_string.encode(), nonce)
    logger.info(f"Encrypted message:\n{encrypted_msg.hex()}")

    # Store preimage and encrypted message for later (as bytes).
    # We will add the encrypted message onto the outbound htlc_add_update message
    config.key_sends[payment_hash.digest()] = {
        "preimage": preimage.digest(),
        "encrypted_msg": encrypted_msg,
    }
    logger.info(
        f"Stored preimage and encrypted message in "
        f"config.key_sends[{payment_hash.digest()}]"
    )

    # Get next peer in route
    peer = config.rpc.listfunds()["channels"][0]["peer_id"]
    logger.info(f"Got next peer {peer}")

    # we add 10 satoshis to amount (10 hops max x 1 satoshi fee each)
    # we add 60 to cltv (10 hops max, CLTV of 6 each)
    amt_msat = msatoshi + 10
    cltv = 9 + 60

    route = config.rpc.getroute(peer, msatoshi=amt_msat, riskfactor=10, cltv=cltv)[
        "route"
    ]
    logger.info(f"Got route to {peer}, executing sendpay command.")

    return config.rpc.sendpay(route, payment_hash.hexdigest(), description, amt_msat)


@gotenna_plugin.init()
# Unused parameters used by lightning.plugin() internally
def init(options, configuration, plugin):
    logger.info("Starting plugin")
    # Store the RPC in config to be accessible by all.
    config.rpc = plugin.rpc
    # Get the local lightning node info.
    config.node_info = plugin.rpc.getinfo()
    logger.info(config.node_info)
    # ======= WARNING =======
    # Store our node private key for message decryption
    config.node_secret_key = str(
        pk_from_hsm.get_privkey(config.node_info["lightning-dir"])
    )
    logger.info(f"Node private key: {config.node_secret_key}")
    # ===== END WARNING =====
    util.write_pubkey_to_file()
    # Hack to get other node pubkeys
    util.read_pubkeys_from_files()
    # Suppress all gossip messages from C-Lightning node.
    plugin.rpc.dev_suppress_gossip()
    logger.info("goTenna plugin initialized")


async def main():
    """Main function that is run when the plugin is loaded (and run) by C-Lightning.
    Function decorated with @plugin.init() will be run when `plugin.run()` is called
    which must be at startup.
    """
    # This nursery will run our main tasks for us:
    # https://trio.readthedocs.io/en/stable/reference-core.html#tasks-let-you-do-multiple-things-at-once
    try:
        async with trio.open_nursery() as config.nursery:
            # We run the plugin itself in a synchronous thread so trio.run() maintains
            # overall control of the app.
            config.nursery.start_soon(trio.to_thread.run_sync, gotenna_plugin.run)
            # # Start the goTenna connection daemon.
            config.nursery.start_soon(mesh.connection_daemon)
    except:
        logger.exception("whoops")
    finally:
        logger.info("goTenna plugin finished.")


trio.run(main)
