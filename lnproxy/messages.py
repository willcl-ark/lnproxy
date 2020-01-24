import logging
import struct
import uuid
import hashlib
import typing

import lnproxy.crypto as crypto

import lnproxy.config as config
import lnproxy.network as network
import lnproxy.onion as onion
import lnproxy.util as util


logger = util.CustomAdapter(logging.getLogger(__name__), None)


codes = {
    16: "init",
    17: "error",
    18: "ping",
    19: "pong",
    32: "open_channel",
    33: "accept_channel",
    34: "funding_created",
    35: "funding_signed",
    36: "funding_locked",
    38: "shutdown",
    39: "closing_signed",
    128: "update_add_htlc",
    130: "update_fulfill_htlc",
    131: "update_fail_htlc",
    132: "commitment_signed",
    133: "revoke_and_ack",
    134: "update_fee",
    135: "update_fail_malformed_htlc",
    136: "channel_reestablish",
    256: "channel_announcement",
    257: "node_announcement",
    258: "channel_update",
    259: "announcement_signatures",
    261: "query_short_channel_ids",
    262: "reply_short_channel_ids_end",
    263: "query_channel_range",
    264: "reply_channel_range",
    265: "gossip_timestamp_filter",
}


class EncryptedMessage:
    """A message sent via C-Lightning plugin RPC.
    """

    def __init__(
        self,
        gid: int,
        plain_text: str = None,
        encrypted_msg: bytes = None,
        dest_pubkey: str = None,
        nonce: bytes = None,
        router=None,
    ):
        self.gid = gid
        self.plain_text = plain_text
        self.encrypted_msg = encrypted_msg
        self.router = router
        self.msatoshi: int = int()
        self.dest_pubkey = dest_pubkey
        self.nonce: bytes = nonce
        self.preimage = None
        self.payment_hash = None
        self.sender_pubkey: str = str()
        self.decrypted_msg: bytes = bytes()
        logger.debug(f"Created {repr(self)}")

    def __str__(self):
        return (
            f"EncryptedMessage({self.gid}, {self.plain_text}, {self.encrypted_msg}, "
            f"{self.decrypted_msg}"
        )

    def __repr__(self):
        return (
            f"EncryptedMessage({self.gid}, {self.plain_text}, {self.encrypted_msg}, "
            f"{self.decrypted_msg}, {self.dest_pubkey}, {self.nonce}, "
            f"{self.preimage}, {self.payment_hash}, "
            f"{self.sender_pubkey}, {self.decrypted_msg})"
        )

    def encrypt(self):
        # First lookup the pubkey from the GID
        self.dest_pubkey = self.router.lookup_pubkey(self.gid)
        # Generate the preimage and payment hash
        self.preimage = hashlib.sha256(self.plain_text.encode("utf-8"))
        self.payment_hash = hashlib.sha256(self.preimage.digest())
        # Make sure that we have a nonce, or get __next__()
        if not self.nonce:
            try:
                self.nonce = self.router.get_nonce(self.gid).to_bytes(16, "big")
            except LookupError:
                raise
        # Try to encrypt
        try:
            self.encrypted_msg = crypto.encrypt(
                self.dest_pubkey, self.plain_text.encode("utf-8"), self.nonce
            )
        except TypeError:
            raise
        logger.debug(f"Encrypted message: {repr(self)}")
        return self.encrypted_msg

    def decrypt(self):
        # The first 4 bytes can be unpacked to reveal the sender GID
        self.gid = struct.unpack(config.be_u32, self.encrypted_msg[0:4])[0]
        # Make sure that we have a nonce, or get __next__()
        if not self.nonce:
            try:
                self.nonce = self.router.get_nonce(self.gid).to_bytes(16, "big")
            except LookupError:
                raise
        try:
            self.decrypted_msg = crypto.decrypt(
                config.node_secret_key, bytes(self.encrypted_msg[4:]), self.nonce
            )
        except:
            logger.exception("Error during decrypt:")
        self.preimage = hashlib.sha256(self.decrypted_msg).digest()
        self.payment_hash = hashlib.sha256(self.preimage).digest()
        return self.preimage, self.payment_hash, self.decrypted_msg


class LightningMessage:
    def __init__(self, header, body_len, body_len_mac, body, body_mac, to_mesh):
        self.header = header
        self.body_len = body_len
        self.body_len_mac = body_len_mac
        self.body = body
        self.body_mac = body_mac
        self.to_mesh = to_mesh
        self.msg_type = None
        self.msg_payload = None
        self.msg_code = None
        # Grab the GID from the handy contextvar
        self.gid = util.gid_key.get()

    @classmethod
    async def read(cls, stream, to_mesh: bool):
        """Reads a full lightning message from a stream.
        """
        # Bolt #8: Read exactly 18 bytes from the network buffer.
        header = await util.receive_exactly(stream, config.MSG_HEADER)

        # Bolt #8: 2-byte message length
        body_len = struct.unpack(">H", header[: config.MSG_LEN])[0]

        # Bolt #8: 16-byte MAC of the message length
        body_len_mac = struct.unpack("16s", header[-16:])[0]
        # body_len_mac = 16 * (bytes.fromhex("00"))

        # Bolt #8: Lightning message
        body = await util.receive_exactly(stream, body_len)

        # TODO: this should be a method called after the class is created!!!
        # # parse the message
        # cls.parse(header, body, to_mesh)

        # Bolt #8: 16 Byte MAC of the Lightning message
        body_mac = await util.receive_exactly(stream, config.MSG_MAC)
        # TODO: we can add a fake MAC on here during full mesh operation saving 16 bytes
        # body_mac = 16 * (bytes.fromhex("00"))

        return cls(header, body_len, body_len_mac, body, body_mac, to_mesh)

    def deserialise_body(self):
        self.msg_type = self.body[0:2]
        self.msg_payload = self.body[2:]
        self.msg_code = deserialize_type(self.msg_type)

    async def parse(self):
        """Parse a lightning message, optionally modify and then return it
        """
        direction = "Sent" if self.to_mesh else "Rcvd"
        # handle empty messages gracefully
        if self.body == b"":
            return

        self.deserialise_body()

        # filter unknown codes and return without processing
        if self.msg_code not in codes.keys():
            logger.info(
                f"Message code not found in ln_msg.codes.keys(): {self.msg_code}"
            )
            return

        logger.info(
            f"{direction} | {codes.get(self.msg_code):<27s} | {len(self.msg_payload):>4d}B",
        )

        # handle htlc_add_update specially
        if self.msg_code == config.ADD_UPDATE_HTLC:
            _body = self.msg_type + parse_update_add_htlc(
                self.msg_payload, self.to_mesh
            )
            # recompute header based on length of msg w/o onion and w/ encrypted msg
            _header = b""
            _header += struct.pack(">H", len(_body))
            _header += struct.pack(">16s", 16 * (bytes.fromhex("00")))
            self.header = _header
            self.body = _body
            return


class HandshakeMessage:
    def __init__(self, message):
        self.message = message

    @classmethod
    async def read(cls, stream, i: int, initiator: bool):
        """Read a new handshake message.
        """
        # logger.info(f"Starting read_handshake {i}")
        hs_pkt_size = {True: [50, 66], False: [50]}
        # pass full 50 / 66 B messages transparently
        req_len = hs_pkt_size[initiator][i]
        message = bytearray()
        # logger.info(f"Trying receive_exactly for {req_len}B from read_handshake")
        # message += await util.receive_exactly(stream, req_len)
        try:
            message += await stream.receive_some(req_len)
        except:
            logger.exception("read_handshake")
        return cls(message)


class AddUpdateHTLC:
    def __init__(self):
        pass


def deserialize_type(msg_type: bytes) -> int:
    """Deserialize the lightning message type
    """
    return struct.unpack(config.be_u16, msg_type)[0]


def handle_inbound_htlc_add_update(
    channel_id, _id, amount_msat, payment_hash, cltv_expiry, orig_payload
):
    # generate a new onion as there won't be one
    logger.info(f"We are htlc recipient; generating new onion")
    # determine whether we are the final hop or not
    # Get a list of my_invoices generated by us creating invoices
    my_invoices = [
        invoice["payment_hash"] for invoice in config.rpc.listinvoices()["invoices"]
    ]
    if payment_hash.hex() in my_invoices:
        logger.info("We're the final hop!")
        # Now we can generate an onion with our pk as first_pubkey
        generated_onion = onion.generate_new(
            my_pubkey=config.rpc.getinfo()["id"],
            next_pubkey=None,
            amount_msat=amount_msat,
            payment_hash=payment_hash,
            cltv_expiry=cltv_expiry,
        )
    else:
        # else generate an onion with our pk as first_hop and next hop pk as
        # second_pubkey

        # first get next pubkey
        # TODO: remove hard-code!
        next_pubkey = util.get_next_pubkey(channel_id)
        logger.info("We're not the final hop...")
        generated_onion = onion.generate_new(
            my_pubkey=config.rpc.getinfo()["id"],
            next_pubkey=next_pubkey,
            amount_msat=amount_msat,
            payment_hash=payment_hash,
            cltv_expiry=cltv_expiry - config.CLTV_d,
        )

    # add the new onion to original payload
    return orig_payload + generated_onion


def deserialize_htlc_payload(
    payload: bytes,
) -> typing.Tuple[bytes, int, int, bytes, int]:
    """Decode an htlc_add_update message and return the values
    returns: channel_id, _id, amount_msat, payment_hash, cltv_expiry
    """
    channel_id = struct.unpack(config.le_32b, payload[0:32])[0]
    _id = struct.unpack(config.be_u64, payload[32:40])[0]
    amount_msat = struct.unpack(config.be_u64, payload[40:48])[0]
    payment_hash = struct.unpack(config.le_32b, payload[48:80])[0]
    cltv_expiry = struct.unpack(config.be_u32, payload[80:84])[0]

    logger.info(f"channel_id: {channel_id.hex()}")
    logger.info(f"id: {_id}")
    logger.info(f"amount_msat: {amount_msat}")
    logger.info(f"payment_hash: {payment_hash.hex()}")
    logger.info(f"cltv_expiry: {cltv_expiry}")

    return channel_id, _id, amount_msat, payment_hash, cltv_expiry


def ret_encrypted_msg_and_header(payment_hash: bytes):
    """Looks up and returns an encrypted message with our (sender) GID attached so
    that recipient can use correct nonce
    """
    # We will send our GID as a u32
    my_gid = struct.pack(
        config.be_u32, network.router.lookup_gid(config.node_info["id"])
    )
    msg = bytearray()
    msg += my_gid
    msg += config.key_sends[payment_hash].encrypted_msg
    header = struct.pack(config.be_u16, len(msg))
    logger.info(
        f"Generated header for encrypted message\nheader: {header.hex()}\nmsg {msg.hex()}"
    )
    return header + bytes(msg)


def parse_update_add_htlc(orig_payload: bytes, to_mesh: bool) -> bytes:
    """Parse an update_add_htlc message
    """
    # Deserialize the htlc details excluding onion or any encrypted message
    channel_id, _id, amount_msat, payment_hash, cltv_expiry = deserialize_htlc_payload(
        orig_payload[0:84]
    )

    # Get a list of my_payment_hashes
    my_payment_hashes = [
        payment["payment_hash"] for payment in config.rpc.listsendpays()["payments"]
    ]
    logger.info(f"my_payment_hashes: {my_payment_hashes}")

    # We are the htlc originator, implies that to_mesh is True
    if payment_hash.hex() in my_payment_hashes:
        # Chop off the onion as this is outbound
        payload = orig_payload[0:84]

        # If this is a key_send
        if payment_hash in config.key_sends:
            # Add encrypted message header and data
            logger.info("Adding encrypted message to outbound htlc")
            header_and_enc_msg = ret_encrypted_msg_and_header(payment_hash)
            return payload + header_and_enc_msg
        # Not a key_send
        else:
            return payload

    # We are routing or recipient
    else:
        # Receiving from the mesh
        if not to_mesh:
            # If 84B long, no encrypted message included
            if len(orig_payload) == 84:
                return handle_inbound_htlc_add_update(
                    channel_id,
                    _id,
                    amount_msat,
                    payment_hash,
                    cltv_expiry,
                    orig_payload,
                )

            # If longer than 84B we expect an encrypted message appended
            # Get the length of it from the first 2 bytes
            enc_msg_len = struct.unpack(config.be_u16, orig_payload[84:86])[0]
            logger.info(f"Encoded message length: {enc_msg_len}")
            # Get the message itself
            gid = util.gid_key.get()
            enc_msg = EncryptedMessage(
                gid=gid,
                encrypted_msg=orig_payload[86 : 86 + enc_msg_len],
                router=network.router,
            )
            enc_msg.nonce = network.router.get_node(gid).nonce.to_bytes(16, "big")
            logger.info(f"Encrypted message: {enc_msg.encrypted_msg.hex()}")

            # Now we check if the message is "for us" (can we decrypt the message)
            try:
                (
                    derived_preimage,
                    derived_payment_hash,
                    decrypted_msg,
                ) = enc_msg.decrypt()
            # Decode failed, this is not for us
            except (LookupError, TypeError):
                logger.info(f"Could not decrypt encrypted message")
                # The encrypted message wasn't for us. We should store it so we can
                # re-attach on the way back out...
                config.key_sends[payment_hash] = enc_msg
                return handle_inbound_htlc_add_update(
                    channel_id,
                    _id,
                    amount_msat,
                    payment_hash,
                    cltv_expiry,
                    orig_payload[0:84],
                )
            # This is one for us!
            else:
                logger.info(f"payment_hash:         {payment_hash.hex()}")
                logger.info(f"derived_payment_hash: {derived_payment_hash.hex()}")
                # Add an invoice to C-Lightning for this amount so we 'expect' it
                config.rpc.invoice(
                    msatoshi=amount_msat,
                    label=f"{uuid.uuid1().hex}",
                    description=f"{uuid.uuid1().hex} Received keysend of {amount_msat}msat",
                    preimage=derived_preimage.hex(),
                )

                logger.info(
                    f"Received encrypted message for us!\n" f"{decrypted_msg.decode()}"
                )
                # Process the htlc as we normally would now
                return handle_inbound_htlc_add_update(
                    channel_id,
                    _id,
                    amount_msat,
                    payment_hash,
                    cltv_expiry,
                    orig_payload[0:84],
                )

        # Sending out to the mesh
        else:
            # Chop off the onion before sending
            payload = orig_payload[0:84]
            # Do we have an encrypted message for it:
            try:
                enc_msg = config.key_sends[payment_hash].encrypted_msg
            except LookupError:
                pass
            # If we do, create the header and append it and the message to payload
            else:
                enc_msg_header = struct.pack(config.be_u16, len(enc_msg))
                payload = payload + enc_msg_header + enc_msg
            return payload
