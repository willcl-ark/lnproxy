import logging
import struct
import uuid
import hashlib

import lnproxy.crypto as crypto

import lnproxy.config as config
import lnproxy.network as network
import lnproxy.onion as onion
import lnproxy.util as util


logger = util.CustomAdapter(logging.getLogger(__name__), None)
router = network.router


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


class UnknownMessage(Exception):
    """An Exception class to raise if we get an unknown message type.
    Usually requires that the entire connection be reset.
    """


class EncryptedMessage:
    """A message sent via C-Lightning plugin RPC.
    """

    def __init__(
        self,
        gid: int = int(),
        plain_text: str = str(),
        encrypted_msg: bytes = bytes(),
        dest_pubkey: str = str(),
        nonce: bytes = bytes(),
    ):
        self.gid = gid
        self.plain_text = plain_text
        self.encrypted_msg = encrypted_msg
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
        self.dest_pubkey = router.lookup_pubkey(self.gid)
        # Generate the preimage and payment hash
        self.preimage = hashlib.sha256(self.plain_text.encode("utf-8"))
        self.payment_hash = hashlib.sha256(self.preimage.digest())
        # Set the nonce to the first 16 bytes of the payment_hash
        # TODO: Is this secure enough?
        self.nonce = self.payment_hash.digest()[:16]
        # Try to encrypt
        try:
            self.encrypted_msg = crypto.encrypt(
                self.dest_pubkey, self.plain_text.encode("utf-8"), self.nonce
            )
        except TypeError:
            raise
        logger.debug(f"Encrypted message: {repr(self)}")
        return self.encrypted_msg

    def decrypt(self, payment_hash: bytes):
        # Set the nonce to the first 16 bytes of the payment_hash
        self.nonce = payment_hash[:16]
        self.decrypted_msg = crypto.decrypt(
            config.node_secret_key, bytes(self.encrypted_msg), self.nonce
        )
        self.preimage = hashlib.sha256(self.decrypted_msg).digest()
        self.payment_hash = hashlib.sha256(self.preimage).digest()
        return self.preimage, self.payment_hash, self.decrypted_msg


class AddUpdateHTLC:
    """An htlc_add_update lightning message.
    May include an encrypted message.
    """

    def __init__(self, payload: bytes, to_mesh: bool):
        self.payload = payload
        self.to_mesh = to_mesh
        self.channel_id: bytes = bytes()
        self._id: int = int()
        self.amount_msat: int = int()
        self.payment_hash: bytes = bytes()
        self.cltv_expiry: int = int()
        self.my_payment_hashes = [
            payment["payment_hash"] for payment in config.rpc.listsendpays()["payments"]
        ]
        self.originator = (
            True if self.payment_hash.hex() in self.my_payment_hashes else False
        )
        self.final_payload: bytes = bytes()
        self.encrypted_msg: bytes = bytes()
        self.onion = None

    def is_key_send(self) -> bool:
        # TODO: update config.key_sends?
        return self.payment_hash in config.key_sends

    def deserialize(self):
        """Decode an htlc_add_update message
        """
        self.channel_id = struct.unpack(config.le_32b, self.payload[0:32])[0]
        self._id = struct.unpack(config.be_u64, self.payload[32:40])[0]
        self.amount_msat = struct.unpack(config.be_u64, self.payload[40:48])[0]
        self.payment_hash = struct.unpack(config.le_32b, self.payload[48:80])[0]
        self.cltv_expiry = struct.unpack(config.be_u32, self.payload[80:84])[0]

        logger.debug(f"channel_id: {self.channel_id.hex()}")
        logger.debug(f"id: {self._id}")
        logger.debug(f"amount_msat: {self.amount_msat}")
        logger.debug(f"payment_hash: {self.payment_hash.hex()}")
        logger.debug(f"cltv_expiry: {self.cltv_expiry}")

    def get_encrypted_msg(self):
        """Looks up and returns an encrypted message.
            """
        msg = bytearray()
        msg += config.key_sends[self.payment_hash].encrypted_msg
        header = struct.pack(config.be_u16, len(msg))
        logger.debug(
            f"Generated header for encrypted message\nheader: {header.hex()}\nmsg {msg.hex()}"
        )
        self.encrypted_msg = header + bytes(msg)

    def handle_inbound(self):
        # Generate a new onion as there won't be one from the mesh
        logger.debug(f"We are htlc recipient; generating new onion")
        # Determine whether we are the final hop or not
        # Get a list of my_invoices generated by us creating invoices
        my_invoices = [
            invoice["payment_hash"] for invoice in config.rpc.listinvoices()["invoices"]
        ]
        if self.payment_hash.hex() in my_invoices:
            logger.debug("We're the final hop!")
            # Now we can generate an onion with our pk as first_pubkey
            self.onion = onion.generate_new(
                my_pubkey=config.rpc.getinfo()["id"],
                next_pubkey=None,
                amount_msat=self.amount_msat,
                payment_hash=self.payment_hash,
                cltv_expiry=self.cltv_expiry,
            )
        else:
            # else generate an onion with our pk as first_hop and next hop pk as
            # second_pubkey

            # first get next pubkey
            # TODO: remove hard-code!
            next_pubkey = util.get_next_pubkey(self.channel_id)
            logger.debug("We're not the final hop...")
            self.onion = onion.generate_new(
                my_pubkey=config.rpc.getinfo()["id"],
                next_pubkey=next_pubkey,
                amount_msat=self.amount_msat,
                payment_hash=self.payment_hash,
                cltv_expiry=self.cltv_expiry - config.CLTV_d,
            )

        # add the new onion to original payload
        # This slice ensures we cut off eny encrypted message
        return self.payload[0:84] + self.onion

    def handle_key_send(self, derived_preimage, derived_payment_hash, decrypted_msg):
        logger.debug(f"payment_hash:         {self.payment_hash.hex()}")
        logger.debug(f"derived_payment_hash: {derived_payment_hash.hex()}")
        # Add an invoice to C-Lightning for this amount so we 'expect' it
        config.rpc.invoice(
            msatoshi=self.amount_msat,
            label=f"{uuid.uuid1().hex}",
            description=f"{uuid.uuid1().hex} Received keysend of {self.amount_msat}msat",
            preimage=derived_preimage.hex(),
        )

        logger.info(
            f"Received encrypted message for us!\n"
            f"Decrypted message: {decrypted_msg.decode()}"
        )
        # Remove the encrypted message
        self.payload = self.payload[0:84]
        # Process the htlc as we normally would
        return self.handle_inbound()

    def try_decode(self):
        # Get the length of it from the first 2 bytes
        enc_msg_len = struct.unpack(config.be_u16, self.payload[84:86])[0]
        logger.debug(f"Encoded message length: {enc_msg_len}")
        # Get the message itself
        enc_msg = EncryptedMessage(encrypted_msg=self.payload[86 : 86 + enc_msg_len],)
        # enc_msg.nonce = router.get_node(gid).nonce.to_bytes(16, "big")
        logger.debug(f"Encrypted message: {enc_msg.encrypted_msg.hex()}")

        # Now we check if the message is "for us" (can we decrypt the message)
        try:
            (derived_preimage, derived_payment_hash, decrypted_msg,) = enc_msg.decrypt(
                self.payment_hash
            )
        # Decode failed, this is not for us
        except Exception:
            logger.error(f"Could not decrypt encrypted message")
            # The encrypted message wasn't for us. We should store it so we can
            # re-attach on the way back out...
            config.key_sends[self.payment_hash] = enc_msg
            return self.handle_inbound()
        # This is one for us!
        else:
            return self.handle_key_send(
                derived_preimage, derived_payment_hash, decrypted_msg
            )

    def parse(self):
        self.deserialize()
        # We are the htlc originator, also implies that to_mesh is True
        if self.originator:
            # Chop that onion off right away!
            self.payload = self.payload[0:84]
            if self.is_key_send():
                # Add encrypted message header and data
                logger.debug("Adding encrypted message to outbound htlc")
                self.get_encrypted_msg()
                return self.payload + self.encrypted_msg
            # Not a key_send
            else:
                return self.payload
        # We are routing or final recipient
        else:
            # Receiving from the mesh
            if not self.to_mesh:
                # No encrypted message
                if len(self.payload) == 84:
                    return self.handle_inbound()
                # If longer than 84B we expect an encrypted message appended
                else:
                    return self.try_decode()
            # Sending out to the mesh
            else:
                # Chop off the onion before sending
                self.payload = self.payload[0:84]
                # Do we have an encrypted message for it:
                try:
                    enc_msg = config.key_sends[self.payment_hash].encrypted_msg
                except LookupError:
                    pass
                # If we do, create the header and append it and the message to payload
                else:
                    enc_msg_header = struct.pack(config.be_u16, len(enc_msg))
                    self.payload += enc_msg_header
                    self.payload += enc_msg
                return self.payload


class HandshakeMessage:
    def __init__(self, message):
        self.message = message

    @classmethod
    async def read(cls, stream, i: int, initiator: bool):
        """Read a new handshake message.
        """
        # logger.debug(f"Starting read_handshake {i}")
        hs_pkt_size = {True: [50, 66], False: [50]}
        # pass full 50 / 66 B messages transparently
        req_len = hs_pkt_size[initiator][i]
        message = bytearray()
        message += await util.receive_exactly(stream, req_len)
        return cls(message)


class LightningMessage:
    def __init__(
        self, header, body_len, body_len_mac, body, body_mac, to_mesh, return_stream
    ):
        self.header = bytes(header)
        self.body_len = bytes(body_len)
        self.body_len_mac = bytes(body_len_mac)
        self.body = bytes(body)
        self.body_mac = bytes(body_mac)
        self.to_mesh = to_mesh
        self.return_stream = return_stream
        self.msg_type = None
        self.msg_payload = None
        self.msg_code = None
        # Grab the GID from the contextvar
        self.gid = util.gid_key.get()

    @classmethod
    async def read(cls, stream, to_mesh: bool, return_stream, cancel_scope):
        """Reads a full lightning message from a stream.
        """
        # Bolt #8: Read exactly 18 bytes from the network buffer.
        header = await util.receive_exactly(stream, config.MSG_HEADER)

        # If we got something and we have a cancel_scope, extend it a little
        if cancel_scope:
            logger.debug(f"Extending cancel_scope by 3 seconds because we got a header")
            cancel_scope.deadline += 3

        # Bolt #8: 2-byte message length
        body_len = struct.unpack(">H", header[: config.MSG_LEN])[0]

        # Bolt #8: 16-byte MAC of the message length
        body_len_mac = struct.unpack("16s", header[-16:])[0]
        # body_len_mac = 16 * (bytes.fromhex("00"))

        # Bolt #8: Lightning message
        body = await util.receive_exactly(stream, body_len)

        # Bolt #8: 16 Byte MAC of the Lightning message
        body_mac = await stream.receive_some(config.MSG_MAC)
        # TODO: we can add a fake MAC on here saving 16 bytes
        # body_mac = 16 * (bytes.fromhex("00"))

        return cls(
            header, body_len, body_len_mac, body, body_mac, to_mesh, return_stream
        )

    def deserialize_body(self):
        self.msg_type = self.body[0:2]
        self.msg_payload = self.body[2:]
        self.msg_code = deserialize_type(self.msg_type)

    async def return_pong(self):
        # Unpack the PING to see what we need to return
        bytes_len = struct.unpack(config.be_u16, self.body[2:4])[0]

        # Now we can construct the response body
        msg_type = struct.pack(config.be_u16, config.PONG)
        bytes_len_return = struct.pack(config.be_u16, bytes_len)
        ignored_return = struct.pack(f"{bytes_len}s", bytes_len * (bytes.fromhex("00")))
        body = msg_type + bytes_len_return + ignored_return

        # And now the response itself
        response = bytearray()
        # First the body length
        response += struct.pack(">H", len(body))
        # Add the fake body length MAC
        response += 16 * (bytes.fromhex("00"))
        # Now the body itself
        response += body
        # And the fake body MAC
        response += 16 * (bytes.fromhex("00"))

        # Now send back to the stream
        await self.return_stream.send_all(response)
        logger.debug(f"Echoed pong back without mesh")

    async def parse(self):
        """Parse a lightning message, optionally modify and then return it
        """
        direction = "Sent" if self.to_mesh else "Rcvd"

        self.deserialize_body()

        # filter unknown codes and return without processing
        if self.msg_code not in codes:
            logger.warning(f"Message code not found in ln_msg.codes: {self.msg_code}")
            raise UnknownMessage(f"Unknown message received, closing. {self.msg_code}")

        logger.debug(
            f"{direction} | "
            f"{codes.get(self.msg_code):<27s} | "
            f"{len(self.msg_payload):>4d}B | "
            f"{hashlib.sha256(self.header + self.body + self.body_mac).hexdigest()}",
        )

        # handle htlc_add_update specially
        if self.msg_code == config.ADD_UPDATE_HTLC:
            _htlc = AddUpdateHTLC(self.msg_payload, self.to_mesh)
            _body = self.msg_type + _htlc.parse()
            # recompute header based on length of msg w/o onion and w/ encrypted msg
            _header = b""
            _header += struct.pack(">H", len(_body))
            _header += struct.pack(">16s", 16 * (bytes.fromhex("00")))
            self.header = _header
            self.body = _body

        # If we get a ping, echo a pong right away!
        if self.msg_code == config.PING:
            await self.return_pong()
            return False
        return True


def deserialize_type(msg_type: bytes) -> int:
    """Deserialize the lightning message type
    """
    return struct.unpack(config.be_u16, msg_type)[0]
