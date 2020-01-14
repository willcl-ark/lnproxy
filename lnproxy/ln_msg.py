import struct
from typing import Tuple

import lnproxy.config as config
import lnproxy.onion as onion
import lnproxy.util as util


log = util.log

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


def deserialize_type(msg_type: bytes) -> int:
    """Deserialize the lightning message type
    """
    return struct.unpack(config.be_u16, msg_type)[0]


def deserialize_htlc_payload(payload: bytes,) -> Tuple[bytes, int, int, bytes, int]:
    """Decode an htlc_add_update message and return the parts
    """
    channel_id = struct.unpack(config.le_32b, payload[0:32])[0]
    _id = struct.unpack(config.be_u64, payload[32:40])[0]
    amount_msat = struct.unpack(config.be_u64, payload[40:48])[0]
    payment_hash = struct.unpack(config.le_32b, payload[48:80])[0]
    cltv_expiry = struct.unpack(config.be_u32, payload[80:84])[0]

    log(f"channel_id: {channel_id.hex()}")
    log(f"id: {_id}")
    log(f"amount_msat: {amount_msat}")
    log(f"payment_hash: {payment_hash.hex()}")
    log(f"cltv_expiry: {cltv_expiry}")

    return channel_id, _id, amount_msat, payment_hash, cltv_expiry


def parse_update_add_htlc(orig_payload: bytes, to_mesh: bool) -> bytes:
    """Parse an update_add_htlc message
    """
    # decode the htlc
    channel_id, _id, amount_msat, payment_hash, cltv_expiry = deserialize_htlc_payload(
        orig_payload[0:84]
    )

    # outbound htlc from local lightning node:
    if to_mesh:
        # chop off the onion before sending
        log(f"We are htlc initiator; chopping off onion before transmission")
        return orig_payload[0:84]

    # htlc from external lightning node
    else:
        # generate a new onion as there won't be one
        log(f"We are htlc recipient; generating new onion")
        # determine whether we are the final hop or not
        if payment_hash.hex() in util.get_my_payment_hashes():
            log("We're the final hop!")
            # if we are generate an onion with our pk as first_pubkey
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
            log("We're not the final hop...")
            generated_onion = onion.generate_new(
                my_pubkey=config.rpc.getinfo()["id"],
                next_pubkey=next_pubkey,
                amount_msat=amount_msat,
                payment_hash=payment_hash,
                cltv_expiry=cltv_expiry - config.CLTV_d,
            )
        # log(f"Generated onion\n{generated_onion}")

        # add the new onion to original payload
        return orig_payload + generated_onion


def parse(header: bytes, body: bytes, to_mesh: bool) -> Tuple[bytes, bytes]:
    """Parse a lightning message, optionally modify and then return it
    """
    direction = "Sent" if to_mesh else "Rcvd"
    # handle empty messages gracefully
    if body == b"":
        return header, body

    msg_type = body[0:2]
    msg_payload = body[2:]
    msg_code = deserialize_type(msg_type)

    # filter unknown codes and return without processing
    if msg_code not in codes.keys():
        log(f"Message code not found in ln_msg.codes.keys(): {msg_code}", level="warn")
        return header, body

    log(
        f"{direction} | {codes.get(msg_code):<27s} | {len(msg_payload):>4d}B",
        level="debug",
    )

    # handle htlc_add_update
    if msg_code == config.ADD_UPDATE_HTLC:
        body = msg_type + parse_update_add_htlc(msg_payload, to_mesh)
        # recompute header based on length of msg without onion
        _header = b""
        _header += struct.pack(">H", len(body))
        _header += struct.pack(">16s", 16 * (bytes.fromhex("00")))
        return _header, body

    return header, body


async def read_handshake_msg(stream, i: int, initiator: bool) -> bytes:
    """Handles handshake messages.
    """
    # log(f"Starting read_handshake {i}")
    hs_pkt_size = {True: [50, 66], False: [50]}
    # pass full 50 / 66 B messages transparently
    req_len = hs_pkt_size[initiator][i]
    message = bytearray()
    # log(f"Trying receive_exactly for {req_len}B from read_handshake")
    # message += await util.receive_exactly(stream, req_len)
    message += await stream.receive_some(req_len)
    return message


async def read_lightning_msg(stream, to_mesh: bool) -> bytes:
    """Reads a full lightning message from a stream and returns the message.
    """
    # Bolt #8: Read exactly 18 bytes from the network buffer.
    header = await util.receive_exactly(stream, config.MSG_HEADER)

    # Bolt #8: 2-byte message length
    body_len = struct.unpack(">H", header[: config.MSG_LEN])[0]

    # Bolt #8: 16-byte MAC of the message length
    # body_len_mac = struct.unpack("16s", header[-16:])[0]
    # TODO: we can add a fake MAC on here during full mesh operation
    # body_len_mac = 16 * (bytes.fromhex("00"))

    # Bolt #8: Lightning message
    body = await util.receive_exactly(stream, body_len)

    # parse the message
    header, body = parse(header, body, to_mesh)

    # Bolt #8: 16 Byte MAC of the Lightning message
    body_mac = await util.receive_exactly(stream, config.MSG_MAC)
    # TODO: we can add a fake MAC on here during full mesh operation
    # body_mac = 16 * (bytes.fromhex("00"))

    return header + body + body_mac
