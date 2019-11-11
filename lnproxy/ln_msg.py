import logging
import struct

import config
import onion
import util

logger = logging.getLogger(f"{'MSG':<5}")
htlc_logger = logging.getLogger(f"{'HTLC':<5}")


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


def parse_update_add_htlc(orig_payload: bytes, direction: str) -> bytes:
    """Parse an update_add_htlc message
    """
    # decode the htlc
    channel_id = struct.unpack(config.le_32b, orig_payload[0:32])[0]
    _id = struct.unpack(config.be_u64, orig_payload[32:40])[0]
    amount_msat = struct.unpack(config.be_u64, orig_payload[40:48])[0]
    payment_hash = struct.unpack(config.le_32b, orig_payload[48:80])[0]
    cltv_expiry = struct.unpack(config.be_u32, orig_payload[80:84])[0]
    _onion = struct.unpack(config.le_onion, orig_payload[84:1450])[0]

    htlc_logger.debug(f"channel_id: {channel_id.hex()}")
    htlc_logger.debug(f"id: {_id}")
    htlc_logger.debug(f"amount_msat: {amount_msat}")
    htlc_logger.debug(f"payment_hash: {payment_hash.hex()}")
    htlc_logger.debug(f"cltv_expiry: {cltv_expiry}")
    htlc_logger.debug(f"onion length: {len(_onion)}")
    htlc_logger.debug(f"onion hex:\n{_onion.hex()}")

    # with open("/Users/will/src/lnproxy/onion.dat", "w") as f:
    #     f.write(_onion.hex())
    #
    # priv_keys = []
    # import extract_private_key_from_hsm_secret
    #
    # for node in extract_private_key_from_hsm_secret.nodes:
    #     priv_keys.append(extract_private_key_from_hsm_secret.get_privkey(node))
    # onion.decode_onion(
    #     "/Users/will/src/lnproxy/onion.dat", priv_keys[1:], payment_hash.hex()
    # )

    # from local lightning node
    if direction == "Inbound":
        # chop off the onion
        return orig_payload[0:84]

    # from external lightning node
    if direction == "Outbound":
        # generate a new onion
        generated_onion = onion.generate_new(
            util.get_l2_pubkey(),
            util.get_l3_pubkey(),
            amount_msat,
            payment_hash,
            cltv_expiry - 6,
        )
        modified_payload = orig_payload[0:84]
        # add the new onion
        modified_payload += struct.pack(config.le_onion, generated_onion)
        return modified_payload


def parse(msg: bytes, direction: str) -> bytes:
    """Parse a lightning message and return it
    """
    msg_type = msg[0:2]
    msg_payload = msg[2:]

    # check the message type
    msg_code = deserialize_type(msg_type)
    # only print messages once, as we share a single proxy for testing
    # 'Inbound' == l1 in tests
    if direction == "Inbound":
        logger.debug(f"{codes.get(msg_code):26s} | {len(msg_payload):>4d}B")

    # handle htlc_updates receiver
    if msg_code == config.ADD_UPDATE_HTLC:
        return msg_type + parse_update_add_htlc(msg_payload, direction)

    return msg_type + msg_payload
