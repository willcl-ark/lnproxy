import logging
import struct

import config
import onion
import util

logger = logging.getLogger(f"{'MSG':<6s}")
htlc_logger = logging.getLogger(f"{'HTLC':<6s}")


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
    logger.debug(f"original onion length: {len(_onion)}")
    # logger.debug(f"original onion:\n{_onion.hex()}")

    # decode the original onion
    with open(config.onion_temp_file, "w") as f:
        f.write(_onion.hex())
    # TODO: remove config.my_node hack!
    priv_keys = onion.get_regtest_privkeys()[config.my_node :]
    logger.debug("Decoding original onion")
    orig_payloads, orig_nexts = onion.decode_onion(
        config.onion_temp_file, priv_keys, payment_hash.hex(),
    )

    # # htlc from local lightning node
    # if direction == "local_to_remote":
    #     # chop off the onion before sending
    #     logger.debug("Chopping off onion before transmission")
    #     return orig_payload[0:84]

    # htlc from external lightning node
    if direction == "remote_to_local":
        # generate a new onion
        logger.debug("Generating new onion")
        # determine whether we are the final hop or not
        if payment_hash.hex() in util.get_my_payment_hashes():
            logger.debug("We're the final hop!")
            # if we are generate an onion with our pk as first_pubkey
            generated_onion = onion.generate_new(
                first_pubkey=config.my_node_pubkey,
                next_pubkey=None,
                amount_msat=amount_msat,
                payment_hash=payment_hash,
                cltv_expiry=cltv_expiry,
            )
        else:
            # else generate an onion with our pk as first_hop and next hop pk as
            # second_pubkey
            logger.debug("We're not the final hop...")
            generated_onion = onion.generate_new(
                first_pubkey=config.my_node_pubkey,
                next_pubkey=config.next_node_pubkey,
                amount_msat=amount_msat - config.C_FEE,
                payment_hash=payment_hash,
                cltv_expiry=cltv_expiry - config.CLTV_d,
            )

    # decode generated onion
    with open(config.onion_temp_file, "w") as f:
        f.write(generated_onion.hex())
    logger.debug("Decoding generated onion:")
    gen_payloads, gen_nexts = onion.decode_onion(
        config.onion_temp_file, priv_keys, payment_hash.hex(),
    )

    logger.debug("Onion comparisons:")
    logger.debug(f"Payloads:\n{orig_payloads}\n{gen_payloads}")
    logger.debug(f"Payloads match: {orig_payloads == gen_payloads}")
    logger.debug(f"Nexts:\n{orig_nexts}\n{gen_nexts}")

    modified_payload = bytearray(orig_payload)
    # add the new onion
    struct.pack_into(config.le_onion, modified_payload, 84, generated_onion)
    # # update the htlc amount to reflect our fee
    # struct.pack_into(config.be_u64, modified_payload, 40, (amount_msat - config.C_FEE))
    return modified_payload


def parse(msg: bytes, direction: str) -> bytes:
    """Parse a lightning message and return it
    """
    msg_type = msg[0:2]
    msg_payload = msg[2:]

    # check the message type
    msg_code = deserialize_type(msg_type)
    logger.debug(
        f"{direction:<15s} | {codes.get(msg_code):<27s} | {len(msg_payload):>4d}B"
    )

    # handle htlc_updates
    if msg_code == config.ADD_UPDATE_HTLC:
        return msg_type + parse_update_add_htlc(msg_payload, direction)

    return msg_type + msg_payload
