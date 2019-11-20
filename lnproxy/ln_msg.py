import logging
import struct
import tempfile
from typing import Tuple

import lnproxy.config as config
import lnproxy.onion as onion
import lnproxy.util as util

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

    htlc_logger.debug(f"{direction:<8s} | channel_id: {channel_id.hex()}")
    htlc_logger.debug(f"{direction:<8s} | id: {_id}")
    htlc_logger.debug(f"{direction:<8s} | amount_msat: {amount_msat}")
    htlc_logger.debug(f"{direction:<8s} | payment_hash: {payment_hash.hex()}")
    htlc_logger.debug(f"{direction:<8s} | cltv_expiry: {cltv_expiry}")

    # htlc from local lightning node:
    if direction == "outbound":
        # _onion = struct.unpack(config.le_onion, orig_payload[84:1450])[0]
        # logger.debug(f"original onion length: {len(_onion)}")
        # logger.debug(f"original onion:\n{_onion.hex()}")

        # # decode the original onion
        # with open(config.onion_temp_file, "w") as f:
        #     f.write(_onion.hex())
        # # TODO: remove config.my_node hack!
        # logger.debug("Decoding original onion")
        # orig_payloads, orig_nexts = onion.decode_onion(
        #     config.onion_temp_file, priv_keys, payment_hash.hex(),
        # )
        # logger.debug(f"Original payloads:{orig_payloads}")

        # chop off the onion before sending
        htlc_logger.info(f"{direction:<8s} | Chopping off onion before transmission")
        return orig_payload[0:84]

    # htlc from external lightning node
    if direction == "inbound":
        # generate a new onion as there won't be one
        htlc_logger.debug(f"{direction:<8s} | Generating new onion")
        # determine whether we are the final hop or not
        if payment_hash.hex() in util.get_my_payment_hashes():
            htlc_logger.debug("We're the final hop!")
            # if we are generate an onion with our pk as first_pubkey
            generated_onion = onion.generate_new(
                first_pubkey=config.my_node_pubkey,
                next_pubkey=None,
                amount_msat=amount_msat,
                payment_hash=payment_hash,
                cltv_expiry=cltv_expiry,
            )
            priv_keys = onion.get_regtest_privkeys([config.my_node])
        else:
            # else generate an onion with ou5r pk as first_hop and next hop pk as
            # second_pubkey
            # TODO: calculate: also subtract config.CLTV_d from cltv_expiry
            htlc_logger.debug("We're not the final hop...")
            generated_onion = onion.generate_new(
                first_pubkey=config.my_node_pubkey,
                next_pubkey=config.next_node_pubkey,
                amount_msat=amount_msat,
                payment_hash=payment_hash,
                cltv_expiry=cltv_expiry - config.CLTV_d,
            )
            priv_keys = onion.get_regtest_privkeys(
                [config.my_node, (config.my_node + 1) % 3]
            )
        # DEBUG: decode generated onion
        onion_file = tempfile.NamedTemporaryFile(mode="w+t", delete=False)
        with open(onion_file.name, "wt") as f:
            f.write(generated_onion.hex())
        htlc_logger.debug("Decoding generated onion:")
        gen_payloads, gen_nexts = onion.decode_onion(
            onion_file.name, priv_keys, payment_hash.hex(),
        )
        htlc_logger.debug(f"Payload(s):{gen_payloads}")
        htlc_logger.debug(f"_next(s):{gen_nexts}")

        modified_payload = orig_payload
        # add the new onion
        modified_payload += struct.pack(config.le_onion, generated_onion)
        return modified_payload


def parse(header: bytes, body: bytes, direction: str) -> Tuple[bytes, bytes]:
    """Parse a lightning message, optionally modify and then return it
    """
    # handle empty messages gracefully
    if body == b"":
        return header, body

    msg_type = body[0:2]
    msg_payload = body[2:]
    msg_code = deserialize_type(msg_type)

    # filter unknown codes and return without processing
    if msg_code not in codes.keys():
        logger.warning(f"Message code not found in ln_msg.codes.keys(): {msg_code}")
        return header, body

    logger.info(
        f"{direction:<8s} | {codes.get(msg_code):<27s} | {len(msg_payload):>4d}B"
    )

    # handle htlc_add_update
    if msg_code == config.ADD_UPDATE_HTLC:
        body = msg_type + parse_update_add_htlc(msg_payload, direction)
        # recompute header based on length of msg without onion
        _header = b""
        _header += struct.pack(">H", len(body))
        _header += struct.pack(">16s", 16 * (bytes.fromhex("00")))
        return _header, body

    return header, msg_type + msg_payload
