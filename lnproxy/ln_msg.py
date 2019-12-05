import struct
from typing import Tuple

import lnproxy.config as config
import lnproxy.onion as onion
import lnproxy.util as util


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


def deserialize_htlc_payload(
    payload: bytes, _logger
) -> Tuple[bytes, int, int, bytes, int]:
    channel_id = struct.unpack(config.le_32b, payload[0:32])[0]
    _id = struct.unpack(config.be_u64, payload[32:40])[0]
    amount_msat = struct.unpack(config.be_u64, payload[40:48])[0]
    payment_hash = struct.unpack(config.le_32b, payload[48:80])[0]
    cltv_expiry = struct.unpack(config.be_u32, payload[80:84])[0]

    _logger(f"channel_id: {channel_id.hex()}")
    _logger(f"id: {_id}")
    _logger(f"amount_msat: {amount_msat}")
    _logger(f"payment_hash: {payment_hash.hex()}")
    _logger(f"cltv_expiry: {cltv_expiry}")

    return channel_id, _id, amount_msat, payment_hash, cltv_expiry


def parse_update_add_htlc(orig_payload: bytes, to_mesh: bool, logger) -> bytes:
    """Parse an update_add_htlc message
    """
    # decode the htlc
    # TODO: remove [0:84] from here when we don't transmit onions!
    channel_id, _id, amount_msat, payment_hash, cltv_expiry = deserialize_htlc_payload(
        orig_payload[0:84], logger
    )

    # htlc from local lightning node:
    if to_mesh:
        # gen_onion = struct.unpack(config.le_onion, orig_payload[84:1450])[0]
        # # priv keys hardcoded in A -> B -> C direction only
        # priv_keys = onion.get_regtest_privkeys(
        #     [
        #         (config.my_node + 1) % 3,
        #         (config.my_node + 2) % 3,
        #         (config.my_node + 3) % 3,
        #     ]
        # )
        # orig_payloads, orig_nexts = onion.decode_onion(
        #     gen_onion, priv_keys, payment_hash.hex(),
        # )
        # logger(f"DEBUG: Original payloads:{orig_payloads}")

        # chop off the onion before sending
        logger(f"INFO: Chopping off onion before transmission")
        return orig_payload[0:84]

    # htlc from external lightning node
    else:
        # generate a new onion as there won't be one
        logger(f"INFO: Generating new onion")
        # determine whether we are the final hop or not
        if payment_hash.hex() in util.get_my_payment_hashes():
            logger("INFO: We're the final hop!")
            # if we are generate an onion with our pk as first_pubkey
            generated_onion = onion.generate_new(
                my_pubkey=config.rpc.getinfo()["id"],
                next_pubkey=None,
                amount_msat=amount_msat,
                payment_hash=payment_hash,
                cltv_expiry=cltv_expiry,
            )
            # priv_keys = onion.get_regtest_privkeys([config.my_node])
        else:
            # else generate an onion with ou5r pk as first_hop and next hop pk as
            # second_pubkey
            # TODO: calculate: also subtract config.CLTV_d from cltv_expiry
            logger("INFO: We're not the final hop...")
            generated_onion = onion.generate_new(
                my_pubkey=config.my_node_pubkey,
                next_pubkey=config.next_node_pubkey,
                amount_msat=amount_msat,
                payment_hash=payment_hash,
                cltv_expiry=cltv_expiry - config.CLTV_d,
            )
            logger.debug(f"INFO: Generated onion\n{generated_onion}")
            # priv_keys = onion.get_regtest_privkeys(
            #     [config.my_node, (config.my_node + 1) % 3]
            # )
        # orig_payloads, orig_nexts = onion.decode_onion(
        #     generated_onion, priv_keys, payment_hash.hex(),
        # )
        # logger(f"DEBUG: Generated payloads:{orig_payloads}")

        # add the new onion to original payload
        return orig_payload + generated_onion


def parse(header: bytes, body: bytes, to_mesh: bool, logger) -> Tuple[bytes, bytes]:
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
        logger(f"WARN: Message code not found in ln_msg.codes.keys(): {msg_code}")
        return header, body

    logger(f"INFO: {codes.get(msg_code):<27s} | {len(msg_payload):>4d}B")

    # handle htlc_add_update
    if msg_code == config.ADD_UPDATE_HTLC:
        body = msg_type + parse_update_add_htlc(msg_payload, to_mesh, logger)
        # recompute header based on length of msg without onion
        _header = b""
        _header += struct.pack(">H", len(body))
        _header += struct.pack(">16s", 16 * (bytes.fromhex("00")))
        return _header, body

    return header, body
