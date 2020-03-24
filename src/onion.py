import logging
import struct
import subprocess

import src.config as config
import src.util as util

logger = util.CustomAdapter(logging.getLogger("onion"), None)


def decode_hop_data(hop_data: bytes, layer=0):
    """Decode a legacy 'hop_data' payload
    https://github.com/lightningnetwork/lightning-rfc/blob/master/04-onion-routing.md#legacy-hop_data-payload-format
    """
    off = 0 if len(hop_data) == 32 else 1
    # Bolt #7: The hop_data format is identified by a single 0x00-byte length, for
    # backward compatibility.
    short_channel_id = struct.unpack_from(config.be_u64, hop_data, 0 + off)[0]
    amt_to_forward = struct.unpack_from(config.be_u64, hop_data, 8 + off)[0]
    outgoing_cltv_value = struct.unpack_from(config.be_u32, hop_data, 16 + off)[0]
    padding = struct.unpack_from("12B", hop_data, 20 + off)[0]
    logger.debug(
        f"Decoded payload layer {layer}:\n"
        f"\tShort channel id: {short_channel_id}\n"
        f"\tAmt to forward: {amt_to_forward}\n"
        f"\tOutgoing CLTV value: {outgoing_cltv_value}\n"
        f"\tPadding: {padding}"
    )
    return short_channel_id, amt_to_forward, outgoing_cltv_value, padding


def encode_hop_data(
    short_channel_id: bytes, amt_to_forward: int, outgoing_cltv_value: int
) -> bytes:
    """Encode a legacy 'hop_data' payload to bytes
    https://github.com/lightningnetwork/lightning-rfc/blob/master/04-onion-routing.md#legacy-hop_data-payload-format
    """
    # Bolt #7: The hop_data format is identified by a single 0x00-byte length, for
    # backward compatibility.
    hop_data = struct.pack(config.be_u8, 0x00)
    hop_data += short_channel_id
    hop_data += struct.pack(config.be_u64, amt_to_forward)
    hop_data += struct.pack(config.be_u32, outgoing_cltv_value)
    # [12*byte:padding]
    hop_data += b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    return hop_data


def generate_new(
    my_pubkey: hex,
    next_pubkey: hex,
    amount_msat: int,
    payment_hash: bytes,
    cltv_expiry: int,
) -> bytes:
    """Generates a new onion with our_pubkey as this hop, and next_pubkey as
    'final hop'
    """
    logger.debug(
        f"my_pubkey: {my_pubkey}, amount_msat: {amount_msat}, "
        f"payment_hash: {payment_hash.hex()}, "
        f"cltv_expiry: {cltv_expiry}"
    )
    # is there is a next_pubkey, we are't the final hop, so add a second_hop!
    if next_pubkey:
        first_hop_chan_id = util.get_short_chan_id(my_pubkey, next_pubkey)
        first_hop_data = encode_hop_data(
            first_hop_chan_id, amount_msat, cltv_expiry
        ).hex()
        # Bolt #7: MUST NOT include short_channel_id for the final node.
        next_hop_id = struct.pack(config.be_u64, 0)
        next_hop_data = encode_hop_data(next_hop_id, amount_msat, cltv_expiry).hex()
        logger.debug(
            f"Generating new onion using command:\n'devtools/onion generate "
            f"{my_pubkey}/{first_hop_data} {next_pubkey}/{next_hop_data} --assoc-data "
            f"{payment_hash.hex()}'"
        )
        onion_tool = subprocess.run(
            [
                config.user["onion"]["ONION_TOOL"],
                "generate",
                f"{my_pubkey}/{first_hop_data}",
                f"{next_pubkey}/{next_hop_data}",
                "--assoc-data",
                f"{payment_hash.hex()}",
            ],
            capture_output=True,
        )
    # else we are the final hop!
    else:
        # Bolt #7: MUST NOT include short_channel_id for the final node.
        first_hop_id = struct.pack(config.be_u64, 0)
        first_hop_data = encode_hop_data(first_hop_id, amount_msat, cltv_expiry).hex()
        onion_tool = subprocess.run(
            [
                config.user["onion"]["ONION_TOOL"],
                "generate",
                f"{my_pubkey}/{first_hop_data}",
                "--assoc-data",
                f"{payment_hash.hex()}",
            ],
            capture_output=True,
        )
    gen_onion = onion_tool.stdout.decode()

    if onion_tool.stdout == b"":
        logger.error(f"Onion tool: {onion_tool.stdout.decode()}")
    gen_onion_bytes = bytes.fromhex(gen_onion)
    logger.debug("Generated onion!")
    # logger.debug(f"Onion hex:\n{gen_onion_bytes.hex()}")
    return gen_onion_bytes
