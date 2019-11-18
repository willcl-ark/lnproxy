import logging
import struct
import subprocess

import lnproxy.config as config
import lnproxy.extract_private_key_from_hsm_secret as extract_pk_from_hsm
import lnproxy.util as util


logging.basicConfig(level=logging.DEBUG)
onion_logger = logging.getLogger(f"{'ONION':<6s}")


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
    onion_logger.debug(
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


def get_regtest_privkeys():
    keys = []
    for node in extract_pk_from_hsm.nodes:
        keys.append(extract_pk_from_hsm.get_privkey(node))
    return keys


def decode_onion(onion_file_path: str, priv_keys: list, assoc_data: str):
    """Takes an ordered list of private keys, an onion and assoc-data (usually payment
    hash) and decodes an onion
    """
    onion_logger.debug("Decoding onion...")
    payloads = []
    nexts = []
    i = 1
    for priv_key in priv_keys:
        _next = ""
        onion_tool = subprocess.run(
            [
                config.ONION_TOOL,
                "decode",
                onion_file_path,
                f"{priv_key}",
                "--assoc-data",
                f"{assoc_data}",
            ],
            capture_output=True,
        )
        if not onion_tool.stderr.decode() == "":
            onion_logger.error(f"Decode Error: {onion_tool.stderr.decode()}")
        onion = onion_tool.stdout.decode()
        # onion_logger.debug(f"Decoded onion: {onion}")

        if "next=" not in onion:
            payload = onion.strip()
        else:
            payload, _next, temp = onion.split("\n")
            temp, _next = _next.split("=")
            # onion_logger.debug(f"_next: {_next}")
        temp, payload = payload.split("=")
        # onion_logger.debug(f"payload: {payload}")
        decode_hop_data(bytes.fromhex(payload), i)
        payloads.append(payload)
        nexts.append(_next)

        if _next:
            with open(onion_file_path, "w") as f:
                f.write(_next)
            i += 1
    return payloads, nexts


def generate_new(
    first_pubkey: hex,
    next_pubkey: hex,
    # pubkeys: list,
    amount_msat: int,
    payment_hash: bytes,
    cltv_expiry: int,
) -> bytes:
    """Generates a new onion with our_pubkey as this hop, and next_pubkey as
    'final hop'
    """
    # # create a hop data for each pubkey
    # hop_data = []
    # if len(pubkeys) > 1:
    #     for pubkey in pubkeys[-1:]:
    #         hop_data.append(encode_hop_data(util.get_next_channel_id(), amount_msat, cltv_expiry).hex())
    # zipped = zip(pubkeys, hop_data)

    # is there is a next_pubkey, we are't the final hop, so add a second_hop!
    if next_pubkey:
        first_hop_id = util.get_next_channel_id()
        first_hop_data = encode_hop_data(first_hop_id, amount_msat, cltv_expiry).hex()
        # Bolt #7: MUST NOT include short_channel_id for the final node.
        next_hop_id = struct.pack(config.be_u64, 0)
        next_hop_data = encode_hop_data(next_hop_id, amount_msat, cltv_expiry).hex()
        onion_logger.debug(
            f"Generating new onion using command:\n'devtools/onion generate "
            f"{first_pubkey}/{first_hop_data} {next_pubkey}/{next_hop_data} --assoc-data "
            f"{payment_hash.hex()}'"
        )
        onion_tool = subprocess.run(
            [
                config.ONION_TOOL,
                "generate",
                f"{first_pubkey}/{first_hop_data}",
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
        onion_logger.debug(
            f"Generating new onion using command:\n'devtools/onion generate "
            f"{first_pubkey}/{first_hop_data} --assoc-data "
            f"{payment_hash.hex()}'"
        )
        onion_tool = subprocess.run(
            [
                config.ONION_TOOL,
                "generate",
                f"{first_pubkey}/{first_hop_data}",
                "--assoc-data",
                f"{payment_hash.hex()}",
            ],
            capture_output=True,
        )
    gen_onion = onion_tool.stdout.decode()

    if onion_tool.stdout == b"":
        onion_logger.error(f"Error from onion tool: {onion_tool.stdout.decode()}")
    gen_onion_bytes = bytes.fromhex(gen_onion)
    onion_logger.debug("Generated onion!")
    onion_logger.debug(f"Onion hex:\n{gen_onion_bytes.hex()}")
    return gen_onion_bytes
