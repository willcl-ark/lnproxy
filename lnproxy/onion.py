import logging
import struct
import subprocess

import config
import util

onion_logger = logging.getLogger(f"{'ONION':<5}")


def decode_hop_data(hop_data: hex):
    """Decode a hex encoded legacy 'hop_data' payload
    https://github.com/lightningnetwork/lightning-rfc/blob/master/04-onion-routing.md#legacy-hop_data-payload-format
    """
    short_channel_id = struct.unpack_from(config.be_u64, hop_data)[0]
    amt_to_forward = struct.unpack_from(config.be_u64, hop_data, 8)[0]
    outgoing_cltv_value = struct.unpack_from(config.be_u32, hop_data, 16)[0]
    padding = struct.unpack_from(">12B", hop_data, 20)[0]
    onion_logger.debug(
        f"Short channel id: {short_channel_id}\n"
        f"Amt to forward: {amt_to_forward}\n"
        f"Outgoing CLTV value: {outgoing_cltv_value}\n"
        f"Padding: {padding}"
    )
    return short_channel_id, amt_to_forward, outgoing_cltv_value


def encode_hop_data(
    short_channel_id: bytes, amt_to_forward: int, outgoing_cltv_value: int
) -> hex:
    """Encode a legacy 'hop_data' payload to hex
    https://github.com/lightningnetwork/lightning-rfc/blob/master/04-onion-routing.md#legacy-hop_data-payload-format
    """
    # Bolt #7: The hop_data format is identified by a single 0x00-byte length, for
    # backward compatibility.
    hop_data = b"\x00"
    hop_data += short_channel_id
    hop_data += struct.pack(config.be_u64, amt_to_forward)
    hop_data += struct.pack(config.be_u32, outgoing_cltv_value)
    # [12*byte:padding]
    hop_data += b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    onion_logger.debug(f"Hop data (hex):\n{hop_data.hex()}")
    return hop_data.hex()


def decode_onion(onion_file_path: str, priv_keys: list, assoc_data: str):
    """Takes an ordered list of private keys, an onion and assoc-data (usually payment
    hash) and decodes an onion
    """
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

        if "next=" not in onion:
            payload, temp = onion.split("\n")
        else:
            payload, _next, temp = onion.split("\n")
            temp, _next = _next.split("=")
            onion_logger.debug(f"_next: {_next}")
        temp, payload = payload.split("=")
        onion_logger.debug(f"payload: {payload}")

        if _next:
            with open(onion_file_path, "w") as f:
                f.write(_next)


def generate_new(
    our_pubkey: hex, next_pubkey: hex, amount_msat: int, payment_hash: hex
) -> bytes:
    """Generates a new onion with our_pubkey as this hop, and next_pubkey as
    'final hop'
    """

    next_channel_id = util.get_next_channel_id()
    next_hop_data = encode_hop_data(next_channel_id, amount_msat, 132)

    final_chan_id = b"\x00\x00\x00\x00\x00\x00\x00\x00"
    final_hop_data = encode_hop_data(final_chan_id, amount_msat, 132)

    onion_logger.debug(
        f"Generating new onion using: 'devtools/onion generate "
        f"{our_pubkey}/{next_hop_data} {next_pubkey}/{final_hop_data} --assoc-data "
        f"{payment_hash.hex()}'"
    )

    onion_tool = subprocess.run(
        [
            config.ONION_TOOL,
            "generate",
            f"{our_pubkey}/{next_hop_data}",
            f"{next_pubkey}/{final_hop_data}",
            "--assoc-data",
            f"{payment_hash.hex()}",
        ],
        capture_output=True,
    )
    gen_onion = onion_tool.stdout.decode()
    if onion_tool.stdout == b"":
        onion_logger.error(f"Error from onion tool: {onion_tool.stdout.decode()}")
    gen_onion_bytes = bytes.fromhex(gen_onion)
    onion_logger.debug(
        f"Generated onion. Length: {len(gen_onion_bytes)}\n" f"Onion:\n{gen_onion}"
    )
    return gen_onion_bytes
