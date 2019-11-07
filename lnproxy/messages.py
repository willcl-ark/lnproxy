import json
import logging
import struct
import subprocess

"""
byte: an 8-bit byte
u16: a 2 byte unsigned integer
u32: a 4 byte unsigned integer
u64: an 8 byte unsigned integer

tu16: a 0 to 2 byte unsigned integer
tu32: a 0 to 4 byte unsigned integer
tu64: a 0 to 8 byte unsigned integer

chain_hash: a 32-byte chain identifier (see BOLT #0)
channel_id: a 32-byte channel_id (see BOLT #2)
sha256: a 32-byte SHA2-256 hash
signature: a 64-byte bitcoin Elliptic Curve signature
point: a 33-byte Elliptic Curve point (compressed encoding as per SEC 1 standard)
short_channel_id: an 8 byte value identifying a channel (see BOLT #7)

### BigSize ###

uint8(x)                if x < 0xfd
0xfd + be16(uint16(x))  if x < 0x10000
0xfe + be32(uint32(x))  if x < 0x100000000
0xff + be64(x)          otherwise.

"""

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("{:<5}".format("MSG"))

# BigSize struct formatting codes
be_u8 = ">B"
be_u16 = ">H"
be_u32 = ">I"
be_u64 = ">Q"
le_32b = "<32s"
le_onion = "<1366s"

# TODO: Hardcodes to get rid of later
LN_CLI = "/Users/will/src/lightning/cli/lightning-cli"
L2_DIR = "--lightning-dir=/tmp/l2-regtest"
ONION_TOOL = "/Users/will/src/lightning/devtools/onion"


def decode_hop_data(hop_data: hex):
    """Decode a hex encoded legacy 'hop_data' payload
    https://github.com/lightningnetwork/lightning-rfc/blob/master/04-onion-routing.md#legacy-hop_data-payload-format
    """
    short_channel_id = struct.unpack_from(be_u64, hop_data)[0]
    amt_to_forward = struct.unpack_from(be_u64, hop_data, 8)[0]
    outgoing_cltv_value = struct.unpack_from(be_u32, hop_data, 16)[0]
    padding = struct.unpack_from(">12B", hop_data, 20)[0]
    logger.debug(
        f"short_channel_id: {short_channel_id}\n"
        f"amt_to_forward: {amt_to_forward}\n"
        f"outgoing_cltv_value: {outgoing_cltv_value}\n"
        f"padding: {padding}"
    )
    return short_channel_id, amt_to_forward, outgoing_cltv_value


def encode_hop_data(
    short_channel_id: str, amt_to_forward: int, outgoing_cltv_value: int
) -> hex:
    """Encode a legacy 'hop_data' payload
    https://github.com/lightningnetwork/lightning-rfc/blob/master/04-onion-routing.md#legacy-hop_data-payload-format
    """
    hop_data = b""
    hop_data += struct.pack(be_u64, short_channel_id)
    hop_data += struct.pack(be_u64, amt_to_forward)
    hop_data += struct.pack(be_u32, outgoing_cltv_value)
    hop_data += b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    logger.debug(f"Hop data created...\n{hop_data.hex()}")
    return hop_data.hex()


def deserialize_type(msg_type: bytes) -> int:
    """Deserialize the lightning message type
    """
    return struct.unpack(be_u16, msg_type)[0]


def parse_update_add_htlc(msg_payload: bytes, direction: str) -> bytes:
    """Parse an update_add_htlc
    """
    if len(msg_payload) != 1450:
        logger.debug(
            ValueError(
                f"update_add_htlc body length mismatch: 1452 != {len(msg_payload)}"
            )
        )

    channel_id = struct.unpack(le_32b, msg_payload[0:32])[0]
    id = struct.unpack(be_u64, msg_payload[32:40])[0]
    amount_msat = struct.unpack(be_u64, msg_payload[40:48])[0]
    payment_hash = struct.unpack(le_32b, msg_payload[48:80])[0]
    cltv_expiry = struct.unpack(be_u32, msg_payload[80:84])[0]
    onion = struct.unpack(le_onion, msg_payload[84:1450])[0]

    logger.debug(f"Channel_id: {channel_id.hex()}")
    logger.debug(f"ID: {id}")
    logger.debug(f"Amount msat: {amount_msat}")
    logger.debug(f"Payment Hash: {payment_hash.hex()}")
    logger.debug(f"CLTV expiry: {cltv_expiry}")
    logger.debug(f"Orig onion length: {len(onion)}")
    logger.debug(f"Orig onion hex:\n{onion.hex()}")
    logger.debug("Generating new onion...")

    my_node_pubkey = json.loads(
        subprocess.run([LN_CLI, L2_DIR, "getinfo"], capture_output=True).stdout.decode()
    )["id"]

    gen_onion = subprocess.run(
        [
            ONION_TOOL,
            "generate",
            f"{my_node_pubkey}",
            "--assoc-data",
            f"{payment_hash.hex()}",
        ],
        capture_output=True,
    ).stdout.decode()
    gen_onion_bytes = bytes.fromhex(gen_onion)
    logger.debug(f"Generated onion:\n{gen_onion}\n Size: {len(gen_onion_bytes)}")

    modified_payload = msg_payload[0:84]
    modified_payload += struct.pack(le_onion, gen_onion_bytes)

    if direction == "Outbound":
        return modified_payload
    return msg_payload


def parse_message(msg: bytes, direction: str) -> bytes:
    """Parse a lightning message and return it
    """
    msg_type = msg[0:2]
    msg_payload = msg[2:]

    # check the message type
    msg_code = deserialize_type(msg_type)
    logger.debug(
        "{:>8} | type: {:^3d} | len: {:>4d}B".format(
            direction, msg_code, len(msg_payload)
        )
    )

    # handle htlc_updates
    if msg_code == 128:
        return msg_type + parse_update_add_htlc(msg_payload, direction)

    return msg_type + msg_payload
