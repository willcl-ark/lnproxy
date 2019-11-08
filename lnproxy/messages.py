import json
import logging
import struct
import subprocess

from lightning_msg_types import MSG_TYPES

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
htlc_logger = logging.getLogger("{:<5}".format("HTLC"))
onion_logger = logging.getLogger("{:<5}".format("ONION"))

# BigSize struct formatting codes
be_u8 = ">B"
be_u16 = ">H"
be_u32 = ">I"
be_u64 = ">Q"
le_32b = "<32s"
le_onion = "<1366s"

#####################################
# TODO: Hardcodes to get rid of later
LN_CLI = "/Users/will/src/lightning/cli/lightning-cli"
L2_DIR = "--lightning-dir=/tmp/l2-regtest"
ONION_TOOL = "/Users/will/src/lightning/devtools/onion"
ADD_UPDATE_HTLC = 128


def get_recv_pk():
    return json.loads(
        subprocess.run([LN_CLI, L2_DIR, "getinfo"], capture_output=True).stdout.decode()
    )["id"]


#####################################


def decode_hop_data(hop_data: hex):
    """Decode a hex encoded legacy 'hop_data' payload
    https://github.com/lightningnetwork/lightning-rfc/blob/master/04-onion-routing.md#legacy-hop_data-payload-format
    """
    short_channel_id = struct.unpack_from(be_u64, hop_data)[0]
    amt_to_forward = struct.unpack_from(be_u64, hop_data, 8)[0]
    outgoing_cltv_value = struct.unpack_from(be_u32, hop_data, 16)[0]
    padding = struct.unpack_from(">12B", hop_data, 20)[0]
    onion_logger.debug(
        f"short_channel_id: {short_channel_id}\n"
        f"amt_to_forward: {amt_to_forward}\n"
        f"outgoing_cltv_value: {outgoing_cltv_value}\n"
        f"padding: {padding}"
    )
    return short_channel_id, amt_to_forward, outgoing_cltv_value


def encode_hop_data(
    short_channel_id: hex, amt_to_forward: int, outgoing_cltv_value: int
) -> hex:
    """Encode a legacy 'hop_data' payload to hex
    https://github.com/lightningnetwork/lightning-rfc/blob/master/04-onion-routing.md#legacy-hop_data-payload-format
    """
    # Bolt #7: The hop_data format is identified by a single 0x00-byte length, for
    # backward compatibility.
    hop_data = b"\x00"
    hop_data += struct.pack(be_u64, short_channel_id)
    hop_data += struct.pack(be_u64, amt_to_forward)
    hop_data += struct.pack(be_u32, outgoing_cltv_value)
    # [12*byte:padding]
    hop_data += b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    onion_logger.debug(f"Encoded hop data:\n{hop_data.hex()}")
    return hop_data.hex()


def deserialize_type(msg_type: bytes) -> int:
    """Deserialize the lightning message type
    """
    return struct.unpack(be_u16, msg_type)[0]


def generate_new_onion(node_pubkey: hex, amount_msat: int, payment_hash: hex) -> bytes:
    final_chan_id = 0x0000000000000000
    hop_data = encode_hop_data(final_chan_id, amount_msat, 132)

    onion_logger.debug(
        "Generating new onion using: 'devtools/onion generate {node_pubkey}/{hop_data} "
        "--assoc-data {payment_hash.hex()}'"
    )

    onion_process = subprocess.run(
        [
            ONION_TOOL,
            "generate",
            f"{node_pubkey}/{hop_data}",
            "--assoc-data",
            f"{payment_hash.hex()}",
        ],
        capture_output=True,
    )
    gen_onion = onion_process.stdout.decode()
    gen_onion_bytes = bytes.fromhex(gen_onion)
    onion_logger.debug(f"Generated onion! Size: {len(gen_onion_bytes)}")
    return gen_onion_bytes


def parse_update_add_htlc(orig_payload: bytes, direction: str) -> bytes:
    """Parse an update_add_htlc
    """
    # decode the htlc
    channel_id = struct.unpack(le_32b, orig_payload[0:32])[0]
    _id = struct.unpack(be_u64, orig_payload[32:40])[0]
    amount_msat = struct.unpack(be_u64, orig_payload[40:48])[0]
    payment_hash = struct.unpack(le_32b, orig_payload[48:80])[0]
    cltv_expiry = struct.unpack(be_u32, orig_payload[80:84])[0]
    onion = struct.unpack(le_onion, orig_payload[84:1450])[0]

    htlc_logger.debug(f"Channel_id: {channel_id.hex()}")
    htlc_logger.debug(f"ID: {_id}")
    htlc_logger.debug(f"Amount msat: {amount_msat}")
    htlc_logger.debug(f"Payment Hash: {payment_hash.hex()}")
    htlc_logger.debug(f"CLTV expiry: {cltv_expiry}")
    htlc_logger.debug(f"Onion length: {len(onion)}")

    # when sending out over the wire
    if direction == "Inbound":
        # chop off the onion
        return orig_payload[0:84]

    # when receiving from the wire
    if direction == "Outbound":
        # generate a new onion
        generated_onion = generate_new_onion(get_recv_pk(), amount_msat, payment_hash)
        modified_payload = orig_payload[0:84]
        modified_payload += struct.pack(le_onion, generated_onion)
        return modified_payload


def parse_message(msg: bytes, direction: str) -> bytes:
    """Parse a lightning message and return it
    """
    msg_type = msg[0:2]
    msg_payload = msg[2:]

    # check the message type
    msg_code = deserialize_type(msg_type)
    # only print messages once as we share a single proxy for testing
    if direction == "Outbound":
        logger.debug(
            "{:26s} | {:>4d}B".format(MSG_TYPES.get(msg_code), len(msg_payload))
        )

    # handle htlc_updates receiver
    if msg_code == ADD_UPDATE_HTLC:
        return msg_type + parse_update_add_htlc(msg_payload, direction)

    return msg_type + msg_payload
