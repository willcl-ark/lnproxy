import io
import logging
import struct

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


def deserialize_type(bytestream: io.BytesIO) -> int:
    """Deserialize the lightning message type
    """
    return struct.unpack_from(be_u16, bytestream.read(2))[0]


def parse_update_add_htlc(bytestream: io.BytesIO, msg_len: int):
    """Parse an update_add_htlc
    """
    if msg_len != 1452:
        return ValueError(f"update_add_htlc length mismatch: 1452 != {msg_len}")
    channel_id = struct.unpack_from(le_32b, bytestream.read(32))[0]
    id = struct.unpack_from(be_u64, bytestream.read(8))[0]
    amount_msat = struct.unpack_from(be_u64, bytestream.read(8))[0]
    payment_hash = struct.unpack_from(le_32b, bytestream.read(32))[0]
    cltv_expiry = struct.unpack_from(be_u32, bytestream.read(4))[0]
    onion = struct.unpack_from(le_onion, bytestream.read(1366))[0]
    logger.debug(f"Channel_id: {channel_id.hex()}")
    logger.debug(f"ID: {id}")
    logger.debug(f"Amount msat: {amount_msat}")
    logger.debug(f"Payment Hash: {payment_hash.hex()}")
    logger.debug(f"CLTV expiry: {cltv_expiry}")
    logger.debug(f"Onion length: {len(onion)}")
    logger.debug(f"Onion hex:\n{onion.hex()}")


def parse_message(msg: bytes, direction: str):
    """Parse a lightning message
    """
    msg_len = len(msg)

    with io.BytesIO(msg) as f:
        msg_type = deserialize_type(f)
        logger.debug(
            "{:>8} | type: {:^3d} | len: {:>4d}B".format(direction, msg_type, msg_len)
        )

        if msg_type == 128:
            parse_update_add_htlc(f, msg_len)
