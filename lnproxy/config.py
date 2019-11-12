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

# BigSize struct formatting codes
be_u8: str = ">B"
be_u16: str = ">H"
be_u32: str = ">I"
be_u64: str = ">Q"
le_32b: str = "<32s"
le_onion: str = "<1366s"

#####################################
# TODO: Hardcodes to get rid of later
LN_CLI: str = "/Users/will/src/lightning/cli/lightning-cli"
L2_DIR: str = "--lightning-dir=/tmp/l2-regtest"
L3_DIR: str = "--lightning-dir=/tmp/l3-regtest"
ONION_TOOL: str = "/Users/will/src/lightning/devtools/onion"
onion_temp_file: str = "/Users/will/src/lnproxy/onion.dat"
ADD_UPDATE_HTLC: int = 128
C_FEE: int = 11
#####################################
