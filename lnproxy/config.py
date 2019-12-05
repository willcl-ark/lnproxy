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

import logging
from pathlib import Path


# BigSize struct formatting codes
be_u8: str = ">B"
be_u16: str = ">H"
be_u32: str = ">I"
be_u64: str = ">Q"
le_32b: str = "<32s"
le_onion: str = "<1366s"

home = str(Path.home())
lnproxy_home = f"{home}/.lnproxy"
Path(lnproxy_home).mkdir(parents=True, exist_ok=True)


# setup logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s.%(msecs)03d | %(name)6s | %(levelname)7s | %(message)s",
    datefmt="%m-%d %H:%M:%S",
    filename=f"{lnproxy_home}/proxy.log",
    filemode="w",
)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter(
    fmt="%(asctime)s.%(msecs)03d | %(name)6s | %(levelname)7s | %(message)s",
    datefmt="%H:%M:%S",
)
console.setFormatter(formatter)
logging.getLogger("").addHandler(console)

# set up memory channels between trio and mesh connections
# shared between all socket connections
# send_to_mesh, receive_from_server = trio.open_memory_channel(50)
# send_to_server, receive_from_mesh = trio.open_memory_channel(50)

#####################################
# TODO: Hardcodes to get rid of later
NODE_DIR = {
    0: "/tmp/l1-regtest",
    1: "/tmp/l2-regtest",
    2: "/tmp/l3-regtest",
}
ONION_TOOL: str = f"{home}/lnproxy_src/lightning/devtools/onion"
rpc = None
ADD_UPDATE_HTLC: int = 128
# TODO: These can be calculated on-the-fly from getroute
#   we should hardcode CLTV used for all channel opens and routing fees
#   Remember: CLTV is absolute (from blockheight), CSV is relative!!!
C_FEE: int = 2
CLTV_d: int = 6
my_node: int = 0
my_node_dir: str = ""
my_node_pubkey: str = ""
next_node_pubkey: str = ""
network = "regtest"
remote_listen_SOCK: str = ""
local_listen_SOCK: str = ""
local_node_addr: str = ""
remote_node_addr: str = ""
#####################################
