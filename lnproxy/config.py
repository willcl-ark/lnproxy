from pathlib import Path

# BigSize struct formatting codes
be_u8: str = ">B"
be_u16: str = ">H"
be_u32: str = ">I"
be_u64: str = ">Q"
le_32b: str = "<32s"
le_onion: str = "<1366s"

# Lightning message size constants
ADD_UPDATE_HTLC: int = 128
MAX_PKT_LEN: int = 65569
MSG_LEN: int = 2
MSG_LEN_MAC: int = 16
MSG_HEADER: int = MSG_LEN + MSG_LEN_MAC
MSG_TYPE: int = 2
ONION_SIZE: int = 1366
MSG_MAC: int = 16

# System-agnostic home-path generator
home = str(Path.home())
lnproxy_home = f"{home}/.lnproxy"
Path(lnproxy_home).mkdir(parents=True, exist_ok=True)

# Onion tool path
ONION_TOOL: str = f"{home}/src/lightning/devtools/onion"

# Plugin
plugin = None
rpc_s = {1: None, 2: None, 3: None}
rpc = None
logger = None

# Trio
nursery = None
trio_token = None
QUEUE = {}

# Lightning node pubkey: GID
nodes = {
    "02492bb1fb0eca426af73c189d115fcda79fa9a2f77783e8d9bda4c64e5716af94": 10000001,
    "03512298acad7fb9b6d2a8096cfe231ead64ae81cc29c78e23329f745d633a5590": 10000002,
    "026e962239a803c0f005751e60ac1e09772fcce206d0a1b666319423017142d879": 10000003,
}
node_info = None

# goTenna Mesh
mesh_conn = None
SEND_TIMES = []
UBER = True

# TODO: These can be calculated on-the-fly from getroute
#   we should hardcode CLTV used for all channel opens and routing fees
#   Remember: CLTV is absolute (from blockheight), CSV is relative!!!
C_FEE: int = 2
CLTV_d: int = 6
