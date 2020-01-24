import pathlib
import lnproxy.private as priv

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
home = str(pathlib.Path.home())

# Onion tool path
ONION_TOOL: str = f"{home}/src/lightning/devtools/onion"

# Plugin
plugin = None
rpc_s = {1: None, 2: None, 3: None}
rpc = None

# Trio
nursery = None
QUEUE = {}

# Lightning node
# nodes format:
#   nodes:
#       {$gid:
#           {pubkey: None,
#            nonce: itertools.counter(),
#            outbound: None,
#            inbound: None
#           }
#       }
nodes = {}
node_info = None
node_secret_key = None
key_sends = {}
# handle_inbounds is a list of pubkey[:4] for each node_pubkey we have a handle_inbound
# running for
handle_inbounds = []

# goTenna Mesh
mesh_conn = None
SEND_TIMES = []
sdk_token = priv.sdk_token
UBER = True

# TODO: These can be calculated on-the-fly from getroute
#   we should hardcode CLTV used for all channel opens and routing fees
#   Remember: CLTV is absolute (from blockheight), CSV is relative!!!
C_FEE: int = 2
CLTV_d: int = 6
