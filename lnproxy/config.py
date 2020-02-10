import pathlib


# BigSize struct formatting codes
be_u8: str = ">B"
be_u16: str = ">H"
be_u32: str = ">I"
be_u64: str = ">Q"
le_32b: str = "<32s"
le_onion: str = "<1366s"

# Lightning message size constants
ADD_UPDATE_HTLC: int = 128
PING = 18
PONG = 19
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
rpc = None

# Trio
nursery = None
node_info = None
node_secret_key = None
key_sends = {}

# goTenna Mesh
mesh_conn = None
BATCH_DELAY = 3
CHUNK_SIZE = 205
# Modify this sdk_token value
sdk_token = None
# Only for importing a debugging SDK token
try:
    import lnproxy.private as priv
except ModuleNotFoundError:
    pass
else:
    sdk_token = priv.sdk_token
geo_region = 2
# --------------------------------------------------------------------------------------
"""Crypto
"""
nonce = 0xD9B4BEF9 .to_bytes(16, "big")
# --------------------------------------------------------------------------------------
"""Misc
"""
# TODO: These can be calculated on-the-fly from getroute
#   we should hardcode CLTV used for all channel opens and routing fees
#   Remember: CLTV is absolute (from blockheight), CSV is relative!!!
C_FEE: int = 2
CLTV_d: int = 6
