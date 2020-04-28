import logging


logger = logging.getLogger("config")

# --------------------------------------------------------------------------------------
"""BigSize struct formatting codes
"""
be_u8: str = ">B"
be_u16: str = ">H"
be_u32: str = ">I"
be_u64: str = ">Q"
le_32b: str = "<32s"
le_onion: str = "<1366s"
# --------------------------------------------------------------------------------------
"""Lightning message constants
"""
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
channel_fee = 10
# --------------------------------------------------------------------------------------
"""Trio
"""
nursery = None
# --------------------------------------------------------------------------------------
"""Crypto
"""
nonce = 0xD9B4BEF9 .to_bytes(16, "big")
# --------------------------------------------------------------------------------------
"""C-Lightning
"""
rpc = None
C_FEE: int = 2
CLTV_d: int = 6
onion_tool_path = None
# --------------------------------------------------------------------------------------
"""Plugin
"""
node_info = None
node_secret_key = None
key_sends = {}
MAX_GID: int = 0xFFFFFFFFFFFF
router = None
router_db = None
gid = None
# How many bytes to use to generate a short_send_id
SEND_ID_LEN = 1
