"""USER VALUES SHOULD BE CHANGED IN CONFIG.INI FILE, NOT IN HERE
"""

# User config import
import configparser
import os
from logging import DEBUG, ERROR, INFO, WARNING

user = configparser.ConfigParser()
config_path = os.path.join(
    os.path.abspath(os.path.dirname(__file__)), "..", "config.ini"
)
user.read(config_path)

log_levels = {
    "debug": DEBUG,
    "info": INFO,
    "warning": WARNING,
    "error": ERROR,
}

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
"""Plugin
"""
rpc = None
log_level = log_levels[user["lnproxy"].get("DEBUG_LEVEL").lower()]
log_fmt = "%(name)7s | %(levelname)8s | %(message)s"
# --------------------------------------------------------------------------------------
"""Trio
"""
nursery = None
node_info = None
node_secret_key = None
key_sends = {}
# --------------------------------------------------------------------------------------
"""goTenna
"""
connection = None
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
MAX_GID: int = 0xFFFFFFFFFFFF
router = None
