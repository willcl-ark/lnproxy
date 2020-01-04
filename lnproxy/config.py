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

# System-agnostic home path generator
home = str(Path.home())
lnproxy_home = f"{home}/.lnproxy"
Path(lnproxy_home).mkdir(parents=True, exist_ok=True)

# Onion tool
ONION_TOOL: str = f"{home}/lnproxy_src/lightning/devtools/onion"

# Plugin
plugin = None
rpc = None
logger = None


def log(msg, level="info"):
    try:
        logger(msg, level=level)
    except TypeError:
        # logger not defined yet by plugin
        print(f"{level.upper()}: {msg}")
    except AttributeError:
        # object doesn't support .split()
        print(f"{level.upper()}: {str(msg)}")


# Trio
nursery = None
trio_token = None
QUEUE = {}
SEND_TIMES = []

# Lightning node pubkey: GID
nodes = {
    "034ba4f511b5441477e346bc0d9602e3f133aae1dc698efc94411b90fb63a037e7": 10000001,
    "03659adf5822a021102e93c1e9a2161d680694435480a47065a0b70e68b90c6bc8": 10000002,
    "03438950f77ee32afd7e3e1ad78b7f349aa905345b005f66fb9c0788eb5a0a68ed": 10000003,
}
node_info = None

# goTenna Mesh
mesh_conn = None
UBER = True

# TODO: These can be calculated on-the-fly from getroute
#   we should hardcode CLTV used for all channel opens and routing fees
#   Remember: CLTV is absolute (from blockheight), CSV is relative!!!
C_FEE: int = 2
CLTV_d: int = 6
