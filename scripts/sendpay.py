import pprint
from uuid import uuid4

from lightning import LightningRpc, RpcError


"""
Challenge:
rpc3 generates an invoice and returns details to rpc1. rpc1 then does a sendpay only to
*rpc2*, who, upon not recognising the payment hash will generate an onion which forwards
to rpc3.
"""


rpc1 = LightningRpc("/tmp/l1-regtest/lightning-rpc")
rpc2 = LightningRpc("/tmp/l2-regtest/lightning-rpc")
rpc3 = LightningRpc("/tmp/l3-regtest/lightning-rpc")


# rpc3 adds an invoice and returns the decoded invoice
try:
    inv = rpc3.decodepay(rpc3.invoice(10000, uuid4().hex, uuid4().hex)["bolt11"])
except RpcError:
    raise


# get rpc2 node_id
rpc2_node_id = rpc2.getinfo()["id"]

# rpc1 gets a route to rpc2
try:
    route = rpc1.getroute(
        node_id=rpc2_node_id, msatoshi=inv["msatoshi"], riskfactor=10, cltv=15
    )["route"]
except RpcError:
    raise


# rpc1 does a sendpay to rpc2
try:
    send = rpc1.sendpay(
        route=route,
        payment_hash=inv["payment_hash"],
        description=uuid4().hex,
        msatoshi=inv["msatoshi"],
    )
except RpcError:
    raise

# check status with waitsendpay
try:
    res = rpc1.waitsendpay(payment_hash=inv["payment_hash"], timeout=10)
except RpcError:
    raise

pprint.pprint(res)
