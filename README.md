# Lnproxy

Proxy connections from a patched C-Lightning.

Proxy removes onion (1300B) before HTLC transmission and receiver dynamically re-generates them upon receipt.


### Requirements

* Python >= 3.7
    
* C-Lightning compiled with `noencrypt_final.patch` and `gossip_disabled_and_300s_HTLC_timeout.patch` applied.

* [jq](https://stedolan.github.io/jq/download/) for your system


### libsecp256k1 installation

First install libsecp256k1 from source as per the [project installation instructions](https://github.com/bitcoin-core/secp256k1)

### C Lightning installation

Clone my lightning branch which includes this repo as a subtree inside the default "plugins" directory:

```bash
git clone https://github.com/willcl-ark/lightning.git
cd lightning
git checkout mesh-plugin

# Setup and activate a virtualenv for this project (e.g. pyenv) and install requirements
pip install -r requirements.txt
pip install -r plugins/sauron/requirements.txt
pip install -r plugins/lnproxy/requirements.txt
```

Follow the remaining compilation instructions for your OS as found at [install C-Lightning](https://github.com/willcl-ark/lightning/blob/mesh-plugin/doc/INSTALL.md)

This branch includes two plugins by default:

1. Lnproxy (this plugin)
1. [Sauron](https://github.com/lightningd/plugins/tree/master/sauron) (fetches blocks from blockstream.info, no need for bitcoind)

## Quick run, testnet, single local node:

Source the helper functions from `path_to/lightning/contrib/startup_testnet1.sh`.

```bash
# Lets export the GID we'll use for ourselves (in range 1 < x < 255)
export GID="111"

# Now we'll source the helper scripts
source path/to/lightning/contrib/startup_testnet1.sh

# Start up C-Lightning
start_ln

# Lets set some remote node variables to help us later
export REMOTE_GID="<gid>"
export REMOTE_PUBKEY="<pubkey>"
export REMOTE_ADDRESS="<host>:<port>"
# LISTEN_PORT specifies which port Lnproxy will listen on for new 
# incoming connections for this node, separate to the C-Lightning
# listening port
export LISTEN_PORT="<listening port>"

# Fund the wallet as usual, e.g.:
l1-cli newaddr
# Send tBTC to the address

# Add a remote node to lnproxy plugin router
l1-cli add-node $REMOTE_GID $REMOTE_PUBKEY $REMOTE_ADDRESS $LISTEN_PORT

# Make a connection to the remote node
l1-cli proxy-connect $REMOTE_GID

# Open a private outbound channel with remote node
l1-cli fundchannel id=$REMOTE_PUBKEY amount=100000 feerate=10000 announce=false

# Pay a regular invoice without onion
l1-cli pay <bolt11_invoice_from_remote_node>

# Send a "message"/spontaneous payment to remote node
l1-cli waitsendpay $(l1-cli message $REMOTE_GID $(openssl rand -hex 12) 100000 | jq -r '.payment_hash')
```

## Quick run, testnet, two local nodes:

Using the helper functions in the `~/src/lightning/contrib/startup_testnet2.sh` let you get set up faster. Run in approximately this sequence as necessary:

```bash
# Start 2x C-Lightning
start_ln

# Add each node to the other node's router
add_nodes
```

The `add_nodes` command will echo the listening port that the remote node (or radio device e.g. fldigi-proxy) should connect in to to make an inbound connection

To make an outbound connection from node 1, use the `proxy-connect` command with the port your transport connection is listening on, e.g.:

```bash
# Now begin outbound connection from l1 to l2. If you are using alternative transport (e.g. fldigi), use the fldigi listening tcp_port

l1-cli proxy-connect $(l2-cli gid)
```

The connection should occur automatically from here, you will need to fund the wallet and open a channel as normal.
    
After these commands have completed, you can move right onto the [payments](#invoice-payment) or [spontaneous sends](#spontaneous-sends) sections below to start making payments.


## Manual mode

### Background

These plugins require the following C-Lightning options to be specified either as command line flag or in the config file:

```text
gid=123
onion-tool-path=~/src/lightning/devtools/onion
disable-plugin=bcli
sauron-api-endpoint=https://blockstream.info/testnet/api"
```

An example testnet config file might therefore look like this:

```text
network=testnet
daemon
log-level=debug
log-file=/tmp/l1-testnet/log
rescan=5

# lnproxy config
onion-tool-path=~/src/lightning/devtools/onion
gid=123

# sauron config
disable-plugin=bcli
sauron-api-endpoint=https://blockstream.info/testnet/api
```

You can specify your config file by placing it in a folder, and starting lightning using:

`lightningd/lightningd --lightning-dir=path/to/config/directory/`

When you start lightning, new commands added by the plugins will be displayed.

### Startup 

First, lets setup an alias for cli/lightning-cli:

```bash
# from within the lightning directory:
export lcli="$(PWD)/cli/lightning-cli" 
```

we start the lightning node:

```bash
lightningd/lightningd  --lightning-dir=/path/to/config_dir
```
    
To watch the plugin logs (via C-Lightning logger) you can run:

```bash
tail -f /path/to/config_dir/log
```

Next we need to add the node gid:pubkey pair of any node we will connect to into the plugin router, e.g.:

```bash
lcli add-node <remote_gid> <remote_pubkey> <remote_host:remote_port> <listening_port>
```

This will echo a listening TCP port for the added node. If you want to accept an incoming connection from this node, you should direct it to this port.

To make an outbound connection, you can use the `proxy-connect` command. This will internally pass the connection through lnproxy and then make the onward connection to the specified tcp_port:

```bash
lcli proxy-connect <remote_GID>
```

You should see returned 'ID' field indicating connection is complete. Next, we can try to open some channels:

```bash
lcli fundchannel <remote_pubkey> <amount> <feerate> false
```
    
If successful, you will see the channel open transaction ID.  We need to wait for `channel_update` to be exchanged for the channel before we can make a payment. 

### Invoice payment

Now we have seen the `channel_update` messages for the channel, if you have, you can try a simple single hop pay:

```bash
# First get a BOLT11 invoice from the remote node...
lcli pay <bolt11_invoice>
```

### Spontaneous sends

To attempt a "spontaneous send" payment with encrypted message, use the "message" command added to C-Lightning by the lnproxy plugin:

```bash
# First lets generate a 12 digit random hex message which we'll use as the message to send
export MESSAGE="$(openssl rand -hex 12)"

# Using waitsendpay will wait synchronously until payment succeeds or fails
lcli waitsendpay $(lcli message <remote_gid> $MESSAGE 100000 | jq .payment_hash)
```

The "message" RPC implements a keysend-like functionality: we know about the recipient in our (plugin) routing table, even though C-Lightning doesn't know about them (no gossip exchanged via l2). This means we can send them a message encrypted with their pubkey (using ECIES where nonce=payment_hash[0:16]) and where only recipient can decrypt the preimage (sha256(decrypted_message).digest()).


# Troubleshooting

* There are some currently known issues with running on Debian via Qubes OS, so currently this OS config is not supported.

# TODOs:


- [ ] Fix first hop routing selection

- [x] Fix bi-directional messaging (add `push_msat` to channel open)

- [ ] Calculate C_FEE and CLTV_DELTA on the fly from `getroute` rather than hardcoding

- [ ] Integrate routing algorithm with the underlying goTenna routing
    
    
