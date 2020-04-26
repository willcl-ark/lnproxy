# Lnproxy

Proxy connections from a patched C-Lightning.

Proxy removes onion (1300B) before HTLC transmission and receiver dynamically re-generates them upon receipt.


### Requirements

* Python >= 3.7
    
* C-Lightning compiled with `noencrypt_final.patch` and `gossip_disabled_and_300s_HTLC_timeout.patch` applied.

* [jq](https://stedolan.github.io/jq/download/) for your system (for the helper scripts)


### libsecp256k1 installation

First install libsecp256k1 from source as per the [project installation instructions](https://github.com/bitcoin-core/secp256k1)

On Debian? See this [comment](https://github.com/ludbb/secp256k1-py/issues/24#issuecomment-397505150) on issue 24.

### C Lightning installation

Clone the C-Lightning branch below. This branch includes two plugins by default:

1. Lnproxy (this plugin)
1. [Sauron](https://github.com/lightningd/plugins/tree/master/sauron) (fetches blocks from blockstream.info, no need for bitcoind on testnet)

```bash
git clone https://github.com/willcl-ark/lightning.git
cd lightning
git checkout lnproxy

# Setup and activate a virtualenv for the lightning branch (with e.g. pyenv) and install lnproxy and C-lightning requirements
pip install --upgrade pip
pip install lnproxy
pip install -r requirements.txt
pip install -r plugins/sauron/requirements.txt

# Next run get-lnproxy.sh script to get the correct version of the plugin for your pip install
. tools/get-lnproxy.sh
```

Follow the remaining compilation instructions for your OS as found at [install C-Lightning](https://github.com/willcl-ark/lightning/blob/lnproxy/doc/INSTALL.md) making sure to follow the `./configure` step using `--enable-developer` flag. We need this flag to disable gossip, minimising bandwidth used. If you've already compiled C-Lightning before on your system, this will likely be enough:

```bash
./configure --enable developer && make
```

## Quick run, testnet, single local node:

```bash
# Let's start by sourcing the helper scripts
source contrib/startup_testnet1.sh

# Start up C-Lightning
start_ln

# You can tail the logs in a second terminal window with
tail -f -n 50 /tmp/l1-testnet/log | cut -c26-

# Fund the wallet as usual, e.g.:
l1-cli newaddr
# Send tBTC to the address
```

Next we are going to add a node to the lnproxy routing table. We can set some variables to help us:

1. `LISTEN_PORT`: the port *you* will listen for incoming connections from the remote node. Open this port in any firewall you have.
2. `REMOTE_PUBKEY`: the remote node's pubkey

```bash
export LISTEN_PORT="<local_open_port>"

# Let's also export their pubkey for convenience
export REMOTE_PUBKEY="<their_node_pubkey>"  
```

Now we can add the node to the Lnproxy router and make the connection:

```bash
# Add a remote node to lnproxy plugin router
l1-cli add-node <remote_pubkey>@<remote_host>:<remote_port> $LISTEN_PORT

# Make a connection to the remote node
l1-cli proxy-connect $REMOTE_PUBKEY
```

After successful connection, we can fund a channel in the usual way:

```bash
# Open a private outbound channel with remote node
l1-cli fundchannel id=$REMOTE_PUBKEY amount=100000 feerate=10000 announce=false

# You can check the status of the channel with
l1-cli listfunds
```

After the channel reaches status `CHANNELD_NORMAL`, we can begin to make a payment, two different payment types shown below:

```bash
# Pay a regular invoice without transmitting onion
# First obtain a bolt11 invoice out-of-band
l1-cli pay <bolt11_invoice>

# Send a "message"/spontaneous payment/sphinx-send to remote node
l1-cli waitsendpay $(l1-cli message $REMOTE_PUBKEY "<your_message_goes_here>" 100000 | jq -r '.payment_hash')
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

l1-cli proxy-connect $(l2-cli getinfo | jq -r .id)
```

The connection should occur automatically from here, you will need to fund the wallet and open a channel as normal.
    
After these commands have completed, you can move right onto the [payments](#invoice-payment) or [spontaneous sends](#spontaneous-sends) sections below to start making payments.


## Manual mode

See [manual_operation.md](manual_operation.md) for a more manual approach.


## Invoice payment

Now we have seen the `channel_update` messages for the channel, if you have, you can try a simple single hop pay:

```bash
# First get a BOLT11 invoice from the remote node...
lcli pay <bolt11_invoice>
```

## Spontaneous sends

To attempt a "spontaneous send" payment with encrypted message, use the "message" command added to C-Lightning by the lnproxy plugin:

```bash
# First lets generate a 12 digit random hex message which we'll use as the message to send
export MESSAGE="$(openssl rand -hex 12)"

# Using waitsendpay will wait synchronously until payment succeeds or fails
lcli waitsendpay $(lcli message <remote_pubkey> $MESSAGE 100000 | jq -r .payment_hash)
```

The "message" RPC implements a keysend-like functionality: we know about the (final) recipient in our plugin routing table, even though C-Lightning doesn't know about them (no gossip exchanged via l2). This means we can send them a message encrypted with their pubkey (using ECIES where `nonce=payment_hash[0:16]`) and where only recipient can decrypt the preimage `(sha256(decrypted_message).digest())`.

See [encryption.md](encryption.md) for more information on this.


# Troubleshooting

* There are some currently known issues with running on Debian via Qubes OS, so currently this OS config is not supported.

## TODO:

Can be found [here](TODO.md)
    
