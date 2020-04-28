# Lnproxy

Proxy connections from a patched C-Lightning.

Removes routing onions (1300B) before HTLC transmission, receiver dynamically re-generates them.


## Requirements

* Python >= 3.7
    
* C-Lightning compiled with `noencrypt_final.patch` and `gossip_disabled_and_300s_HTLC_timeout.patch` applied.

* Optional: [jq](https://stedolan.github.io/jq/download/) for your system (for the helper scripts)

* Build tools (below)

### Build tools

On Debian/Ubuntu the following tools are required to compile C-lightning and lnproxy dependencies:

```bash
sudo apt install -y autoconf automake autotools-dev build-essential \
gettext git libgmp-dev libsodium-dev libsqlite3-dev libtool net-tools \
 pkg-config zlib1g-dev
```

On MacOS a similar toolset will be required, many of the above packages can be installed by the same names using the [Homebrew](https://brew.sh) package manager.

## C-Lightning installation

Clone the C-Lightning branch below. This branch is based off master and includes two plugins by default:

1. Lnproxy (this plugin)
1. [Sauron](https://github.com/lightningd/plugins/tree/master/sauron) (fetches blocks from blockstream.info, no need for bitcoind on testnet)

```bash
git clone https://github.com/willcl-ark/lightning.git
cd lightning
git checkout lnproxy

# Setup and activate a virtualenv for the lightning project
# See [venv](#python3.7-virtual-environments-on-ubuntu/debian) section below for more info

# Install python requirements for C-Lightning and the two plugins
pip install --upgrade pip
pip install lnproxy
pip install -r requirements.txt
pip install -r plugins/sauron/requirements.txt

# Run get-lnproxy.sh script to get the correct version of the plugin from github that matches your pip installed version.
# This is required because pip can't easily install directly into your C-Lightning project plugin directory
. tools/get-lnproxy.sh
```

Follow the remaining compilation instructions for your OS as found at [install C-Lightning](https://github.com/willcl-ark/lightning/blob/lnproxy/doc/INSTALL.md) making sure to follow the `./configure` step using `--enable-developer` flag. We need this flag to disable gossip, minimising bandwidth used. If you've already compiled C-Lightning before on your system, the following sequence will likely work:

```bash
./configure --enable developer && make
```

## Quick run, testnet, single local node:

### Initial setup

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

### Adding a node to connect with

Next we are going to add a node to the lnproxy routing table. We can set some variables to help us:

1. `LISTEN_PORT`: the port *you* will listen for incoming connections from the remote node. Open this port in any firewall you have.
2. `REMOTE_PUBKEY`: the remote node's pubkey

```bash
export LISTEN_PORT="<local_open_port>"

# Let's also export their pubkey for convenience
export REMOTE_PUBKEY="<their_node_pubkey>"  
```

Now we can add the node to the Lnproxy router and make the connection. Nodes added to the router are persisted across restarts and can be removed using the `remove-node` command (or deleting `lightning_dir/router` file):

```bash
# Add a remote node to lnproxy plugin router
l1-cli add-node <remote_pubkey>@<remote_host>:<remote_port> $LISTEN_PORT

# Make a connection to the remote node
l1-cli proxy-connect $REMOTE_PUBKEY
```

### Funding a channel

After successful connection, we can fund a channel in the usual way:

```bash
# Open a private outbound channel with remote node
l1-cli fundchannel id=$REMOTE_PUBKEY amount=100000 feerate=10000 announce=false

# You can check the status of the channel with
l1-cli listfunds
```

### Making a payment

After the channel reaches status `CHANNELD_NORMAL`, we can begin to make a payment, two different payment types shown below:


#### Invoice payment

```bash
# Pay a regular invoice. First obtain a bolt11 invoice out-of-band.
lcli pay <bolt11_invoice>
```

#### Spontaneous sends

To attempt a "spontaneous send" payment with encrypted message, use the "message" command added to C-Lightning by the lnproxy plugin:

```bash
# Create a message to send
export MESSAGE="$(openssl rand -hex 12)"     # Use a random message
# or 
export MESSAGE="write your own message here" # Use your own message

# Send the message + payment
l1-cli message <remote_pubkey> $MESSAGE 10000

# We can monitor the payment using waitsendpay command with the payment_hash returned from running the above command:
l1-cli waitsendpay <payment_hash>
```

The "message" RPC implements a keysend-like functionality: we know about the (final) recipient in our plugin routing table, even though C-Lightning doesn't know about them (no gossip exchanged via l2). This means we can send them a message encrypted with their pubkey (using ECIES where `nonce=payment_hash[0:16]`) and where only recipient can decrypt the preimage `(sha256(decrypted_message).digest())`.

See [encryption.md](encryption.md) for more information on this.

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
    
After these commands have completed, you can move on to the [payments](#invoice-payment) or [spontaneous sends](#spontaneous-sends) sections to start making various payment types.

## Full manual operation

See [manual_operation.md](manual_operation.md) for a more manual approach not utilising the helper scripts.

# Troubleshooting

### Build errors related to `libwally-core` or `jsmn` or `libbacktrace` or `libsodium`

These projects are loaded as git submodules. Sometimes during a clone (with old versions of git?) they are not initialised and updated automatically. This can be done by running:

```bash
git submodule init
git submodule update
```

### Python3.7 virtual environments on Ubuntu/Debian

Default python3 (python3.6) package does not include the required `venv` module by default in Debian or Ubuntu. Therefore installing `python3.7-dev` and `python3.7-venv` packages will still result in failure to create new venvs. The underlying system default `python3` package must also be updated to include the `venv` component.

 Therefore installing python3.7 on Ubuntu/Debian requires:

```bash
# Install python3-venv, then python3.7-dev and python3.7-venv packages 
sudo apt install -y python3-venv python3.7-dev python3.7-venv

# To make a new venv for a project, from the project directory:
python3.7 -m venv venv
source venv/bin/activate
```


# TODO:

* Can be found [here](TODO.md)
    
