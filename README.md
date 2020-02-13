# Lnproxy

Proxy connections from a patched C-Lightning.

Proxy removes onions before HTLC transmission and dynamically re-generates them upon receipt.

Currently hardcoded values for a 3 node regtest, setup. 

### Requirements

* Python >= 3.7
    
* C-Lightning compiled with noencrypt_final.patch and gossip_disabled_and_300s_HTLC_timeout.patch applied.


### C Lightning installation

Patch C-Lightning with noencrypt patch to disable lightning message encryption. This can either be done by pulling from my branch (recommended), or patching C-Lightning manually using the provided patch. To use the pre-patched branch which is currently based on top ov v0.8.1rc1:

    git clone https://github.com/willcl-ark/lightning.git
    cd lightning
    git checkout mesh

Follow the remaining installation instructions for your OS as found at [install C-Lightning](https://github.com/willcl-ark/lightning/blob/noencrypt-mesh/doc/INSTALL.md)


### Lnproxy installation

Clone and setup:

    git clone https://github.com/willcl-ark/lnproxy.git
    cd lnproxy
    python3 -m venv .venv
    source .venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
    
Next we add our goTenna SDK token and ONION_TOOL path to the config.ini file:

1) Add sdk_token as a string in goTenna section
2) Modify ONION_TOOL path as appropriate to point to your lightning/devtools/onion 
   binary file, e.g:

    `vim config.ini`
        
        
    [goTenna Mesh]
    sdk_token = your_sdk_token_here
    
    [Onion tool path]
    ONION_TOOL = path_to/your_onion/binary_file
    
    
## Regtest Testing

Testing currently uses 4 terminal windows, these could also be screen/tmux sessions if you prefer.

Lnproxy is run by C-Lightning as a plugin, and we need to tell C-Lightning how to find it. Let's export to the shell $PATH_TO_BITCOIN, which should point to the Bitcoin datadir for your OS and $PLUGIN_PATH which should point to lnproxy/plugin/gotenna.py file:

    # e.g. on OSX you might do
    export PATH_TO_BITCOIN="/Users/$USER/Library/Application Support/Bitcoin"
    export PLUGIN_PATH="/Users/$USER/src/lnproxy/plugin/gotenna.py"
    
Change to the C-Lightning directory and source the script:

    # wherever you cloned C-Lightning, e.g.
    cd ~/src/lightning
    source contrib/startup_regtest.sh

You will see printed a list of available commands for later reference. Of note you should remember that it is possible to shutdown all three nodes and bitcoind from a single command, `stop_ln` and cleanup everything with `cleanup_ln`.


## Quick run

Using the helper functions in the c-lightning/contrib/startup_script.sh let you get set up faster. Run in approximately this sequence as necessary:

    start_ln
    connect_ln
    channel_ln
    
After these commands have completed, you can move right onto the [payments](#payments) or [spontaneous sends](#spontaneous-sends) sections below to start making payments.


## Command-by-command

First, we start all 3 lightning nodes with a single helper command:

    start_ln
    
To watch the output logs (via C-Lightning logger) of each node, you can run (each in a separate terminal):

    tail -f /tmp/l1-regtest/log | grep gotenna
    tail -f /tmp/l2-regtest/log | grep gotenna
    tail -f /tmp/l3-regtest/log | grep gotenna

While we wait, lets generate some blocks in Bitcoin Core, as C-Lightning takes some time to register them:

    bt-cli generatetoaddress 101 $(bt-cli getnewaddress "" bech32)
    bt-cli sendtoaddress $(l1-cli newaddr | jq -r '.bech32') 1
    bt-cli sendtoaddress $(l2-cli newaddr | jq -r '.bech32') 1
    bt-cli sendtoaddress $(l3-cli newaddr | jq -r '.bech32') 1
    bt-cli generatetoaddress 6 $(bt-cli getnewaddress "" bech32)
    
Next connect and power on 3 goTenna devices, you should see them connecting in the log messages. Now we can connect the C-Lightning nodes together. In the terminal window where we sourced our helper functions, run the following:

    l1-cli add-node $(l2-cli gid) $(l2-cli getinfo | jq .id)
    l1-cli add-node $(l3-cli gid) $(l3-cli getinfo | jq .id)
    l2-cli add-node $(l1-cli gid) $(l1-cli getinfo | jq .id)
    l2-cli add-node $(l3-cli gid) $(l3-cli getinfo | jq .id)
    l3-cli add-node $(l1-cli gid) $(l1-cli getinfo | jq .id)
    l3-cli add-node $(l2-cli gid) $(l2-cli getinfo | jq .id)

This will add the other nodes to the (plugin) router tables. Next, we can try to connect them together:

    l1-cli proxy-connect $(l2-cli gid)
    l2-cli proxy-connect $(l3-cli gid)

This will connect the three nodes via the proxies, you should see returned two 'ID' fields. Next, we can try to open some channels:

    l1-cli fundchannel $(l2-cli getinfo | jq .id) 5000000 10000 false
    l2-cli fundchannel $(l3-cli getinfo | jq .id) 5000000 10000 false
    # Generate a few blocks to activate the channels
    bt-cli generatetoaddress 6 $(bt-cli getnewaddress "" bech32)
    
If successful, you will see the channel open transaction IDs and also 6 blocks generated to confirm the channels. At this stage, we can switch to the proxy windows and check for errors and also to see which messages have been exchanged between the nodes. We need to wait for `channel_update` to be exchanged between all channels before we can make a payment. 

Whilst we wait for that, we will set the channel fees for all nodes to zero for testing. We use the helper function provided in the c-lightning/contrib/startup_script.sh for this:

    fees_ln 0 0
    
This will recursively set fees on all channels in all directions to zero.

### Payments

Hopefully by now we have send the `channel_update` messages for the channels, if you have, you can try a simple single hop pay:

    l1-cli pay $(l2-cli invoice 500000 $(openssl rand -hex 12) $(openssl rand -hex 12) | jq -r '.bolt11')
    l2-cli pay $(l3-cli invoice 500000 $(openssl rand -hex 12) $(openssl rand -hex 12) | jq -r '.bolt11')

(If you don't have openssl on OSX try `brew install openssl` or just add some random text yourself)

However if you try to pay l3 from l1 using the following you will receive an error: can't find route. This is because the plugin disables C-Lightning gossip at node startup, to limit the number of mesh messages.

    l1-cli pay $(l3-cli invoice 500000 $(openssl rand -hex 12) $(openssl rand -hex 12) | jq -r '.bolt11')

### Spontaneous sends

To attempt a "spontaneous send" mesh payment with encrypted message over one or multiple hops, use the "message" command added to C-Lightning by the plugin:

    # see "l1-cli help message" for help.
    # Single hop version
    l1-cli waitsendpay $(l1-cli message $(l2-cli gid) $(openssl rand -hex 12) 100000 | jq .payment_hash)

or
    
    # Double hop version
    l1-cli waitsendpay $(l1-cli message $(l3-cli gid) $(openssl rand -hex 12) 100000 | jq .payment_hash)
    
The "message" RPC implements a keysend-like functionality: we know about the recipient in our (plugin) routing table, even though C-Lightning doesn't know about them (no gossip exchanged via l2). This means we can send them a message encrypted with their pubkey (using ECIES where nonce=payment_hash[0:16]) and where recipient can decrypt the preimage (sha256(decrypted_message).digest()).

It's this plugin routing table that we want to fully integrate with the underlying goTenna routing table in future work.


# TODOs:


- [ ] Fix first hop routing selection

- [x] Fix bi-directional messaging (add `push_msat` to channel open?)

- [ ] Calculate C_FEE and CLTV_DELTA on the fly from `getroute` rather than hardcoding

- [ ] Integrate routing algorithm with the underlying goTenna routing
    
    
