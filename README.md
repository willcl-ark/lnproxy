# Lnproxy

Proxy connections from a patched C-Lightning.

Proxy removes onions before HTLC transmission and dynamically re-generates them upon receipt.

Currently hardcoded values for a 3 node regtest, setup. 

### Requirements

* Python >= 3.7
    
* C-Lightning compiled with noencrypt_final.patch and gossip_disabled_and_300s_HTLC_timeout.patch applied.


### C Lightning installation

Patch C-Lightning with noencrypt patch to disable lightning message encryption. This can either be done by pulling from my branch (recommended), or patching C-Lightning manually using the provided patch. To use the pre-patched branch:

    git clone https://github.com/willcl-ark/lightning.git
    cd lightning
    git checkout noencrypt-mesh-htlc

Follow the remaining installation instructions for your OS as found at [install C-Lightning](https://github.com/willcl-ark/lightning/blob/noencrypt-mesh/doc/INSTALL.md)


### Lnproxy installation

Clone and setup:

    git clone https://github.com/willcl-ark/lnproxy.git
    cd lnproxy
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
    pip install -e .
    
Next we add our goTenna SDK token and ONION_TOOL path to the config file:

    vim lnproxy/config.py
    # add sdk_token as a string in goTenna section
    # modify ONION_TOOL path as appropriate to point to your devtools/onion binary
    
    
## Regtest Testing

Testing currently uses 4 terminal windows, these could also be screen/tmux sessions if you prefer.

Lnproxy is run by C-Lightning as a plugin, and we need to tell C-Lightning how to find it. Let's export to the shell $PATH_TO_BITCOIN, which should point to the Bitcoin datadir for your OS and $PLUGIN_PATH which should point to lnproxy/plugin/gotenna.py file:

    # e.g. on OSX you might do
    export PATH_TO_BITCOIN="~/Library/Application\ Support/Bitcoin"
    export PLUGIN_PATH="/Users/will/src/lnproxy/plugin/gotenna.py"
    
Change to the right directory and source the script:

    # wherever you cloned C-Lightning, e.g.
    cd ~/src/lightning
    source contrib/startup_regtest.sh

You will see printed a list of available commands for later reference. Of note you should remember that it is possible to shutdown all three nodes and bitcoind from a single command, `stop_ln` and cleanup everything with `cleanup_ln`.

We can now start all 3 lightning nodes with a single command:

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

    l1-cli add-node 1000002 $(l2-cli getinfo | jq .id)
    l1-cli add-node 1000003 $(l3-cli getinfo | jq .id)
    l2-cli add-node 1000001 $(l1-cli getinfo | jq .id)
    l2-cli add-node 1000003 $(l3-cli getinfo | jq .id)
    l3-cli add-node 1000001 $(l1-cli getinfo | jq .id)
    l3-cli add-node 1000002 $(l2-cli getinfo | jq .id)

This will add the other nodes to the (plugin) router tables. Next, we can try to connect them together:

    l1-cli proxy-connect 1000002
    l2-cli proxy-connect 1000003

This will connect the three nodes via the proxies, you should see returned two 'ID' fields. Next, we can try to open some channels:

    l1-cli fundchannel $(l2-cli getinfo | jq .id) 5000000 10000 false
    l2-cli fundchannel $(l3-cli getinfo | jq .id) 5000000 10000 false
    # Generate a few blocks to activate the channels
    bt-cli generatetoaddress 6 $(bt-cli getnewaddress "" bech32)
    
If successful, you will see the channel open transaction IDs and also 6 blocks generated to confirm the channels. At this stage, we can switch to the proxy windows and check for errors and also to see which messages have been exchanged between the nodes. If all looks good, we can try to me a payment:

    l1-cli pay $(l2-cli invoice 500000 $(openssl rand -hex 12) | jq -r '.bolt11')
    l2-cli pay $(l3-cli invoice 500000 $(openssl rand -hex 12) $(openssl rand -hex 12) | jq -r '.bolt11')

(If you don't have openssl on OSX try `brew install openssl` or just add some random text yourself)

However if you try to pay l3 from l1 using the following you will receive an error: can't find route. This is because the plugin disables C-Lightning gossip at node startup, to limit the number of mesh messages.

    l1-cli pay $(l3-cli invoice 500000 $(openssl rand -hex 12) $(openssl rand -hex 12) | jq -r '.bolt11')


To attempt a 3-hop mesh payment, run the python script `sendpay.py` found in lnproxy/scripts/sendpay.py.
This generates an invoice from l3-cli and passes it out of band to l1-cli. However, it demonstrates that l1 can pay l3 even though C-Lightning doesn't know the whole route (it only knows about it's channel to l2). L2 will check the HTLC, find that it's not the final recipient and forward it on to someone _they_ know about, l3, who knows the preimage.

To use the plugin "message" function, use the following (with connected peers and opened channels):

    # see "l1-cli help message" for help.
    l1-cli message 1000002 "Hello, world" 100000

or

    l1-cli message 1000003 "Hello, world2" 100000
    
The "message" RPC implements a keysend-like functionality: we know about the recipient in our (plugin) routing table, even though C-Lightning doesn't know about them (no gossip exchanged via l2). This means we can send them a message encrypted with their pubkey (using ECIES where nonce=payment_hash[0:16]) and where recipient can decrypt the preimage (sha256(decrypted_message).digest()).

It's this plugin routing table that we want to fully integrate with the underlying goTenna routing table in future work.