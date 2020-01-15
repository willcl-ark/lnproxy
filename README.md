# Lnproxy

Proxy connections from a patched C-Lightning.

Proxy removes onions before HTLC transmission and dynamically re-generates them upon receipt.

Currently hardcoded values for a 3 node regtest, setup. 

### Requirements

* Python >= 3.7
    
* C-Lightning compiled with noencrypt_final.patch applied. The patch can be found in clightning dir of this project


### C Lightning installation

Patch C-Lightning with noencrypt patch to disable lightning message encryption. This can either be done by pulling from my branch (recommended), or patching C-Lightning manually using the provided patch. To use the pre-patched branch:

    git clone https://github.com/willcl-ark/lightning.git
    cd lightning
    git checkout noencrypt-mesh

Follow the remaining installation instructions for your OS as found at [install C-Lightning](https://github.com/willcl-ark/lightning/blob/noencrypt-mesh/doc/INSTALL.md)


### Lnproxy installation

Clone and setup:

    git clone https://github.com/willcl-ark/lnproxy.git
    cd lnproxy
    python3 -m venv .venv
    source .venv/bin/activate       # bash shell
    source .venv/bin/activate.fish  # fish shell
    pip install -r requirements.txt
    
Next we add our goTenna SDK token and ONION_TOOL path to the config file:

    vim lnproxy/config.py
    # add sdk_token in goTenna section
    # modify ONION_TOOL path as appropriate
    
    
### (Optional) Fish shell installation

In my C-Lightning branch I have added to the contrib startup scripts a fish shell derivation which provides a lot of extra helper functions for testing lnproxy. You can, and I recommend, installing fish shell (no need to make it your default shell, yet!) so that you can use them.

On macOS, this is as easy as

    brew install fish

But installation of other platforms is equally easy: [install fish](https://fishshell.com)

        
## Regtest Testing

Testing currently uses 4 terminal windows, these could also be screen/tmux sessions if you prefer.

Lnproxy is run by C-Lightning as a plugin, and we need to tell C-Lightning how to find it...

    # wherever you cloned C-Lightning, e.g.
    cd ~/src/lightning
    # switch to fish shell
    fish
    # set the environment variable pointing to the plugin file, fish syntax:
    set path_to_plugin "wherever_you_cloned_lnproxy/plugin/gotenna.py"
    source contrib/startup_regtest_fish.sh

You will see printed a list of available commands for later reference. Of note you should remember that it is possible to shutdown all three nodes and bitcoind from a single command, `stop_ln`.

We can now start all 3 lightning nodes with a single command:

    start_ln
    
To watch the output logs (via C-Lightning logger) of each node, you can run (each in a separate terminal):

    tail -f /tmp/l1-regtest/log | grep gotenna
    tail -f /tmp/l2-regtest/log | grep gotenna
    tail -f /tmp/l3-regtest/log | grep gotenna
    
Next connect and power on 3 goTenna devices, you should see them connecting in the log messages. Now we can connect the C-Lightning nodes together. In the terminal window where we sourced our helper functions, run the following:

    connect_ln_proxy

This will connect the three nodes via the python proxies, you should see returned two 'ID' fields. Next, we can try to open some channels, again the fish shell helper function can do this for us easily:

    channel_ln_priv
    
If successful, you will see the channel open transaction IDs and also 6 blocks generated to confirm the channels. At this stage, we can switch to the proxy windows and check for errors and also to see which messages have been exchanged between the nodes. If all looks good, we can try to me a payment:

    l1_pay_l2

Also you can try:

    l2_pay_l3

However if you try `l1_pay_l3` you will receive an error: can't find route. This is because the plugin disables C-Lightning gossip at node startup, to limit the number of mesh messages.

To attempt a 3-hop mesh payment, run the python script `sendpay.py` found in lnproxy/scripts/sendpay.py.

    
