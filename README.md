# Lnproxy

Proxy connections from a patched C-Lightning.

Removes onions before HTLC transmission and re-generates them upon receipt.

### Requirements
* Python 3.7.x

* C-Lightning compiled with noencrypt.patch applied. The patch can be found in clightning dir of this project


### General preparation

We will be cloning two code repositories, so let's keep things neat. If you already have a source code directory use that, otherwise we will make a new one:

    mkdir ~/src

Now we will clone the two projects:

    # C-Lightning, forked from ElementsProject
    git clone https://github.com/willcl-ark/lightning/tree/noencrypt-mesh
    
    # Lnproxy
    git clone https://github.com/willcl-ark/lnproxy.git
    
Now our home directory has the following structure:

    ~/src
       ├── lightning
       └── lnproxy

Now, we can set the projects up...

### C Lightning preparation

Patch C-Lightning with noencrypt patch to disable lightning message encryption. This can either be done by pulling from my branch (recommended) or patching C-Lightning manually using the provided patch. From my branch that we already cloned:

    cd ~/src/lightning

Follow the remaining installation instructions for your OS as found [install ](https://github.com/willcl-ark/lightning/blob/noencrypt-mesh/doc/INSTALL.md)

### Lnproxy Installation

Switch into the directory, create a new virtual env, activate it and install the package

    cd ~/src/lnproxy
    python3 -m venv .venv
    source .venv/bin/activate
    pip install lnproxy

### Fish shell 

(Optional, but recommended)

I have made a fish shell script in my C-Lightning repo which provides a lot of useful helper functions for regtest environment testing. You can, and I recommend, installing fish shell (but not making it your default shell, yet!) so that you can use them.

On macOS, this is as easy as

    brew install fish

But installation of other platforms is equally easy: [install fish](https://fishshell.com)

        
## Regtest Testing

Testing currently uses 4 terminal windows, these could also be screen/tmux sessions if you prefer. Lets start, but not connect or use the 3 C-Lightning nodes:

    cd ~/src/lightning
    # switch to fish shell
    fish
    source contrib/startup_regtest_fish.sh
    start_ln
    
You will see printed a list of available commands for later reference. We must now start the 3 Lnproxies, one for each node, before connecting the nodes together. In a new terminal window:

    cd ~/src/lnproxy
    source .venv/bin/activate
    python lnproxy/proxy.py 1
    
In the next two terminal windows run the same commands, changing the '1' on the final line to a '2' and a '3' respectively.

Now we can connect the C-Lightning nodes together. In the lightning terminal window, where we ust sourced the fish shell script and ran `start_ln` above, run the following:

    connect_ln_proxy

This will connect the three nodes via the python proxies, you should see returned two 'ID' fields. Next, we can try to open some channels, again the fish shell helper function can do this for us easily:

    channel_ln
    
If successful, you will see the channel open transaction IDs and also 6 blocks generated to confirm the channels. At this stage, we shoudl switch to the proxy windows and check for errors and also to see which messages have been exchanged between the nodes. If al looks good, we can try to me a payment:

    l1_pay_l3 1000000

...will attempt to send 1000000 sat from l1 to l3. We use large values as channel size is set to maximum. Other possible combinations to try initially, whicle the channels are 100% unbalanced, would be:

    l1_pay_l2 1000000
    l2_pay_l3 1000000

Note that, if it can't find funds or a route C-Lightning polls bitcoind periodically for blockchain info, so usually just wait a few moments and try again.

With a few initial payments made, the reverse direction payments are possible.
    
