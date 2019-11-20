# Lnproxy

Proxy connections from a patched C-Lightning.

Proxy removes onions before HTLC transmission and dynamically re-generates them upon receipt.

Currently hardcoded values for a 3 node regtest, setup. 

### Requirements

* Python 3.7.5
    
* [pyenv](https://github.com/pyenv/pyenv) 

* C-Lightning compiled with noencrypt.patch applied. The patch can be found in clightning dir of this project


### General preparation

We will be cloning one or two code repositories, so let's keep things neat. If you already have a source code directory you can use that, but note that some of the temporary hardcodes in lnproxy.config.py might not work properly... To make a new one and set python version for it (and subdirectories):

    mkdir ~/lnproxy_src && cd ~/lnproxy_src
    pyenv install 3.7.5 && pyenv local 3.7.5

Now, we are ready to set the projects up...

### C Lightning preparation

Patch C-Lightning with noencrypt patch to disable lightning message encryption. This can either be done by pulling from my branch (recommended), if you followed above instruction you have already done this, or patching C-Lightning manually using the provided patch. To use the pre-patched branch:

    cd ~/lnproxy_src
    git clone https://github.com/willcl-ark/lightning.git
    cd lightning
    git checkout noencrypt-mesh

Follow the remaining installation instructions for your OS as found at [install C-Lightning](https://github.com/willcl-ark/lightning/blob/noencrypt-mesh/doc/INSTALL.md)

### Lnproxy Installation

We can either clone git repo and install from source, or install via pip.

#### From source

Start by installing the python dependency/package manager poetry (other install methods available, see [website](https://github.com/sdispater/poetry)):

    curl -sSL https://raw.githubusercontent.com/sdispater/poetry/master/get-poetry.py | python

Now we can do main clone and setup:

    cd ~/lnproxy_src
    git clone https://github.com/willcl-ark/lnproxy.git
    cd lnproxy
    python3 -m venv .venv
    source .venv/bin/activate       # bash shell
    source .venv/bin/activate.fish  # fish shell
    poetry install
    

#### Using pip

    mkdir -p ~/lnproxy_src/lnproxy && cd ~/lnproxy_src/lnproxy
    python3 -m venv .venv
    source .venv/bin/activate       # bash shell
    source .venv/bin/activate.fish  # fish shell only
    pip install lnproxy
    
### Fish shell 

(Optional, but recommended)

I have added to the C-Lightning contrib startup script in a fish shell version which provides a lot of useful helper functions for regtest environment testing. You can, and I recommend, installing fish shell (no need to make it your default shell, yet!) so that you can use them.

On macOS, this is as easy as

    brew install fish

But installation of other platforms is equally easy: [install fish](https://fishshell.com)

        
## Regtest Testing

Testing currently uses 4 terminal windows, these could also be screen/tmux sessions if you prefer. Lets start, but not connect or use, the 3 C-Lightning nodes:

    cd ~/lnproxy_src/lightning
    # switch to fish shell
    fish
    source contrib/startup_regtest_fish.sh
    start_ln
    
You will see printed a list of available commands for later reference. Of note you should remember that it is possible to shutdown all three nodes and bitcoind from a single command, `cleanup_ln`.

We can now start the 3 Lnproxies, one for each node, before connecting the nodes together. In a new terminal window (or screen) for each proxy:

    cd ~/lnproxy_src/lnproxy
    poetry shell        # alternatively: `source .venv/bin/activate(.fish)`
    lnproxy 1
    
In the next two terminal windows run the same commands, changing the '1' on the final line to a '2' and a '3' respectively.

Now we can connect the C-Lightning nodes together. In the very first (C-Lightning) terminal window, where we ust sourced the fish shell script and ran `start_ln` above, run the following:

    connect_ln_proxy

This will connect the three nodes via the python proxies, you should see returned two 'ID' fields. Next, we can try to open some channels, again the fish shell helper function can do this for us easily:

    channel_ln
    
If successful, you will see the channel open transaction IDs and also 6 blocks generated to confirm the channels. At this stage, we can switch to the proxy windows and check for errors and also to see which messages have been exchanged between the nodes. If all looks good, we can try to me a payment:

    l1_pay_l3 1000000

...will attempt to send 1000000 sat from l1 to l3. We use large values as channel size is set to maximum. Other possible combinations to try initially, while the channels are 100% unbalanced, would be:

    l1_pay_l2 1000000
    l2_pay_l3 1000000

Note that, if it can't find funds or a route C-Lightning polls bitcoind periodically for blockchain info, so usually just wait a few moments and try again.

With a few initial payments made, the reverse direction payments are possible.

    
