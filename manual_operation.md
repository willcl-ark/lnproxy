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
lcli add-node <remote_pubkey> <remote_host:remote_port> <listening_port>
```

This will echo a listening TCP port for the added node. If you want to accept an incoming connection from this node, you should direct it to this port.

To make an outbound connection, you can use the `proxy-connect` command. This will internally pass the connection through lnproxy and then make the onward connection to the specified tcp_port:

```bash
lcli proxy-connect <remote_pubkey>
```

You should see returned 'ID' field indicating connection is complete. Next, we can try to open some channels:

```bash
lcli fundchannel <remote_pubkey> <amount> <feerate> false
```

If successful, you will see the channel open transaction ID.  We need to wait for `channel_update` to be exchanged for the channel before we can make a payment.


