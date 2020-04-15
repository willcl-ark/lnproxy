#!/bin/sh

## Short script to startup two local nodes with
## bitcoind, all running on regtest
## Makes it easier to test things out, by hand.

## Should be called by source since it sets aliases
##
##  First load this file up.
##
##  $ source contrib/startup_regtest_3.sh
##
##  Start up the nodeset
##
##  $ start_ln
##
##  Let's connect the nodes.
##
##  $ l2-cli getinfo | jq .id
##    "02b96b03e42d9126cb5228752c575c628ad09bdb7a138ec5142bbca21e244ddceb"
##  $ l2-cli getinfo | jq .binding[0].port
##    9090
##  $ l1-cli connect 02b96b03e42d9126cb5228752c575c628ad09bdb7a138ec5142bbca21e244ddceb@localhost:9090
##    {
##      "id" : "030b02fc3d043d2d47ae25a9306d98d2abb7fc9bee824e68b8ce75d6d8f09d5eb7"
##    }
##
##  When you're finished, clean up or stop
##
##  $ stop_ln  # stops the services, keeps the aliases
##  $ cleanup_ln # stops and cleans up aliases
##

# Do the Right Thing if we're currently in top of srcdir.
if [ -z "$PATH_TO_LIGHTNING" ] && [ -x cli/lightning-cli ] && [ -x lightningd/lightningd ]; then
	PATH_TO_LIGHTNING=$(pwd)
fi

if [ -z "$PATH_TO_LIGHTNING" ]; then
	# Already installed maybe?  Prints
	# shellcheck disable=SC2039
	type lightning-cli || return
	# shellcheck disable=SC2039
	type lightningd || return
	LCLI=lightning-cli
	LIGHTNINGD=lightningd
else
	LCLI="$PATH_TO_LIGHTNING"/cli/lightning-cli
	LIGHTNINGD="$PATH_TO_LIGHTNING"/lightningd/lightningd
	# This mirrors "type" output above.
	echo lightning-cli is "$LCLI"
	echo lightningd is "$LIGHTNINGD"
fi

if [ -z "$PATH_TO_BITCOIN" ]; then
	if [ -d "$HOME/.bitcoin" ]; then
		PATH_TO_BITCOIN="$HOME/.bitcoin"
	else
		echo "\$PATH_TO_BITCOIN not set to a .bitcoin dir?" >&2
		return
	fi
fi

mkdir -p /tmp/l1-regtest /tmp/l2-regtest /tmp/l3-regtest

# Node one config
cat << EOF > /tmp/l1-regtest/config
network=regtest
daemon
log-level=debug
log-file=/tmp/l1-regtest/log
bind-addr=/tmp/l1-regtest/unix_socket
plugin=$PLUGIN_PATH
gid=253
rescan=5
EOF

cat << EOF > /tmp/l2-regtest/config
network=regtest
daemon
log-level=debug
log-file=/tmp/l2-regtest/log
bind-addr=/tmp/l2-regtest/unix_socket
plugin=$PLUGIN_PATH
gid=254
rescan=5
EOF

cat << EOF > /tmp/l3-regtest/config
network=regtest
daemon
log-level=debug
log-file=/tmp/l3-regtest/log
bind-addr=/tmp/l3-regtest/unix_socket
plugin=$PLUGIN_PATH
gid=255
rescan=5
EOF

alias l1-cli='$LCLI --lightning-dir=/tmp/l1-regtest'
alias l2-cli='$LCLI --lightning-dir=/tmp/l2-regtest'
alias l3-cli='$LCLI --lightning-dir=/tmp/l3-regtest'
alias bt-cli='bitcoin-cli -regtest'
alias l1-log='less /tmp/l1-regtest/log'
alias l2-log='less /tmp/l2-regtest/log'
alias l3-log='less /tmp/l3-regtest/log'

start_ln() {
	# Start bitcoind in the background
	test -f "$PATH_TO_BITCOIN/regtest/bitcoind.pid" || \
		bitcoind -daemon -regtest -txindex -fallbackfee=0.001

	# Wait for it to start.
	while ! bt-cli ping 2> /dev/null; do sleep 1; done

	# Kick it out of initialblockdownload if necessary
	if bt-cli getblockchaininfo | grep -q 'initialblockdownload.*true'; then
		bt-cli generatetoaddress 1 "$(bt-cli getnewaddress)" > /dev/null
	fi

	# Start the lightning nodes
	test -f /tmp/l1-regtest/lightningd-regtest.pid || \
		"$LIGHTNINGD" --lightning-dir=/tmp/l1-regtest
	test  -f /tmp/l2-regtest/lightningd-regtest.pid || \
		"$LIGHTNINGD" --lightning-dir=/tmp/l2-regtest
	test  -f /tmp/l3-regtest/lightningd-regtest.pid || \
		"$LIGHTNINGD" --lightning-dir=/tmp/l3-regtest

	fund_ln

	# Give a hint.
	echo "Commands: l1-cli, l2-cli, l3-cli l[1|2|3]-log, bt-cli, fund_ln, connect_ln, channel_ln, fees_ln, restart_ln, test_msg_ln, stop_ln, cleanup_ln"
}

fund_ln() {
  # Generate 101 blocks to mature a block then send 1 BTC to each lightning node, confirming it with 6 more blocks
  bt-cli generatetoaddress 101 $(bt-cli getnewaddress "" bech32)
  bt-cli sendtoaddress $(l1-cli newaddr | jq -r '.bech32') 1
  bt-cli sendtoaddress $(l2-cli newaddr | jq -r '.bech32') 1
  bt-cli sendtoaddress $(l3-cli newaddr | jq -r '.bech32') 1
  bt-cli generatetoaddress 6 $(bt-cli getnewaddress "" bech32)
}

connect_ln() {
    l1-cli add-node $(l2-cli gid) $(l2-cli getinfo | jq .id)
    l1-cli add-node $(l3-cli gid) $(l3-cli getinfo | jq .id)
    l2-cli add-node $(l1-cli gid) $(l1-cli getinfo | jq .id)
    l2-cli add-node $(l3-cli gid) $(l3-cli getinfo | jq .id)
    l3-cli add-node $(l1-cli gid) $(l1-cli getinfo | jq .id)
    l3-cli add-node $(l2-cli gid) $(l2-cli getinfo | jq .id)

    l1-cli proxy-connect $(l2-cli gid)
    l2-cli proxy-connect $(l3-cli gid)
}

channel_ln() {
  # Open a new channel from l1 to l2 and from l2 to l3 with some proportion pushed to remote
  l1-cli fundchannel id=$(l2-cli getinfo | jq .id) amount=16777215 feerate=10000 announce=false push_msat=6000000000
  l2-cli fundchannel id=$(l3-cli getinfo | jq .id) amount=16777215 feerate=10000 announce=false push_msat=6000000000
  bt-cli generatetoaddress 6 $(bt-cli getnewaddress "" bech32)
  fees_ln 10 0
}

fees_ln() {
  # Set the fees for all channels to zero
  for channel in $(l1-cli listfunds | jq .channels[].peer_id)
    do l1-cli setchannelfee $channel $1 $2
  done
  for channel in $(l2-cli listfunds | jq .channels[].peer_id)
    do l2-cli setchannelfee $channel $1 $2
  done
  for channel in $(l3-cli listfunds | jq .channels[].peer_id)
    do l3-cli setchannelfee $channel $1 $2
  done
}

restart_ln() {
  stop_ln
  sleep 1
  start_ln
  sleep 1
  connect_ln
}

test_msg_ln() {
  l1-cli waitsendpay $(l1-cli message $(l3-cli gid) $(openssl rand -hex 12) 100000 | jq -r '.payment_hash')
}

stop_ln() {
	test ! -f /tmp/l1-regtest/lightningd-regtest.pid || \
		(kill "$(cat /tmp/l1-regtest/lightningd-regtest.pid)"; \
		rm /tmp/l1-regtest/lightningd-regtest.pid)
	test ! -f /tmp/l2-regtest/lightningd-regtest.pid || \
		(kill "$(cat /tmp/l2-regtest/lightningd-regtest.pid)"; \
		rm /tmp/l2-regtest/lightningd-regtest.pid)
	test ! -f /tmp/l3-regtest/lightningd-regtest.pid || \
		(kill "$(cat /tmp/l3-regtest/lightningd-regtest.pid)"; \
		rm /tmp/l3-regtest/lightningd-regtest.pid)
	test ! -f "$PATH_TO_BITCOIN/regtest/bitcoind.pid" || \
		(kill "$(cat "$PATH_TO_BITCOIN/regtest/bitcoind.pid")"; \
		rm "$PATH_TO_BITCOIN/regtest/bitcoind.pid")
	pkill -f $PLUGIN_PATH
}

cleanup_ln() {
	stop_ln
	unalias l1-cli
	unalias l2-cli
	unalias l3-cli
	unalias bt-cli
	unalias l1-log
	unalias l2-log
	unalias l3-log
	unset -f start_ln
	unset -f fund_ln
	unset -f fees_ln
	unset -f connect_ln
	unset -f test_msg_ln
	unset -f restart_ln
	unset -f stop_ln
	rm -Rf /tmp/l1-regtest/
	rm -Rf /tmp/l2-regtest/
	rm -Rf /tmp/l3-regtest/
	rm -Rf "$PATH_TO_BITCOIN/regtest"
	unset -f cleanup_ln
	find /tmp/ -name "[0-9]*" | xargs rm
}