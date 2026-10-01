#!/usr/bin/env bash
# demo-regtest.sh runs Canary's v1 demo end to end on a real local regtest node.
#
# It starts a throwaway bitcoind, makes five taproot payments in one block, and
# runs two reference indexers against it: an honest one, and one told to
# withhold the 1 BTC payment's entry while still signing it into the block's
# record. Then it runs canary check, canary verify and canary status.
#
# Usage: scripts/demo-regtest.sh [--act5] [OUTPUT_DIR]
#        scripts/demo-regtest.sh --help
#
# --act5 adds the demo's last act, a block that can't be checked. Before the
# main payment it makes an early payment and mines 150 blocks, so that block
# ends up past the 144-block window. The withholding indexer leaves both
# payments out. A second canary check then covers the early block alone,
# with only the withholder pinned and nothing declared. Nobody can supply the
# entry, so the block reads Can't be checked, reason gap_unfilled. That is
# neither a pass nor an accusation. The main check runs unchanged, and still
# names the withholder for the main payment.
#
# OUTPUT_DIR defaults to ./demo-out. It must be empty or not exist yet. The
# state file, the evidence file, the indexer logs and each command's output go
# there. The script creates it only once bitcoind is up, so a run that fails to
# build or start leaves nothing behind and can simply be run again. Everything
# else lives in a temporary directory that is removed on exit, including both
# indexers' secret keys.
#
# Needs Bitcoin Core v30 or later (brew install bitcoin), Go and curl.
#
# Environment, all optional:
#   BITCOIND, BITCOIN_CLI          the Bitcoin Core programs to run
#   CANARY_DEMO_RPC_PORT           bitcoind RPC and REST port (default 28443)
#   CANARY_DEMO_P2P_PORT           bitcoind P2P port, bound to 127.0.0.1 (default 28444)
#   CANARY_DEMO_HONEST_PORT        the honest indexer's port (default 28481)
#   CANARY_DEMO_WITHHOLDER_PORT    the withholding indexer's port (default 28482)
#   CANARY_DEMO_WAIT_SECONDS       how long to wait for each server (default 120)
set -euo pipefail

BITCOIND=${BITCOIND:-bitcoind}
BITCOIN_CLI=${BITCOIN_CLI:-bitcoin-cli}
RPC_PORT=${CANARY_DEMO_RPC_PORT:-28443}
P2P_PORT=${CANARY_DEMO_P2P_PORT:-28444}
HONEST_PORT=${CANARY_DEMO_HONEST_PORT:-28481}
WITHHOLDER_PORT=${CANARY_DEMO_WITHHOLDER_PORT:-28482}
WAIT_SECONDS=${CANARY_DEMO_WAIT_SECONDS:-120}

# The retention window is 144 blocks. The withholder is named only while the
# payment's block sits inside it, so the demo mines one block after the
# payment and never 144 or more.
RETENTION_WINDOW=144

# With --act5, the early payment's block ends up this many blocks below the
# tip: 149 blocks after it, then the main payment's block.
ACT5_DEPTH=150

USAGE="Usage: scripts/demo-regtest.sh [--act5] [OUTPUT_DIR]"

# print_help prints the comment block at the top of this file, from the first
# line after the shebang to the line before set -euo pipefail.
print_help() {
	sed -n '2,/^set -euo pipefail$/{
/^#/s/^# \{0,1\}//p
}' "${BASH_SOURCE[0]}"
}

# Set as the run goes. The cleanup reads them, so each starts empty.
TMP=""
BITCOIND_PID=""
HONEST_PID=""
WITHHOLDER_PID=""

step() { printf '\n==> %s\n' "$*"; }
say() { printf '    %s\n' "$*"; }
fail() {
	printf '\ndemo-regtest: %s\n' "$*" >&2
	exit 1
}

# stop_pid sends SIGTERM to a process, waits up to 10 seconds for it to
# exit, and then kills it.
stop_pid() {
	local pid=$1 i
	[ -n "$pid" ] || return 0
	kill "$pid" 2>/dev/null || return 0
	for ((i = 0; i < 40; i++)); do
		kill -0 "$pid" 2>/dev/null || break
		sleep 0.25
	done
	kill -9 "$pid" 2>/dev/null || true
	wait "$pid" 2>/dev/null || true
}

# cleanup stops the indexers and bitcoind and removes the temporary
# directory. It keeps the output directory.
cleanup() {
	local status=$? i
	set +e
	if [ -n "$HONEST_PID$WITHHOLDER_PID$BITCOIND_PID" ]; then
		step "Stopping the indexers and bitcoind"
	fi
	stop_pid "$HONEST_PID"
	stop_pid "$WITHHOLDER_PID"
	if [ -n "$BITCOIND_PID" ] && kill -0 "$BITCOIND_PID" 2>/dev/null; then
		cli stop >/dev/null 2>&1
		for ((i = 0; i < 120; i++)); do
			kill -0 "$BITCOIND_PID" 2>/dev/null || break
			sleep 0.5
		done
		stop_pid "$BITCOIND_PID"
	fi
	case $TMP in
	*/canary-demo.*) rm -rf "$TMP" ;;
	esac
	exit "$status"
}

cli() {
	"$BITCOIN_CLI" -regtest -datadir="$TMP/bitcoin" -rpcport="$RPC_PORT" "$@"
}

wallet() {
	cli -rpcwallet=demo "$@"
}

# port_in_use reports whether something on this computer accepts connections
# on the port.
port_in_use() {
	(exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
}

# npub_to_hex decodes a Nostr npub into the 64 hex characters canary check
# pins. It reads the bech32 data part and skips the checksum, because the npub
# comes from canary-indexer on this computer. The caller compares the result
# with the pubkey the indexer prints when it starts.
npub_to_hex() {
	local npub=$1 charset=qpzry9x8gf2tvdw0s3jn54khce6mua7l
	local data acc=0 bits=0 out="" i c before
	case $npub in
	npub1*) ;;
	*) return 1 ;;
	esac
	data=${npub#npub1}
	data=${data%??????}
	[ ${#data} -eq 52 ] || return 1
	for ((i = 0; i < ${#data}; i++)); do
		c=${data:i:1}
		before=${charset%%"$c"*}
		[ ${#before} -lt 32 ] || return 1
		acc=$(((acc << 5) | ${#before}))
		bits=$((bits + 5))
		if ((bits >= 8)); then
			bits=$((bits - 8))
			out="$out$(printf '%02x' $(((acc >> bits) & 255)))"
			acc=$((acc & ((1 << bits) - 1)))
		fi
	done
	[ ${#out} -eq 64 ] || return 1
	printf '%s\n' "$out"
}

# logged_pubkey reads the pubkey an indexer printed when it started.
logged_pubkey() {
	sed -n 's/.* pubkey \([0-9a-f]\{64\}\), pin it with .*/\1/p' "$1" | sed -n 1p
}

# wait_for_indexer polls /info until the indexer has indexed Core's tip.
wait_for_indexer() {
	local label=$1 port=$2 pid=$3 log=$4 want=$5 i body tip
	for ((i = 0; i < WAIT_SECONDS * 2; i++)); do
		if ! kill -0 "$pid" 2>/dev/null; then
			tail -n 20 "$log" >&2
			fail "The $label indexer stopped. Its log is $log."
		fi
		if body=$(curl -fsS --max-time 2 "http://127.0.0.1:$port/info" 2>/dev/null); then
			tip=$(printf '%s\n' "$body" | sed -n 's/.*"tip":{[^}]*"hash":"\([0-9a-f]\{64\}\)".*/\1/p')
			if [ "$tip" = "$want" ]; then
				return 0
			fi
		fi
		sleep 0.5
	done
	fail "The $label indexer did not reach block $want within $WAIT_SECONDS seconds. Its log is $log."
}

main() {
	local root out="" act5="" arg version major port

	root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
	for arg in "$@"; do
		case $arg in
		--act5) act5=yes ;;
		-h | --help)
			print_help
			exit 0
			;;
		-*) fail "Unknown option $arg. $USAGE" ;;
		*)
			[ -z "$out" ] || fail "Give at most one output directory. $USAGE"
			out=$arg
			;;
		esac
	done
	out=${out:-./demo-out}

	step "Checking prerequisites"
	if ! command -v "$BITCOIND" >/dev/null 2>&1 || ! command -v "$BITCOIN_CLI" >/dev/null 2>&1; then
		fail "bitcoind and bitcoin-cli are not installed. Install Bitcoin Core v30 or later, for example with: brew install bitcoin"
	fi
	command -v go >/dev/null 2>&1 || fail "Go is not installed. The demo builds canary and canary-indexer from this repository."
	command -v curl >/dev/null 2>&1 || fail "curl is not installed. The demo uses it to ask each indexer how far it has synced."
	version=$("$BITCOIND" -version 2>/dev/null | sed -n 1p) || version=""
	major=$(printf '%s\n' "$version" | sed -n 's/.*version v\{0,1\}\([0-9][0-9]*\)\..*/\1/p')
	if [ -z "$major" ]; then
		say "Can't read the bitcoind version, so going on. The indexer needs v30 or later."
	elif [ "$major" -lt 30 ]; then
		fail "$version is too old. The indexer reads /rest/spenttxouts, which Bitcoin Core added in v30."
	else
		say "$version"
	fi
	for port in "$RPC_PORT" "$P2P_PORT" "$HONEST_PORT" "$WITHHOLDER_PORT"; do
		if port_in_use "$port"; then
			fail "Something on this computer already uses port $port. Stop it, or pick other ports with the CANARY_DEMO_*_PORT variables."
		fi
	done
	if [ -e "$out" ] && [ -n "$(ls -A "$out" 2>/dev/null)" ]; then
		fail "The output directory $out is not empty. Remove it, or give another directory."
	fi
	# The directory is created only once bitcoind is up, so make the path
	# absolute now: the build below changes directory.
	case $out in
	/*) ;;
	*) out=$PWD/${out#./} ;;
	esac
	say "Output goes to $out"

	trap cleanup EXIT
	trap 'exit 130' INT
	trap 'exit 143' TERM
	local parent=${TMPDIR:-/tmp}
	TMP=$(mktemp -d "${parent%/}/canary-demo.XXXXXX")

	step "Building canary and canary-indexer"
	(cd "$root" && go build -o "$TMP/bin/canary" ./cmd/canary && go build -o "$TMP/bin/canary-indexer" ./cmd/canary-indexer)
	local canary="$TMP/bin/canary" indexer="$TMP/bin/canary-indexer"

	step "Starting bitcoind in regtest mode, RPC and REST on port $RPC_PORT"
	mkdir -p "$TMP/bitcoin"
	"$BITCOIND" -regtest -datadir="$TMP/bitcoin" \
		-rest=1 -txindex=1 -fallbackfee=0.0001 \
		-port="$P2P_PORT" -bind="127.0.0.1:$P2P_PORT" -listenonion=0 \
		-rpcport="$RPC_PORT" -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 \
		>"$TMP/bitcoind.out" 2>&1 &
	BITCOIND_PID=$!
	local i ready=""
	for ((i = 0; i < WAIT_SECONDS * 2; i++)); do
		if ! kill -0 "$BITCOIND_PID" 2>/dev/null; then
			cat "$TMP/bitcoind.out" >&2
			tail -n 20 "$TMP/bitcoin/regtest/debug.log" >&2 2>/dev/null || true
			fail "bitcoind stopped while starting."
		fi
		if cli getblockchaininfo >/dev/null 2>&1; then
			ready=yes
			break
		fi
		sleep 0.5
	done
	[ -n "$ready" ] || fail "bitcoind did not answer RPC within $WAIT_SECONDS seconds."
	local rest="http://127.0.0.1:$RPC_PORT/rest"
	say "Bitcoin Core REST is at $rest"

	# Everything before this point either succeeded or left no output, so a
	# failed build or start can be retried with the same directory.
	mkdir -p "$out/logs"
	out=$(cd "$out" && pwd)

	step "Creating a wallet and mining 200 blocks"
	cli createwallet demo >/dev/null
	local miner
	miner=$(wallet getnewaddress "" bech32)
	cli generatetoaddress 200 "$miner" >/dev/null
	say "Mined to $miner. The first 100 block rewards can now be spent."

	local early_txid="" early_block="" early_height=""
	if [ -n "$act5" ]; then
		step "Act 5: paying 1 BTC to another taproot address, then mining $ACT5_DEPTH blocks"
		local early_payee
		early_payee=$(wallet getnewaddress "" bech32m)
		early_txid=$(wallet sendtoaddress "$early_payee" 1.0)
		cli generatetoaddress 1 "$miner" >/dev/null
		early_block=$(cli getbestblockhash)
		early_height=$(cli getblockcount)
		cli getrawtransaction "$early_txid" 0 "$early_block" >/dev/null 2>&1 ||
			fail "Transaction $early_txid is not in block $early_block. The early payment did not confirm."
		cli generatetoaddress $((ACT5_DEPTH - 1)) "$miner" >/dev/null
		say "Paid $early_payee in transaction $early_txid"
		say "The early payment is in block $early_height, hash $early_block"
		say "After the main payment's block, it sits $ACT5_DEPTH blocks below the tip, past the $RETENTION_WINDOW-block window."
	fi

	step "Paying 1 BTC to a new taproot (bech32m) address, among four other taproot payments"
	local payee txid other amount
	# Four ordinary taproot payments share the block, so the withheld entry is one of
	# several and the honest list visibly holds the others.
	for amount in 0.2 0.3; do
		other=$(wallet getnewaddress "" bech32m)
		wallet sendtoaddress "$other" "$amount" >/dev/null
	done
	payee=$(wallet getnewaddress "" bech32m)
	txid=$(wallet sendtoaddress "$payee" 1.0)
	for amount in 0.4 0.5; do
		other=$(wallet getnewaddress "" bech32m)
		wallet sendtoaddress "$other" "$amount" >/dev/null
	done
	say "Paid $payee in transaction $txid"
	say "Four other taproot payments go into the same block."

	step "Mining 1 block to confirm the payment"
	cli generatetoaddress 1 "$miner" >/dev/null
	local block height tip
	block=$(cli getbestblockhash)
	height=$(cli getblockcount)
	cli getrawtransaction "$txid" 0 "$block" >/dev/null 2>&1 ||
		fail "Transaction $txid is not in block $block. The payment did not confirm."
	say "The payment is in block $height, hash $block"

	step "Making two throwaway indexer keys"
	mkdir -p "$TMP/keys"
	local honest_npub withholder_npub honest_pub withholder_pub
	honest_npub=$("$indexer" --gen-key "$TMP/keys/honest.key")
	withholder_npub=$("$indexer" --gen-key "$TMP/keys/withholder.key")
	honest_pub=$(npub_to_hex "$honest_npub") || fail "Can't read the honest indexer's npub $honest_npub."
	withholder_pub=$(npub_to_hex "$withholder_npub") || fail "Can't read the withholding indexer's npub $withholder_npub."
	say "honest      $honest_pub"
	say "withholder  $withholder_pub"
	say "The secret keys stay in the temporary directory and are removed on exit."

	step "Starting the honest indexer on port $HONEST_PORT"
	"$indexer" --core-rest "$rest" --addr "127.0.0.1:$HONEST_PORT" \
		--key-file "$TMP/keys/honest.key" --poll 1s \
		>"$out/logs/honest.log" 2>&1 &
	HONEST_PID=$!

	step "Starting the withholding indexer on port $WITHHOLDER_PORT"
	say "It leaves $txid out of every list it serves, and still signs it into the block's record."
	local withhold_args=(--withhold-txid "$txid")
	if [ -n "$act5" ]; then
		withhold_args+=(--withhold-txid "$early_txid")
		say "It leaves the early payment $early_txid out the same way."
	fi
	"$indexer" --core-rest "$rest" --addr "127.0.0.1:$WITHHOLDER_PORT" \
		--key-file "$TMP/keys/withholder.key" --poll 1s "${withhold_args[@]}" \
		>"$out/logs/withholder.log" 2>&1 &
	WITHHOLDER_PID=$!

	step "Waiting for both indexers to reach block $height"
	wait_for_indexer honest "$HONEST_PORT" "$HONEST_PID" "$out/logs/honest.log" "$block"
	wait_for_indexer withholder "$WITHHOLDER_PORT" "$WITHHOLDER_PID" "$out/logs/withholder.log" "$block"
	[ "$(logged_pubkey "$out/logs/honest.log")" = "$honest_pub" ] ||
		fail "The honest indexer's log names a pubkey other than its npub's."
	[ "$(logged_pubkey "$out/logs/withholder.log")" = "$withholder_pub" ] ||
		fail "The withholding indexer's log names a pubkey other than its npub's."
	say "Both indexers serve block $height."

	# The withholder's gap is an omission only while the block sits inside the
	# window, so measure the depth at the tip canary check will read.
	tip=$(cli getblockcount)
	if [ $((tip - height)) -ge "$RETENTION_WINDOW" ]; then
		fail "The payment's block is $((tip - height)) blocks deep. It must be less than $RETENTION_WINDOW."
	fi
	# Act 5 needs the opposite: the early block past the window.
	if [ -n "$act5" ] && [ $((tip - early_height)) -lt "$RETENTION_WINDOW" ]; then
		fail "The early payment's block is $((tip - early_height)) blocks deep. Act 5 needs $RETENTION_WINDOW or more."
	fi

	step "Running canary check on blocks 0 to $tip, with both servers pinned and the payment declared"
	local code=0
	set +e
	"$canary" check \
		--indexer "http://127.0.0.1:$HONEST_PORT=honest" --pubkey "honest=$honest_pub" \
		--indexer "http://127.0.0.1:$WITHHOLDER_PORT=withholder" --pubkey "withholder=$withholder_pub" \
		--core-rest "$rest" --from 0 --to "$tip" \
		--expect "$txid@$block" \
		--state "$out/state.json" --evidence-dir "$out/evidence" 2>&1 | tee "$out/check.txt"
	code=${PIPESTATUS[0]}
	set -e
	case $code in
	1) say "canary check saw a finding, as expected." ;;
	0) fail "canary check saw no finding. It should have named the withholding server." ;;
	*) fail "canary check failed with exit code $code. Its output is in $out/check.txt." ;;
	esac

	local evidence="$out/evidence/omission-regtest-$height-${txid:0:8}-${withholder_pub:0:8}.json"
	[ -f "$evidence" ] || fail "canary check wrote no evidence file at $evidence."

	step "Checking the evidence file offline with canary verify"
	set +e
	"$canary" verify "$evidence" 2>&1 | tee "$out/verify.txt"
	code=${PIPESTATUS[0]}
	set -e
	[ "$code" -eq 0 ] || fail "canary verify exited $code. The evidence file should check out."

	step "Printing canary status"
	"$canary" status --state "$out/state.json" | tee "$out/status.txt"

	if [ -n "$act5" ]; then
		step "Act 5: running canary check on block $early_height alone, with only the withholding server pinned"
		say "The withholder left the early payment out too. Its signed tip puts that block $((tip - early_height)) blocks deep."
		say "Past the window a gap is permitted. No other server and no declared payment can supply the entry."
		mkdir -p "$out/act5"
		set +e
		"$canary" check \
			--indexer "http://127.0.0.1:$WITHHOLDER_PORT=withholder" --pubkey "withholder=$withholder_pub" \
			--core-rest "$rest" --from "$early_height" --to "$early_height" \
			--state "$out/act5/state.json" --evidence-dir "$out/act5/evidence" 2>&1 | tee "$out/act5/check.txt"
		code=${PIPESTATUS[0]}
		set -e
		case $code in
		0) ;;
		1) fail "The act 5 check saw a finding. Block $early_height should read Can't be checked, which accuses nobody. Its output is in $out/act5/check.txt." ;;
		*) fail "The act 5 check failed with exit code $code. Its output is in $out/act5/check.txt." ;;
		esac

		step "Printing canary status for act 5"
		"$canary" status --state "$out/act5/state.json" | tee "$out/act5/status.txt"
		if ! grep -qx "1 Can't be checked" "$out/act5/status.txt" ||
			! grep -q '"reason": "gap_unfilled"' "$out/act5/state.json"; then
			fail "Block $early_height does not read Can't be checked, reason gap_unfilled. See $out/act5/state.json."
		fi
		say "Block $early_height reads Can't be checked, reason gap_unfilled. That is neither a pass nor an accusation."
	fi

	cat >"$out/run.txt" <<EOF
network     regtest
payment     $txid
block       $height $block
chain tip   $tip
honest      http://127.0.0.1:$HONEST_PORT  pubkey $honest_pub
withholder  http://127.0.0.1:$WITHHOLDER_PORT  pubkey $withholder_pub
evidence    evidence/$(basename "$evidence")
EOF
	if [ -n "$act5" ]; then
		cat >>"$out/run.txt" <<EOF
act 5       payment $early_txid
act 5 block $early_height $early_block
act 5 state act5/state.json
EOF
	fi

	step "Done"
	say "State file:     $out/state.json"
	say "Evidence file:  $evidence"
	say "Logs and output: $out"
	say "To see the results in the dashboard, from $root run:"
	say "  go run ./cmd/canary ui --state $out/state.json"
	if [ -n "$act5" ]; then
		say "Act 5 state:    $out/act5/state.json"
		say "To see act 5 in the dashboard, run:"
		say "  go run ./cmd/canary ui --state $out/act5/state.json"
	fi
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
	main "$@"
fi
