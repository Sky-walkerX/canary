# Video script

The demo video for Canary's BOSS Battle entry. It runs 3:56 without the optional
Servers disagree scene, and 4:21 with it. Both fit the target of 3:15 to 4:30, and both
clear the reported 180-second floor.

The story order is fixed. The loss comes first, then the cause, then Canary, then a check
anyone can repeat, then the limits. The video ends on a block Canary could not check,
because that state shows how the design treats what it cannot know.

The values quoted below come from the recorded run of 1 Oct 2026, whose output is in
[docs/runs/2026-10-01](../runs/2026-10-01/). The setup repeats that run's steps, and each
take, dry runs included, starts from an empty run directory. So every take gives the same
block heights, 201 and 351, the same five entries in block 351 and the same counts lines.
Txids, block hashes, keys and the evidence file's name change on every run, and the
withheld entry's position can change too. If a take differs from the values here, the
screen wins. Take the new values from the terminal while editing, never from memory.

## Rules for the recording

- **Every frame comes from a real run.** Re-record a bad take. Never fake or retype
  output. Cut dead time between takes, never inside one, and keep timestamps visible so
  each cut shows.
- **Capture the run you commit.** The evidence file shown on screen must be the file
  committed under `evidence/` in the tagged commit. Compare their SHA-256 after editing.
- **Use your own voice.** No synthetic voice.
- **Keep the payment inside the 144-block window for the detection scene.** Never mine
  144 or more blocks between the payment and the first `canary check`. Outside the window
  an empty slot is allowed, and the run would end with no accusation.
- **Keep secrets out of the repository.** The run directory holds both servers' secret
  keys. It lives outside the repository, and you delete the keys when you finish.

## Chapters

Paste these into the YouTube description. YouTube needs the first chapter at 0:00 and at
least 10 seconds per chapter.

Without the Servers disagree scene:

```
0:00 The problem
0:44 One switch
1:10 Why regtest
1:24 Detection
2:18 Check it yourself
3:02 What Canary does not do
3:30 Can't be checked
3:44 Accountable, not trustless
```

With it:

```
0:00 The problem
0:44 One switch
1:10 Why regtest
1:24 Detection
2:18 Servers disagree
2:43 Check it yourself
3:27 What Canary does not do
3:55 Can't be checked
4:09 Accountable, not trustless
```

Suggested title: *Canary: catching a silent-payments server that leaves out a recent entry
it signed for*.

Suggested description, above the chapters:

```
A silent-payments light wallet can't tell "nobody paid you" from "the server left your
payment out." Canary checks the tweak list a server sends against the record the same
server signed, and names the server when they contradict each other.

Recorded on a local regtest node. Version 1 is built and tested on regtest only. Canary
makes tweak sourcing accountable, not trustless.

Code, evidence file and docs: https://github.com/Sky-walkerX/canary
Built by one developer with Claude, Anthropic's AI assistant.
```

## Setting up the run

These commands follow `scripts/demo-regtest.sh --act5` step for step, with the same
ports. The script stops every process when it finishes, so the video uses these commands
by hand to keep both servers running between shots. The README must then say the video
shows a manual run of the script's steps.

On 1 Oct the script ran end to end on Bitcoin Core v31.1.0. These commands copy its
steps, but do a full dry run of them before the take you keep.

You need Bitcoin Core v30 or later, Go and curl. Run everything from the repository root,
in zsh or bash.

**Build once per take, while online.** The run directory sits outside the repository.
Every take starts from an empty one. A second pass in the same directory fails at
`createwallet`, because the wallet already exists, and leftover evidence files break the
site build in act 4. If a previous take is still running, run the commands under
[After recording](#after-recording) first.

```sh
export RUN=~/canary-run
rm -rf "$RUN"
mkdir -p "$RUN"/{bin,keys,logs,evidence,bitcoin}
go build -o "$RUN/bin/canary" ./cmd/canary
go build -o "$RUN/bin/canary-indexer" ./cmd/canary-indexer
export PATH="$RUN/bin:$PATH"
cli() { bitcoin-cli -regtest -datadir="$RUN/bitcoin" -rpcport=28443 "$@"; }
REST=http://127.0.0.1:28443/rest
```

**Start Bitcoin Core in regtest mode.**

```sh
bitcoind -regtest -datadir="$RUN/bitcoin" -rest=1 -txindex=1 -fallbackfee=0.0001 \
  -port=28444 -bind=127.0.0.1:28444 -listenonion=0 \
  -rpcport=28443 -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -daemon
cli -rpcwait getblockcount
```

**Mine, and make act 5's early payment.** Any Core-wallet payment to a taproot address
is eligible, so no silent-payments wallet is needed. The early payment confirms in block
201. The 149 blocks after it, plus the main payment's block, leave it 150 blocks below the
tip, past the 144-block window.

```sh
cli createwallet demo
MINER=$(cli -rpcwallet=demo getnewaddress "" bech32)
cli generatetoaddress 200 "$MINER" > /dev/null
EARLY_TXID=$(cli -rpcwallet=demo sendtoaddress "$(cli -rpcwallet=demo getnewaddress "" bech32m)" 1.0)
cli generatetoaddress 1 "$MINER" > /dev/null
EARLY_HEIGHT=$(cli getblockcount)
cli generatetoaddress 149 "$MINER" > /dev/null
echo "early payment $EARLY_TXID in block $EARLY_HEIGHT"
```

**Pay a taproot address beside four other taproot payments, and confirm it.** The
payment confirms in block 351, which then holds five entries.

```sh
for amount in 0.2 0.3; do
  cli -rpcwallet=demo sendtoaddress "$(cli -rpcwallet=demo getnewaddress "" bech32m)" "$amount" > /dev/null
done
PAYEE=$(cli -rpcwallet=demo getnewaddress "" bech32m)
TXID=$(cli -rpcwallet=demo sendtoaddress "$PAYEE" 1.0)
for amount in 0.4 0.5; do
  cli -rpcwallet=demo sendtoaddress "$(cli -rpcwallet=demo getnewaddress "" bech32m)" "$amount" > /dev/null
done
cli generatetoaddress 1 "$MINER" > /dev/null
BLOCK=$(cli getbestblockhash)
HEIGHT=$(cli getblockcount)
echo "payment $TXID in block $HEIGHT, hash $BLOCK"
```

In the 1 Oct run, the early payment was
`b3d748316d7d1d7fcc64837a2d4ca459015bd8f7519f1c1ad73db4499c21cdb9` in block 201. The
main payment was `ad56b9bb4aa382fdaec664abc1dcaf57b0477905c5c17c2c7669d6212d5fe21e` in
block 351, hash `72ef80792f8633d70f19945464df62f82a267b68ee3e113199e9d11a5e41d58a`.

**Start the two index servers.** One is honest. The other withholds both payments.

```sh
canary-indexer --gen-key "$RUN/keys/honest.key"
canary-indexer --gen-key "$RUN/keys/withholder.key"
canary-indexer --core-rest "$REST" --addr 127.0.0.1:28481 \
  --key-file "$RUN/keys/honest.key" --poll 1s > "$RUN/logs/honest.log" 2>&1 &
HONEST_PID=$!
canary-indexer --core-rest "$REST" --addr 127.0.0.1:28482 \
  --key-file "$RUN/keys/withholder.key" --poll 1s \
  --withhold-txid "$TXID" --withhold-txid "$EARLY_TXID" \
  > "$RUN/logs/withholder.log" 2>&1 &
WITHHOLDER_PID=$!
until curl -fs http://127.0.0.1:28481/info | grep -q "$BLOCK"; do sleep 1; done
until curl -fs http://127.0.0.1:28482/info | grep -q "$BLOCK"; do sleep 1; done
pub() { sed -n 's/.* pubkey \([0-9a-f]\{64\}\), pin it with .*/\1/p' "$1" | head -n 1; }
HONEST_PUB=$(pub "$RUN/logs/honest.log")
WITHHOLDER_PUB=$(pub "$RUN/logs/withholder.log")
```

Each server prints its pubkey when it starts. `canary check` pins those keys by flag and
never learns a key from the server. In the 1 Oct run the withholder's key began
`db614560`, and the honest server's began `3d27ad61`.

**Save the run's values for other terminals.** The file holds public values only. Run
`source ~/canary-run/env.sh` in every other terminal or pane you film.

```sh
cat > "$RUN/env.sh" <<EOF
export RUN="$RUN" REST="$REST" TXID="$TXID" BLOCK="$BLOCK" HEIGHT="$HEIGHT"
export EARLY_TXID="$EARLY_TXID" EARLY_HEIGHT="$EARLY_HEIGHT"
export MINER="$MINER" HONEST_PUB="$HONEST_PUB" WITHHOLDER_PUB="$WITHHOLDER_PUB"
export PATH="$RUN/bin:\$PATH"
cli() { bitcoin-cli -regtest -datadir="\$RUN/bitcoin" -rpcport=28443 "\$@"; }
EOF
```

**Screen.** One terminal at 18 pt or larger, about 100 columns wide, and one browser
window. Act 1 uses a split screen, which a terminal multiplexer or two windows side by
side can give you.

## Act 1. The loss, 0:00 to 0:44

### Shot 1, 0:00 to 0:10. The problem in one line

**Screen.** A plain title card with the caption text, then a cut to the terminal.

**Say.** "A silent-payments wallet asks a server for the data that finds your payments.
If the server leaves yours out, nothing tells you."

**Caption.** A light wallet can't tell "nobody paid you" from "the server left your
payment out."

### Shot 2, 0:10 to 0:30. The node has the payment, the server's list does not

**Screen.** Split screen. Left, your own node:

```sh
cli -rpcwallet=demo gettransaction "$TXID" | grep -E '"(confirmations|blockhash|blockheight)"'
```

Right, the withholding server's answer for the same block:

```sh
curl -s -D - -o "$RUN/withheld.bin" "http://127.0.0.1:28482/tweaks/$BLOCK"
xxd "$RUN/withheld.bin"
```

The headers show `200 OK` and `X-Canary-Receipt`. The body is 269 bytes. It starts with
the count, five, as `05000000`. Four slots of kind `01` carry a full entry, 66 bytes
each. The payment's slot is the single byte `03`. In the 1 Oct run the payment sat at
position 0, so `03` came straight after the count. Positions follow transaction order in
the block, so a new take can put it elsewhere.

**Say.** "On the left, my own Bitcoin node. A payment, confirmed in block 351. On the
right, what a server sent for that block. Status 200, no error. The first four bytes
count five entries. Four slots hold an entry. One is a single byte, zero three. That
slot is empty."

**Caption.** Left: Core shows the payment in block 351. Right: the server's list for
that block. 200 OK, five slots, and the payment's slot is empty.

### Shot 3, 0:30 to 0:44. What an honest server sends

**Screen.** The right pane only, now asking the honest server:

```sh
curl -s "http://127.0.0.1:28481/tweaks/$BLOCK" | xxd
```

**Say.** "A second server sends the full entry: the transaction ID and its tweak. Without
that tweak, a wallet never finds the payment. It just shows a smaller balance."

**Caption.** Honest server: five slots of kind 01, each a txid in internal byte order and
a 33-byte tweak. Withholder: the payment's slot is kind 03, empty.

## Act 2. The cause, 0:44 to 1:24

### Shot 4, 0:44 to 0:58. One switch

**Screen.** The help text, with the `--withhold-txid` line highlighted in the edit:

```sh
canary-indexer --help
```

**Say.** "Here's the cause. Our reference server has one switch, withhold-txid. Each use
leaves one transaction out of every list it serves, and still signs it into its record.
Here it's set twice: my payment, and an earlier one for the last scene."

**Caption.** Each --withhold-txid leaves one transaction out of what the server sends.
The signed record still includes it. This run sets it twice.

### Shot 5, 0:58 to 1:10. Why a transaction, and why the sender

**Screen.** The withholding server's log:

```sh
cat "$RUN/logs/withholder.log"
```

It shows the start-up warning, the pubkey and the indexed heights, and no error. The
warning says the server leaves 2 transactions out of every list it serves, and names both
txids. Point at it in the edit. It is there because this is a demo tool, and a real
withholder would print nothing. Serving the list logged no error.

**Say.** "It targets a transaction, not an address. No server can find your payments
without your scan key. The sender doesn't need to. It knows its own transaction."

**Caption.** The exchange that pays you can also run the server that tells you whether
you were paid.

### Shot 6, 1:10 to 1:24. Why regtest

**Screen.**

```sh
cli getblockchaininfo | grep -E '"(chain|blocks)"'
```

It shows `"chain": "regtest"` and `"blocks": 351`.

**Say.** "All of this runs on regtest, a private Bitcoin network on this laptop. Blocks
come on command, and anyone with Bitcoin Core can repeat the run. But it's not a public
network."

**Caption.** Regtest is a private test network. Blocks on command, no faucet, repeatable
on one machine. Not a public network.

## Act 3. Detection, 1:24 to 2:18

### Shot 7, 1:24 to 1:40. canary check

**Screen.** Type or paste the command, then run it:

```sh
canary check \
  --indexer http://127.0.0.1:28481=honest --pubkey honest="$HONEST_PUB" \
  --indexer http://127.0.0.1:28482=withholder --pubkey withholder="$WITHHOLDER_PUB" \
  --core-rest "$REST" \
  --expect "$TXID@$BLOCK" \
  --state "$RUN/state.json" --evidence-dir "$RUN/evidence"
```

**Say.** "Now Canary. canary check asks each server for its signed record of every block,
and the list it serves, with a signed receipt. I pinned both keys, and declared my
payment. My node supplies block hashes, not the verdict."

**Caption.** Each server's signed record, its list and a receipt over the bytes. Keys
pinned by flag. --expect declares the payment I made.

### Shot 8, 1:40 to 2:06. The server named

**Screen.** The output of the same command, then the exit code:

```sh
echo $?
```

The output starts "Checking blocks 0–351 against 2 servers." The summary reads
`351 Checked · 1 Data withheld`, then "withholder left out an entry it had signed for:
block 351, txid ad56b9bb…e21e." The next line names the evidence file,
`omission-regtest-351-ad56b9bb-db614560.json` in the 1 Oct run, and says "You can prove
this to others." The exit code is 1, which means a finding. A new take prints its own
txid and file name, and the caption uses what the screen shows.

**Say.** "The withholder's record includes my payment's entry. Its list leaves that slot
empty, while the block is still new. Servers may prune old entries, but must keep a hash
of each one for 144 blocks, about a day. So this isn't pruning. Canary fills the gap,
recomputes the root, and it matches. It names the server, the block and the
transaction."

**Caption.** Data withheld. withholder left out an entry it had signed for: block 351,
txid ad56b9bb…e21e.

### Shot 9, 2:06 to 2:18. Coverage

**Screen.** Start the dashboard, open http://127.0.0.1:7352/, show the Overview, then
click the finding. Stop the dashboard with Ctrl-C after the shot.

```sh
canary ui --state "$RUN/state.json"
```

**Say.** "The dashboard shows coverage, block by block. Checked means the tweak list
matched, not that payments were checked. A balance over unchecked blocks is a lower
bound."

**Caption.** A balance computed over blocks you could not check is a lower bound, not a
balance.

## Act 3b. Servers disagree, optional, 2:18 to 2:43

Film this scene only if a second switch exists that makes a server sign a record already
missing the entry. It did not exist on 1 Oct. The frozen v1 formats define only
`--withhold-txid`, which always signs an honest record. Without that switch, skip the
scene and use the chapters without it.

### Shot 10, 2:18 to 2:43. Two signed roots for one block

**Screen.** A third server on port 28483, started with [the record-omitting switch, if
built], then a check of the honest server against it. Leave out `--expect`. A declared
payment would turn the block into Data withheld, which outranks Servers disagree, and
the scene would not show the disagreement.

```sh
canary check \
  --indexer http://127.0.0.1:28481=honest --pubkey honest="$HONEST_PUB" \
  --indexer http://127.0.0.1:28483=signs-less --pubkey signs-less="[its pubkey, from the run]" \
  --core-rest "$REST" \
  --state "$RUN/disagree-state.json" --evidence-dir "$RUN/disagree-evidence"
```

**Say.** "What if the server signs a record that already leaves the entry out? Then its
root differs from the honest server's root for the same block. Canary says Servers
disagree, and names both. It can't tell which one lied, so it drops neither. Settling
that takes the full block."

**Caption.** Servers disagree. Two signed roots for one block. Which one lied is unknown.

## Act 4. Check it yourself, 2:18 to 3:02

Add 25 seconds to every time from here on if you kept act 3b.

**Between takes,** copy the evidence file into the repository, build the browser checker
and the site, and serve the site on this computer:

```sh
EV=$(ls "$RUN"/evidence/omission-regtest-*.json)
[ "$(printf '%s\n' "$EV" | wc -l)" -eq 1 ] || echo "STOP: $RUN/evidence must hold exactly one omission file"
NAME=$(basename "$EV")
cp "$EV" evidence/
make wasm
go run ./cmd/site -evidence "evidence/$NAME"
python3 -m http.server 8080 --bind 127.0.0.1 --directory site/dist
```

If the second line prints STOP, go no further. The run directory was not empty, so start
the take again. The last command serves the site until you press Ctrl-C, so give it its
own terminal and stop it after shot 13. Set `EV` and `NAME` the same way in the terminal
you film for shot 12. The site build also writes a tampered copy, with one byte changed,
to `site/dist/evidence/`, under the same name with `-tampered` before `.json`. It flips
one hex digit of the first proof hash, and the page's note names the byte.

In the 1 Oct run, `NAME` was `omission-regtest-351-ad56b9bb-db614560.json`, which is
already committed. A new take adds its own file beside it, and
`TestCommittedEvidenceChecksOut` checks every committed file.

### Shot 11, 2:18 to 2:42. The browser checker

**Screen.** http://127.0.0.1:8080/ in the browser. Click "Choose an evidence file" and
pick the file from `$RUN/evidence`. The result reads "Checks out." with its eight steps.
Then click "Try a tampered copy". It reads "Does not check out: inclusion failed.",
because the changed proof hash no longer leads to the signed root.

**Say.** "Anyone can check the evidence file Canary wrote. This page runs the same Go
code in the browser, as WebAssembly, and the file never leaves it. Eight steps, from the
record's signature to the 144-block window. Checks out. Now a copy with one byte changed.
It fails, at the step that covers that byte."

**Caption.** The same verify code as the terminal, compiled to WebAssembly. The page
makes no outside requests.

### Shot 12, 2:42 to 3:02. The terminal, with the network off

**Screen.** Turn Wi-Fi off from the menu bar, on camera, and unplug any network cable.
Then show that nothing outside answers, and verify both files with the `canary` you built
earlier:

```sh
curl -sS --max-time 5 https://github.com
canary verify "evidence/$NAME"
canary verify "site/dist/evidence/${NAME%.json}-tampered.json"
```

The first file prints "Checks out." and exits 0. The tampered copy prints "Does not check
out: inclusion failed." and exits 1. Both match what the 1 Oct file and its tampered copy
print.

**Say.** "Same file, in a terminal, with Wi-Fi off. No node, no server, no internet.
Checks out. The tampered copy doesn't. And a file that fails doesn't make the server
honest. It means this file's claim fails."

**Caption.** canary verify, offline. The accusation rests on the server's own signatures
and receipt.

## Act 5. The limits, 3:02 to 3:56

This act is never cut. It states the limits before anyone has to ask.

### Shot 13, 3:02 to 3:30. What Canary does not do

**Screen.** The site's limits table at http://127.0.0.1:8080/, which still loads with
the network off, because it is served from this computer.

**Say.** "Now what Canary doesn't do. Checked means the tweak list was checked, never the
payments. A server can send the right tweak, drop the payment's output, and version one
still says Checked. A server that declares pruning can send just a hash, and that passes.
Version one is tested on regtest only, against our own server. And it uses no relays
yet."

**Caption.** Not covered in v1: output data, hash-only entries under a pruning policy,
public networks and relays. Canary looks for hiding only, never fake entries.

### Shot 14, 3:30 to 3:44. A block Canary can't check

**Screen.** Check block 201 alone against the withholding server, with no second server
and no declared payment. The withholder also left the early payment out of block 201.
Its signed tip puts that block 150 blocks deep, past the window.

```sh
canary check \
  --indexer http://127.0.0.1:28482=withholder --pubkey withholder="$WITHHOLDER_PUB" \
  --core-rest "$REST" --from "$EARLY_HEIGHT" --to "$EARLY_HEIGHT" \
  --state "$RUN/limit-state.json" --evidence-dir "$RUN/limit-evidence"
```

In the 1 Oct run it printed "Checking blocks 201–201 against 1 server." and the counts
line `1 Can't be checked`. It found nothing and exited 0. The state file gives the
reason, `gap_unfilled`. To show it, open `canary ui --state "$RUN/limit-state.json"` and
the Blocks page.

**Say.** "One last run. The same server, alone, on an older block. It also left an
earlier payment out of block 201, which now sits 150 blocks deep. Past the window, an
empty slot could be honest pruning, and nothing here fills it. Can't be checked. Not a
pass. Not an accusation."

**Caption.** Can't be checked means Canary could not recompute the root. It is neither a
pass nor an accusation.

### Shot 15, 3:44 to 3:56. The closing line

**Screen.** A plain closing card with the caption text and the repository address.

**Say.** "Canary doesn't make tweak servers trustless. It makes them accountable, if one
server is honest and its records reach you. I built it with Claude, an AI assistant."

**Caption.** Accountable, not trustless. Given at least one honest server publishing
signed records, and an uncensored path to a relay carrying them.
github.com/Sky-walkerX/canary

## After recording

Stop the servers and Core, and delete the secret keys:

```sh
kill "$HONEST_PID" "$WITHHOLDER_PID"
cli stop
rm -rf "$RUN/keys"
```

Check that the committed evidence file is the one the video shows:

```sh
shasum -a 256 "evidence/$NAME" "$EV"
```

The two hashes must match. Commit only that one file from the run. For the 1 Oct file
the hash is `aea26b9bf54926af62eefe09b7fb7bd64540025b052001f52a41f77cac1b9710`. If the
video shows a new run, its file sits beside the 1 Oct file. Then the README must say the
video shows a later run of the same steps, with its own txids and keys. Then check the
runtime: at least 3:00, and no more than 4:30.

## If something fails

| Problem | What to do |
|---|---|
| The hand-run commands fail, but `scripts/demo-regtest.sh` works | Record the script's run in one take. Show act 1 from its printed steps, its logs and the served bytes, which the evidence file keeps in `served_base64`. Say on screen that the servers stopped when the script ended |
| Nothing is recorded by 13:00 IST on 5 Oct | Record the terminal only, in one take, and narrate over it |
| `--expect` fails, for example because Core can't find the transaction | Drop `--expect` from shot 7. The honest server's list still supplies the withheld entry, so act 3 still names the server. Drop "and declared my payment" from the narration |
| The record-omitting switch was never built | Skip act 3b. The FAQ covers that branch in words |
| Block 201 does not read Can't be checked in shot 14 | Name the state and what it means over the limits table, without showing it, and say on screen that it was not staged |
| Bitcoin Core will not start on the day | Narrate over the 1 Oct run from its files: its output in `docs/runs/2026-10-01`, `canary ui` on its state file and `canary verify` on the committed evidence file. Say on screen that this replays the run of 1 Oct from its files, and drop act 1's live `curl` |
| A result on screen differs from this script | Narrate what the screen shows. The screen wins over the script |

## Words to keep, and words to avoid

- Say "accountable, not trustless", and never drop the "not".
- Say "Checked means the tweak list was checked". Never imply the payments were checked.
- Say "left out an entry it had signed for". Never say "hidden payment", and never name
  an amount.
- Say "Servers disagree names both servers". Never say Canary knows which server lied.
- Say "Can't be checked is neither a pass nor an accusation".
- Say "you can prove this to others" only for the evidence file with a receipt.
- Never say the records are on a relay, or that the run used a public network.
- Never say Canary was first. SPCOMMIT published tweak-list commitments before it.
