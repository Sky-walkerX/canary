# Scripts

## demo-regtest.sh

`demo-regtest.sh` runs Canary's v1 demo end to end on a real Bitcoin Core node in regtest
mode. One index server serves every entry. The other leaves one taproot payment out of
the lists it serves, while its signed record still includes it. `canary check` must name
that server from its own signatures.

### Prerequisites

- **Bitcoin Core v30 or later**, for `bitcoind` and `bitcoin-cli`. On macOS, run
  `brew install bitcoin`. The reference indexer reads `/rest/spenttxouts`, which Core added
  in v30. The script stops with a clear message if `bitcoind` is missing or older.
- **Go**, to build `canary` and `canary-indexer` from this repository.
- **curl**, to ask each indexer how far it has synced.

### Run it

```sh
scripts/demo-regtest.sh              # writes ./demo-out
scripts/demo-regtest.sh ~/canary-run # or any directory that is empty or absent
scripts/demo-regtest.sh --act5       # adds the demo's last act, a block that can't be checked
```

It uses ports 28443 (RPC and REST) and 28444 (P2P, bound to 127.0.0.1) for `bitcoind`,
and 28481 and 28482 for the two indexers. It stops before starting anything if a port is
taken. To use other ports, set `CANARY_DEMO_RPC_PORT`, `CANARY_DEMO_P2P_PORT`,
`CANARY_DEMO_HONEST_PORT` or `CANARY_DEMO_WITHHOLDER_PORT`.

### What it does

1. Builds `canary` and `canary-indexer` into a temporary directory.
2. Starts `bitcoind -regtest -rest=1 -txindex=1 -fallbackfee=0.0001` with a new data
   directory inside that temporary directory.
3. Creates a wallet and mines 200 blocks, so the first block rewards can be spent.
4. Sends 1 BTC to a new taproot (bech32m) address and mines 1 block. It notes the txid
   and the block hash.
5. Makes two throwaway indexer keys with `canary-indexer --gen-key`.
6. Starts an honest indexer, and a second one with `--withhold-txid` set to the payment.
7. Waits until both indexers report Core's tip in `/info`.
8. Runs `canary check` over blocks 0 to the tip, with both servers pinned and the payment
   declared with `--expect TXID@BLOCKHASH`.
9. Runs `canary verify` on the evidence file, then prints `canary status`.

The payment's block stays 0 blocks deep, well inside the 144-block window. The script
never mines 144 or more blocks between the payment and the check, because the
withholder is named only inside that window. Just before the check, it reads Core's tip
again and stops if the block has left the window.

### Act 5: a block that can't be checked

`--act5` adds the demo's last act. It shows the limit of the retention rule: past the
144-block window, a gap that nobody can fill is neither a pass nor an accusation.

1. After step 3, it pays 1 BTC to another taproot address and mines 150 blocks. The
   early payment confirms in the first of them.
2. Steps 4 to 9 run as above. The withholding indexer gets `--withhold-txid` twice: once
   for the main payment, once for the early one.
3. The main check is unchanged. It covers both payments' blocks. The honest server's list
   fills the early gap, so the early block reads Checked. The main payment's block reads
   Data withheld, reason `absent_in_window`, as before.
4. Then it runs a second `canary check` on the early block alone. Only the withholding
   server is pinned, and no payment is declared. Its signed tip puts that block 150 blocks
   deep, outside the window, and Core confirms that tip. No other server or declared
   payment can supply the entry.
5. That block reads Can't be checked, reason `gap_unfilled`. The run has no findings and
   exits 0. The script stops if the result is anything else.

The second check writes to its own `act5/` directory, so the main state file keeps the
main result.

On exit, including Ctrl-C or a failure, it stops both indexers and `bitcoind` and removes
the temporary directory. The secret keys go with it.

### What it produces

The output directory holds:

| Path | Content |
|---|---|
| `state.json` | The state file `canary check` wrote. `canary status` and `canary ui` read it |
| `evidence/omission-regtest-<height>-<txid>-<pubkey>.json` | The evidence file that names the withholding server. `canary verify` checks it offline |
| `check.txt`, `verify.txt`, `status.txt` | What each command printed |
| `logs/honest.log`, `logs/withholder.log` | Each indexer's log. They hold public keys only |
| `run.txt` | The payment's txid, its block, and each server's address and pubkey. With `--act5`, also the early payment and its block |
| `act5/state.json` | With `--act5` only. The state file of the second check: one block, Can't be checked |
| `act5/check.txt`, `act5/status.txt` | With `--act5` only. What the second check and its `canary status` printed |

To see the results in the dashboard, run `go run ./cmd/canary ui --state <dir>/state.json`
from the repository root.

### What the run shows, and what it does not

The run shows `canary check` naming a server from contradictions between the server's own
signed record and its own signed list. The evidence file lets anyone check that offline.

It does not show more than that:

- It runs on regtest, with one Core node feeding both indexers and Canary.
- Both indexers share Canary's `canonical` package, so their agreement tests the protocol,
  not two independent implementations.
- Checked means the tweak list was checked. It never means payments were checked.
