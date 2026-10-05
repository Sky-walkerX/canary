# Draft: GitHub release notes for `v0.1.0`

**Status: draft. [brackets] stay until Monday 5 Oct.** Paste it as the body of the GitHub
release for the tag. Press the two claim checks in the notes below before you publish it.

---

## Canary v0.1.0

A silent-payments light wallet cannot tell "nobody paid you" from "the server left your
payment out". Canary checks the tweak list a server sends against the list that same
server signed and published for that block. When what it sent contradicts what it signed,
Canary names the server and the block.

Canary does not make tweak sourcing trustless. It makes it **accountable**, under two
conditions: at least one honest indexer publishes commitments, and there is an uncensored
path to a relay that carries them.

This is the BOSS Battle submission. **v1 is built and tested on regtest only.** `canary
check` accepts main and prints a notice; it refuses signet.

### Check the evidence in one command

```
go run ./cmd/canary verify evidence/omission-regtest-351-ad56b9bb-db614560.json
```

It prints `Checks out.`, the accused key `db614560…d48c`, block 351 with position 0 and
txid `ad56b9bb…e21e`, and the eight checks that pass. The file needs no node, no server and
no network. Its SHA-256 is `aea26b9bf54926af62eefe09b7fb7bd64540025b052001f52a41f77cac1b9710`.

### The run this release rests on

On 1 Oct 2026, `scripts/demo-regtest.sh --act5` ran end to end on Bitcoin Core v31.1.0 in
regtest mode. Two reference indexers read the same node. One ran with `--withhold-txid`,
left a payment out of the list it served, and still signed that payment into its record
for block 351.

`canary check` covered blocks 0 to 351, with both servers' keys pinned and the payment
declared: **351 Checked · 1 Data withheld**, naming the withholder for block 351. Act 5
checked block 201 against the withholder alone and read **1 Can't be checked**, which is
neither a pass nor an accusation.

The accusation rests on the accused server's own signatures, not on our word: its signed
receipt covers the 269-byte list it served, where that entry's position is marked absent.

### What is in the box

- `canary check`, `verify`, `status` and `ui`: the detection loop, the evidence files and
  the local dashboard.
- A reference indexer that can withhold a chosen transaction, for reproducing the demo.
- The evidence file above, and a CI test that checks it out on every push.
- The public site with the in-browser checker, which runs the same Go verifier compiled
  to WebAssembly, offline: <[site URL]>

### Limits, named now

- **The output side is not checked.** "Checked" means the tweak list was checked. A
  server can serve the right tweak and drop the output a wallet matches against. Fixed in
  v2, which adds output keys to the entry.
- **A hash-only entry under a cut-through policy reads Checked, gap filled.**
- **With one server, a record that leaves your entry out reads Checked.** Only a second
  honest server, or a payment you declare, catches it.
- **A withholder can sign a tip above Core's** and turn an omission into Can't be
  checked. A declared payment still names it.

### Tests

[brackets: recount on 5 Oct with the command in `docs/submission/checklist.md`, then put
the three numbers here] — measured on 1 Oct: 444 top-level tests, 879 cases, 19 packages,
with and without `-race`.

### What is not here

- No mainnet demo, and no relay publication.
- No wallet, no scanner, and nothing that holds a scan key.
- Signet needs a network-ID flag after v1.

### Documentation

[How Canary works](https://github.com/Sky-walkerX/canary/blob/v0.1.0/docs/how-canary-works.md),
the [FAQ](https://github.com/Sky-walkerX/canary/blob/v0.1.0/docs/faq.md), and the
[exact formats](https://github.com/Sky-walkerX/canary/blob/v0.1.0/docs/design/2026-09-30-v1-formats.md).
MIT licensed.

---

## Notes before publishing

1. Fill `[site URL]` from [checklist.md](checklist.md) and the test numbers from the
   Monday recount. The `[brackets]` line stays a bracket until then.
2. Check every claim against `CLAUDE.md`, "Claims and wording". The two that bite:
   *accountable*, not trustless, must lead; and "Checked" never means payments were
   checked.
3. The relay sentence above says no publication happened. If the records reach relays
   before Tuesday, say so here and in the README; until then leave it.
4. The tag must exist before the release: `git tag v0.1.0 && git push origin v0.1.0`.
