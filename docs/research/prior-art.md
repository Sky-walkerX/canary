# Prior art and gap analysis

**Compiled 2026-09-06.** Every claim here was verified against a primary source on that
date. Re-verify before relying on any of it — the point of this document is that the
gap is open *right now*, and that is a perishable fact.

---

## 1. The gap is open, and the BIP says so

- **BIP-352 v1.1.0 (March 2026)** introduced light-client approaches and states the
  trust assumption directly: the indexer can withhold data, preventing the receiver from
  seeing payments.
- **Bitshala's BIP-352 guide (3 August 2026)** — written by the hackathon's own
  organisers — calls trustless light-client tweak sourcing "the big one" among the
  protocol's open problems: *"a light client that accepts tweak data from a server has
  no way to detect omission. Until it is solved, 'privacy-preserving' light client
  scanning means the server cannot see your outputs, not that it cannot withhold them."*
- **Bitcoin Optech #421 (4 September 2026)** — the most recent newsletter at time of
  writing — covers silent payments only in the context of miner payouts via coinbase
  transactions. Nothing on index integrity.
- **Bitcoin Core PR #28241**, "Silent payment index (for light wallets and consistency
  check)" by Sjors — **closed unmerged** on 2025-02-20, still marked draft, `Needs
  rebase` / `CI failed`. Its "consistency check" refers to validating the index
  implementation against test vectors (comparing a checksum of the index across all of
  mainnet), **not** client-side omission detection. No collision.
  <https://github.com/bitcoin/bitcoin/pull/28241>

**Conclusion:** no shipped implementation addresses omission detection.

## 2. The canonical thread analysed the *opposite* attack

[Silent Payments: Light Client Protocol](https://delvingbitcoin.org/t/silent-payments-light-client-protocol/891),
Delving Bitcoin, May–June 2024. Participants: setavenger (protocol author), cygnet3,
josibake, harding.

harding (5 June 2024) laid out three attacks on malicious index servers. **All three are
commission attacks** — injecting fake tweaks or filters so the victim fetches a block and
reveals their network identity:

1. Fake payment to the victim's SP address, with filters built only from the fake payment.
2. Reuse of a legitimate tweak to construct a filter for a transaction not in the block.
3. Dust spam to the target address, tracking who downloads the containing blocks.

His conclusion on multi-server comparison:

> "Downloading tweaks and filters from different servers doesn't help. Even if we can be
> sure the servers aren't colluding, whoever controls the filter distribution server can
> always force a match by lying."

**This is correct for commission and backwards for omission.**

| | Commission | Omission |
|---|---|---|
| Structure | **Union** attack — one liar suffices | **Intersection** attack — one honest source defeats it |
| Multi-server | Does not help | Is precisely the defence |
| Agreed mitigation | Fetch blocks from random nodes over ephemeral Tor | Does nothing — the client never learns to fetch the block |

The thread converged on the Tor block-fetching mitigation and closed. Omission was never
separately analysed. Two years later, both the BIP and Bitshala still list it unsolved.

An auditing approach was raised and rejected in that thread on the grounds that
*"audits only tell you that the server was honest in the past."* That objection applies
to periodic third-party audits. It does not apply to per-block commitments verified by
the client against the data it was actually served, which is what Canary does.

## 3. Why the naive version does not work

Honest indexers legitimately serve **different** tweak sets, so a raw diff produces
nothing but false positives:

- **blindbit-oracle** supports cut-through (dropping a transaction's tweak once all its
  taproot outputs are spent — measured at ~38% of tweaks on mainnet) and configurable
  dust-limit filtering.
- **silentiumd** computes scalars only for transactions containing *unspent* taproot
  outputs — cut-through by default.

Any workable design must define a canonical set. **Superseded 2026-09-07 by §2.1 of the
design doc:** this section originally concluded that servers must declare their policy and
that responses must be *normalised before comparing*. That is the wrong shape. Normalising
two policy-filtered responses against each other cannot distinguish policy from
dishonesty, because both are subtractive and both are permitted. §2 compares committed
*canonical* sets instead and leaves the served sets alone — the policy declaration
survives, but as an excuse that must be published in advance, not as an input to a diff.
This is still real protocol design and still a plausible reason nobody has built it.

**Useful consequence:** a server can commit at index time and prune afterwards. The
commitment survives at 36 bytes per block — a 32-byte root plus the set size — so an
aggressively cut-through server remains accountable for exactly what it dropped.

## 4. The ecosystem is Go

| Project | Language | Status (2026-09-06) | Role |
|---|---|---|---|
| [blindbit-oracle](https://github.com/setavenger/blindbit-oracle) | Go | Active, pushed 2026-07-23; v2 requires Core v30+ REST, unpruned | Primary indexer to fork |
| [silentiumd](https://github.com/louisinger/silentiumd) | Go | Stale, pushed 2025-01-04 | Second implementation — staleness makes divergence *more* likely, which is useful |
| [go-bip352](https://github.com/setavenger/go-bip352) | Go | v0.1.8, verified 2026-09-08 | BIP-352 primitives. **Renamed** — the old `gobip352` path is v0.1.4 and lacks the eligibility functions (§6.4) |
| [BIP0352-light-client-specification](https://github.com/setavenger/BIP0352-light-client-specification) | — | WIP spec | The light-client protocol we extend |

blindbit-oracle's `/info` endpoint already advertises feature flags
(`tweaks_only`, `tweaks_full_basic`, `tweaks_full_with_dust_filter`,
`tweaks_cut_through_with_dust_filter`) and reports `"network": "signet"` — a natural
place to hang a policy declaration.

A working **silent payments signet faucet** exists at
<https://silentpayments.dev/faucet/signet/>, which removes the need for a counterparty
when demonstrating receipt.

## 5. Live infrastructure is decaying

`bitcoin.silentium.dev` — the public mainnet indexer named in the light-client
documentation — **no longer serves the API.** The domain redirects to
`access.silentium.dev`, an unrelated parked page. Verified 2026-09-06:

```
/v1/chain-tip                  len=533 sha=4473e411def3
/v1/block/850000/scalars       len=533 sha=4473e411def3
/totally/fake/path             len=533 sha=4473e411def3
```

Identical 533-byte bodies, HTTP 200, for every path including nonexistent ones. A client
pointed at this host does not get an error. It gets a success response and no payments.

**Design consequence:** do not build the demo on third-party public servers being alive.
Run every indexer locally against a shared signet node.

## 6. Divergence hunting: construct, don't scan

Rather than scanning mainnet hoping an ambiguous transaction appears — which would
require an unpruned node and days of IBD — construct signet transactions that
deliberately hit each ambiguous BIP-352 eligibility corner and check whether the
implementations agree.

The richest known corner: **script-path spends using NUMS point H as the internal key**
are excluded from the input set. A receiver detects this by checking whether the taproot
internal key in the control block equals H. This was contested during BIP design —
*"any exclusion of allowable inputs seems like a footgun"* — and correct handling
requires parsing the control block, which is exactly the kind of rule independent
implementations get wrong differently.

Any disagreement found is a real interop bug worth reporting upstream, and turns the
demo from "here is a mechanism" into "here is what it found."

---

## Sources

- BIP-352: <https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki>
- Bitshala BIP-352 guide, 3 Aug 2026
- Delving Bitcoin thread 891: <https://delvingbitcoin.org/t/silent-payments-light-client-protocol/891>
- Bitcoin Core PR #28241: <https://github.com/bitcoin/bitcoin/pull/28241>
- Bitcoin Optech #421: <https://bitcoinops.org/en/newsletters/2026/09/04/>
- RFC 6962 (Certificate Transparency): <https://www.rfc-editor.org/rfc/rfc6962>
- silentpayments.xyz, BlindBit suite, silentiumd (see table in §4)
