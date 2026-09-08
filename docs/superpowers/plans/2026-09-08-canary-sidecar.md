# Canary Sidecar Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `canaryd`, the proxy that sits between an unmodified light wallet and its indexers, verifies what it is served, reports coverage, and refuses to pass on data it could not verify — plus the `canary` CLI and the offline-verifiable evidence artifact.

**Architecture:** A proxy, not an observer. The wallet points at `canaryd` instead of the indexer, so a component in the data path can refuse to serve unverified data — which is the only answer that works against a wallet that does not know Canary exists. Inside, a four-rung ladder ordered by cost feeds a six-state coverage machine.

**Tech Stack:** Go 1.24+, the Canary protocol core (`canonical`, `commit`, `policy`, `feed`), `net/http`.

**Spec:** [`docs/design/2026-09-06-canary-design.md`](../../design/2026-09-06-canary-design.md) — §2.5, §4, §5, §6.1, §6.2, §6.3.

**Owners:** Dev C for `ladder`, `headers`, coverage, proxy and CLI; Naman for `evidence` and `tripwire`, which §5.3 pairs because the tripwire is what produces a node-free artifact (§6.5). **Weeks 2–3** (§6.6).

**Depends on:** the `canonical`, `commit`, `policy`, `feed` and `wire` packages from Plan A. `wire` is the contract with the indexer fork: Plan B encodes, this plan decodes, and neither owns the type.

## Global Constraints

- **Resolve gaps BEFORE recomputing the root.** This ordering is load-bearing and is the single most important rule in this plan. A block whose root was never recomputed is *unresolvable*, never clean (§2.5).
- **Tolerance governs effort and reporting, never verification.** A tip-following client may chase a gap less hard and report it more quietly. Neither mode may skip the root recomputation (§2.5).
- **`headers` is NOT an SPV chain.** No proof-of-work validation, no most-work rule. It is a store of `(height, hash)` observations plus the contested-past-six-confirmations rule (§4.6).
- **Root divergence names two servers without saying which lied.** It must never trigger automatic exclusion — that is how an attacker gets an honest server dropped (§4.5).
- **Comparison is keyed on block hash, not height** (§2.5, §2.7).
- **The wire format comes from the core's `wire` package**, never from the fork's `internal/` tree — Go forbids importing another module's internal packages, so an import of `blindbit-oracle/internal/server` will not compile here.
- **The evidence artifact verifies offline.** `canary verify <file>` opens no socket (§4.7).
- **Never trust `created_at`** for ordering or freshness (§3.5).
- **Indexer identity is pinned manually** — a set of `(indexer_url, indexer_nostr_pubkey)` pairs. No discovery, no trust-on-first-use (§3.6).

---

## File Structure

| Path | Responsibility |
|---|---|
| `headers/headers.go` | `(height, hash)` observations and the contested-past-6 rule |
| `ladder/compare.go` | §2.5's comparison procedure, ordering enforced |
| `ladder/coverage.go` | The six coverage states and their aggregation |
| `ladder/alarm.go` | Alarms keyed on `(server, block, txid)`, and the exclusion asymmetry |
| `ladder/crosscheck.go` | §2.5 step 5's cross-server root comparison and §4.3's union |
| `evidence/artifact.go` | The §4.7 artifact: build, marshal, verify offline |
| `tripwire/assert.go` | Expected-payment assertions and the three innocent explanations |
| `tripwire/schedule.go` | The Poisson scheduler |
| `proxy/proxy.go` | The blindbit-facing HTTP surface and refuse-in-path |
| `cmd/canaryd/main.go` | Daemon wiring |
| `cmd/canary/main.go` | `canary status`, `canary verify <file>`, `canary probe` |

---

### Task 1: `headers` — chain agreement without SPV

**Files:**
- Create: `headers/headers.go`
- Test: `headers/headers_test.go`

**Interfaces:**
- Consumes: `feed.Commitment`.
- Produces: `type Store`, `func New() *Store`, `func (s *Store) Observe(author [32]byte, height uint32, hash [32]byte)`, `func (s *Store) Pin(height uint32, hash [32]byte)`, `func (s *Store) Status(height uint32, tip uint32) ChainStatus`, and `type ChainStatus` with `Agreed`, `Contested`, `Contradicted`, `Unknown`.

**Why this is not SPV.** An earlier design said *"Canary maintains its own header chain — 80 bytes per block, PoW-verified, standard SPV."* That is false where we run: a BIP-325 signet gets its integrity from a challenge signature in the coinbase, not from accumulated work, and a laptop can outrun the real chain. Chain agreement is an **output**, not an input: reorgs resolve, lies persist, and a height still contested six confirmations later is a signed chain contradiction (§4.6).

- [ ] **Step 1: Write the failing test**

```go
// headers/headers_test.go
package headers

import "testing"

func author(b byte) [32]byte {
	var a [32]byte
	a[0] = b
	return a
}

func hash(b byte) [32]byte {
	var h [32]byte
	h[0] = b
	return h
}

func TestAgreementWhenEveryoneSaysTheSameThing(t *testing.T) {
	s := New()
	s.Observe(author(1), 100, hash(0xAA))
	s.Observe(author(2), 100, hash(0xAA))

	if got := s.Status(100, 101); got != Agreed {
		t.Errorf("status = %v, want Agreed", got)
	}
}

func TestDisagreementNearTheTipIsContestedNotContradicted(t *testing.T) {
	s := New()
	s.Observe(author(1), 100, hash(0xAA))
	s.Observe(author(2), 100, hash(0xBB))

	// Two blocks on: this is what a reorg looks like, and reporting it as an
	// attack would be the loudest possible false positive (§4.6).
	if got := s.Status(100, 102); got != Contested {
		t.Errorf("status at tip 102 = %v, want Contested", got)
	}
}

func TestDisagreementPastSixConfirmationsIsAContradiction(t *testing.T) {
	s := New()
	s.Observe(author(1), 100, hash(0xAA))
	s.Observe(author(2), 100, hash(0xBB))

	// Reorgs resolve; lies persist. Six deep, this is a signed statement about
	// the chain contradicted by another signed statement (§4.6).
	if got := s.Status(100, 106); got != Contradicted {
		t.Errorf("status at tip 106 = %v, want Contradicted", got)
	}
}

func TestPinIsAuthoritativeAgainstASingleServer(t *testing.T) {
	s := New()
	// One server, so convergence has nothing to work with. The pin is the one
	// chain fact Canary did not learn from an indexer (§4.6).
	s.Pin(100, hash(0xAA))
	s.Observe(author(1), 100, hash(0xBB))

	if got := s.Status(100, 200); got != Contradicted {
		t.Errorf("status = %v, want Contradicted — the server disagrees with the pin", got)
	}
}

func TestUnknownHeightIsUnknownNotAgreed(t *testing.T) {
	s := New()
	if got := s.Status(999, 1000); got != Unknown {
		t.Errorf("status = %v, want Unknown — no observation is not agreement", got)
	}
}

func TestSingleObserverIsNotAgreement(t *testing.T) {
	s := New()
	s.Observe(author(1), 100, hash(0xAA))

	// One server agreeing with itself proves nothing. Without a second source
	// or a pin, chain membership rests on §4.6's anchor and is not derivable.
	if got := s.Status(100, 200); got != Unknown {
		t.Errorf("status = %v, want Unknown for a lone observer", got)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./headers/ -v`
Expected: FAIL — the package does not exist.

- [ ] **Step 3: Write the implementation**

```go
// headers/headers.go
//
// Package headers records (height, hash) observations and decides whether a
// height is agreed, transiently contested, or permanently contradicted.
//
// This is NOT an SPV chain. There is no proof-of-work validation and no
// most-work rule, because on a BIP-325 signet integrity comes from the
// challenge signature in the coinbase rather than from accumulated work, and a
// laptop can outrun the real chain. Asserting a security property that does not
// hold is worse than asserting none (§4.6).
package headers

import "sync"

// ConfirmationDepth is where "contested" becomes "contradicted". Reorgs resolve
// within a few blocks; a lie persists (§4.6).
const ConfirmationDepth = 6

type ChainStatus int

const (
	Unknown      ChainStatus = iota // no observation, or only one observer
	Agreed                          // every observer names the same hash
	Contested                       // observers disagree, still within the reorg window
	Contradicted                    // observers disagree past six confirmations, or one contradicts the pin
)

func (c ChainStatus) String() string {
	switch c {
	case Agreed:
		return "agreed"
	case Contested:
		return "contested"
	case Contradicted:
		return "contradicted"
	default:
		return "unknown"
	}
}

type Store struct {
	mu   sync.RWMutex
	obs  map[uint32]map[[32]byte][32]byte // height -> author -> hash
	pins map[uint32][32]byte
}

func New() *Store {
	return &Store{
		obs:  map[uint32]map[[32]byte][32]byte{},
		pins: map[uint32][32]byte{},
	}
}

// Observe records that author names hash at height. The observations come from
// the commitment feed, which already carries both — so this costs nothing new
// to detect (§4.6).
func (s *Store) Observe(a [32]byte, height uint32, h [32]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.obs[height] == nil {
		s.obs[height] = map[[32]byte][32]byte{}
	}
	s.obs[height][a] = h
}

// Pin records a (height, hash) obtained out of band — from the user's own Core
// node, or typed in by hand. This is the anchor of §4.6, and the model §3.6
// already chose for indexer identity.
func (s *Store) Pin(height uint32, h [32]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pins[height] = h
}

func (s *Store) Status(height, tip uint32) ChainStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()

	at := s.obs[height]
	pin, pinned := s.pins[height]

	if len(at) == 0 {
		return Unknown
	}

	// A pin beats convergence: any server disagreeing with it is contradicted
	// immediately, with no waiting period, because the pin is not a guess.
	if pinned {
		for _, h := range at {
			if h != pin {
				return Contradicted
			}
		}
		return Agreed
	}

	// Convergence needs two observers. One server agreeing with itself is not
	// agreement — under a single server chain membership is not derivable from
	// the indexer set at all (§4.6).
	if len(at) < 2 {
		return Unknown
	}

	var first [32]byte
	firstSet := false
	for _, h := range at {
		if !firstSet {
			first, firstSet = h, true
			continue
		}
		if h != first {
			if tip >= height+ConfirmationDepth {
				return Contradicted
			}
			return Contested
		}
	}
	return Agreed
}
```

- [ ] **Step 4: Run the tests and commit**

```bash
go test ./headers/ -v
git add headers/
git commit -m "feat(headers): chain agreement as an output, not an SPV chain"
```

---

### Task 2: `ladder` — §2.5's comparison procedure, with the ordering enforced

**Files:**
- Create: `ladder/compare.go`
- Test: `ladder/compare_test.go`

**Interfaces:**
- Consumes: `feed.Commitment`, `commit.RootFromLeafHashes`, `commit.LeafHash`, `policy.Policy`, and `wire.Position` from the protocol core.
- Produces: `type Verdict` with `Clean`, `OmissionDetected`, `Unresolvable`, `Refused`, `Unverified`; `type GapFiller interface { Fill(blockHash [32]byte, index uint32) (canonical.Leaf, bool) }`; `func Compare(in CompareInput) (Result, error)`.

**This is the most important task in the plan.** An earlier draft of §2.5 recomputed the root first and resolved gaps last. A position returned as a hole then made the root uncomputable, so the block was silently never verified — and step 3 is the only rung that catches targeted omission. A server that could reach the recomputation first and decline had a free, permanent way never to be verified, which is exactly the attack this project exists to catch.

The tests below lock the ordering, not just the outcome.

- [ ] **Step 1: Write the failing test**

```go
// ladder/compare_test.go
package ladder

import (
	"testing"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/Sky-walkerX/canary/commit"
	"github.com/Sky-walkerX/canary/feed"
	"github.com/Sky-walkerX/canary/policy"
	"github.com/Sky-walkerX/canary/wire"
)

const netRegtest = canonical.Network(0xdab5bffa)

func mkLeaves(n int) []canonical.Leaf {
	out := make([]canonical.Leaf, n)
	for i := range out {
		out[i].TxID[0] = byte(i + 1)
		out[i].Tweak[0] = 0x02
		out[i].Tweak[1] = byte(i)
	}
	return out
}

func fullPositions(leaves []canonical.Leaf) []wire.Position {
	out := make([]wire.Position, len(leaves))
	for i, l := range leaves {
		out[i] = wire.Position{Kind: wire.KindFull, Leaf: l}
	}
	return out
}

// recordingFiller notes whether it was consulted, and when.
type recordingFiller struct {
	leaves map[uint32]canonical.Leaf
	called bool
}

func (f *recordingFiller) Fill(_ [32]byte, i uint32) (canonical.Leaf, bool) {
	f.called = true
	l, ok := f.leaves[i]
	return l, ok
}

func baseInput(leaves []canonical.Leaf, positions []wire.Position) CompareInput {
	var bh [32]byte
	bh[0] = 0x42
	return CompareInput{
		Network:   netRegtest,
		BlockHash: bh,
		Commitment: &feed.Commitment{
			Network:   netRegtest,
			BlockHash: bh,
			N:         uint32(len(leaves)),
			Root:      commit.Root(netRegtest, bh, leaves),
		},
		Positions:      positions,
		Policy:         policy.Policy{PrunesSpent: true},
		CommitsNearby:  true,
		Filler:         &recordingFiller{},
	}
}

func TestCleanWhenEveryPositionIsServed(t *testing.T) {
	leaves := mkLeaves(4)
	in := baseInput(leaves, fullPositions(leaves))

	res, err := Compare(in)
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != Clean {
		t.Errorf("verdict = %v, want Clean", res.Verdict)
	}
	if !res.RootRecomputed {
		t.Error("a Clean verdict requires the root to have been recomputed")
	}
}

// The ordering test. A gap must be filled BEFORE the root is recomputed.
func TestGapIsResolvedBeforeTheRootIsRecomputed(t *testing.T) {
	leaves := mkLeaves(4)
	pos := fullPositions(leaves)
	pos[2] = wire.Position{Kind: wire.KindAbsent}

	in := baseInput(leaves, pos)
	filler := &recordingFiller{leaves: map[uint32]canonical.Leaf{2: leaves[2]}}
	in.Filler = filler

	res, err := Compare(in)
	if err != nil {
		t.Fatal(err)
	}
	if !filler.called {
		t.Fatal("the filler was never consulted — gaps must be resolved, not skipped")
	}
	if res.Verdict != Clean {
		t.Errorf("verdict = %v, want Clean after the gap was filled", res.Verdict)
	}
	if !res.RootRecomputed {
		t.Error("the root must be recomputed once the gap is filled")
	}
	if !res.GapsResolved {
		t.Error("result must record that a gap existed and was resolved")
	}
}

// The hole this ordering closes. An unfillable gap is NOT clean.
func TestUnfillableGapIsUnresolvableNotClean(t *testing.T) {
	leaves := mkLeaves(4)
	pos := fullPositions(leaves)
	pos[1] = wire.Position{Kind: wire.KindAbsent}

	in := baseInput(leaves, pos)
	in.Filler = &recordingFiller{leaves: map[uint32]canonical.Leaf{}} // fills nothing

	res, err := Compare(in)
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != Unresolvable {
		t.Errorf("verdict = %v, want Unresolvable", res.Verdict)
	}
	if res.RootRecomputed {
		t.Error("the root cannot have been recomputed with a position still missing")
	}
	if res.Verdict == Clean {
		t.Fatal("an unfilled gap must never read as clean — this is the §2.5 hole")
	}
}

// A retained hash fills the gap from the server's own data, with no second server.
func TestRetainedHashFillsTheGapWithoutASecondServer(t *testing.T) {
	leaves := mkLeaves(4)
	pos := fullPositions(leaves)
	pos[3] = wire.Position{Kind: wire.KindHash, Hash: commit.LeafHash(leaves[3])}

	in := baseInput(leaves, pos)
	filler := &recordingFiller{}
	in.Filler = filler

	res, err := Compare(in)
	if err != nil {
		t.Fatal(err)
	}
	if filler.called {
		t.Error("a retained hash needs no second server — the filler should not be consulted")
	}
	if res.Verdict != Clean {
		t.Errorf("verdict = %v, want Clean", res.Verdict)
	}
}

func TestOmissionDetectedWhenTheRootDisagrees(t *testing.T) {
	leaves := mkLeaves(4)
	pos := fullPositions(leaves)
	// The server serves a DIFFERENT leaf at position 1 — served ≠ committed.
	var wrong canonical.Leaf
	wrong.TxID[0] = 0xFF
	wrong.Tweak[0] = 0x03
	pos[1] = wire.Position{Kind: wire.KindFull, Leaf: wrong}

	res, err := Compare(baseInput(leaves, pos))
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != OmissionDetected {
		t.Errorf("verdict = %v, want OmissionDetected", res.Verdict)
	}
	// Proven against the server's own signature, from that one server alone.
	if !res.RootRecomputed {
		t.Error("the accusation rests on a recomputed root")
	}
}

// §2.5 step 0, the three cases.
func TestStepZeroNeverCommittedIsUnverifiedNotRefused(t *testing.T) {
	leaves := mkLeaves(2)
	in := baseInput(leaves, fullPositions(leaves))
	in.Commitment = nil
	in.CommitsNearby = false

	res, err := Compare(in)
	if err != nil {
		t.Fatal(err)
	}
	// Refusing here would refuse 100% of unmodified blindbit and contradict
	// §0's "requires nobody's cooperation" (§2.5 step 0).
	if res.Verdict != Unverified {
		t.Errorf("verdict = %v, want Unverified", res.Verdict)
	}
	if res.Verdict == Clean {
		t.Error("Unverified is never Clean — nothing about the data was checked")
	}
}

func TestStepZeroSelectiveNonPublicationIsRefused(t *testing.T) {
	leaves := mkLeaves(2)
	in := baseInput(leaves, fullPositions(leaves))
	in.Commitment = nil
	in.CommitsNearby = true // commits for neighbours, but not for this block

	res, err := Compare(in)
	if err != nil {
		t.Fatal(err)
	}
	// Commit to every block except the one you lied about — that IS the attack.
	if res.Verdict != Refused {
		t.Errorf("verdict = %v, want Refused", res.Verdict)
	}
}

func TestPolicyContradictionRaisesAnAlarm(t *testing.T) {
	leaves := mkLeaves(4)
	pos := fullPositions(leaves)
	pos[2] = wire.Position{Kind: wire.KindHash, Hash: commit.LeafHash(leaves[2])}

	in := baseInput(leaves, pos)
	in.Policy = policy.Policy{PrunesSpent: false, DustThresholdSat: 0} // declares a full index

	res, err := Compare(in)
	if err != nil {
		t.Fatal(err)
	}
	// A server declaring no subtraction that shows any gap has contradicted
	// itself. Local and immediate, no second server needed (§2.3, §2.5 step 4).
	if !res.PolicyContradiction {
		t.Error("a gap under a declared full index must raise the policy alarm")
	}
}

func TestResponseLengthMustMatchTheCommitment(t *testing.T) {
	leaves := mkLeaves(4)
	in := baseInput(leaves, fullPositions(leaves)[:3]) // one position short

	res, err := Compare(in)
	if err == nil && res.Verdict == Clean {
		t.Error("a response shorter than n must not read as clean — it is indistinguishable from a smaller block (§2.4)")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./ladder/ -v`
Expected: FAIL — the package does not exist.

- [ ] **Step 3: Write the implementation**

```go
// ladder/compare.go
package ladder

import (
	"fmt"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/Sky-walkerX/canary/commit"
	"github.com/Sky-walkerX/canary/feed"
	"github.com/Sky-walkerX/canary/policy"
	"github.com/Sky-walkerX/canary/wire"
)

type Verdict int

const (
	Unverified       Verdict = iota // no commitment, and none claimed (§2.5 step 0)
	Refused                         // commits for neighbours but not here (§2.5 step 0)
	Clean                           // root recomputed over all n and matched
	OmissionDetected                // named server, block, position
	Unresolvable                    // a gap nobody can fill; the root was never recomputed
)

func (v Verdict) String() string {
	switch v {
	case Refused:
		return "refused"
	case Clean:
		return "clean"
	case OmissionDetected:
		return "omission-detected"
	case Unresolvable:
		return "unresolvable"
	default:
		return "unverified"
	}
}

// GapFiller recovers a missing leaf from somewhere else.
//
// The source is never trusted: the candidate is hashed and the root recomputed,
// so a match proves the leaf against the FIRST server's own signature (§2.4).
type GapFiller interface {
	Fill(blockHash [32]byte, index uint32) (canonical.Leaf, bool)
}

type CompareInput struct {
	Network    canonical.Network
	BlockHash  [32]byte
	Commitment *feed.Commitment // nil when the server published none for this block
	Positions  []wire.Position
	Policy     policy.Policy
	Filler     GapFiller

	// CommitsNearby reports whether this server published commitments for
	// neighbouring blocks. It is the difference between a server that does not
	// participate and one that skipped exactly this block (§2.5 step 0).
	CommitsNearby bool
}

type Result struct {
	Verdict             Verdict
	RootRecomputed      bool
	GapsResolved        bool
	PolicyContradiction bool
	MissingIndexes      []uint32
	Recomputed          [32]byte
}

// Compare runs §2.5 for one (server, block).
//
// The step order is not an implementation detail. Gaps are resolved BEFORE the
// root is recomputed, because the recomputation is the only rung that catches
// targeted omission — and a server that could reach it first and decline would
// have a free, permanent way never to be verified (§2.5).
func Compare(in CompareInput) (Result, error) {
	var res Result

	// Step 0. Three cases, and only the middle one is a refusal.
	if in.Commitment == nil {
		if in.CommitsNearby {
			// Selective non-publication IS the attack: commit to every block
			// except the one you lied about.
			res.Verdict = Refused
			return res, nil
		}
		// Never commits and claims none. The data is still used — it feeds
		// §4.3's union — but nothing about it is checked. Never clean.
		res.Verdict = Unverified
		return res, nil
	}

	n := int(in.Commitment.N)
	if len(in.Positions) != n {
		// A response merely shorter than n is indistinguishable from a smaller
		// block, and under a single server nothing else would catch it (§2.4).
		res.Verdict = Unresolvable
		return res, fmt.Errorf("ladder: response has %d positions, commitment declares n=%d",
			len(in.Positions), n)
	}

	// Step 1. The gap set: positions not returned in full.
	hashes := make([][32]byte, n)
	haveHash := make([]bool, n)
	gapCount := 0

	for i, p := range in.Positions {
		switch p.Kind {
		case wire.KindFull:
			hashes[i] = commit.LeafHash(p.Leaf)
			haveHash[i] = true
		case wire.KindHash:
			// The server pruned the leaf but retained its hash. That is enough
			// to recompute the root from this one server alone (§2.4).
			hashes[i] = p.Hash
			haveHash[i] = true
			gapCount++
		case wire.KindAbsent:
			gapCount++
		default:
			return res, fmt.Errorf("ladder: position %d has unknown kind %d", i, p.Kind)
		}
	}

	// Step 4, computed here because it depends only on the gap set: a server
	// declaring no subtraction that shows any gap has contradicted itself.
	// Local, immediate, no second server (§2.3).
	if gapCount > 0 && !in.Policy.PrunesSpent && in.Policy.DustThresholdSat == 0 {
		res.PolicyContradiction = true
	}

	// Step 2. Resolve the gaps. THIS RUNS BEFORE THE RECOMPUTATION.
	for i := 0; i < n; i++ {
		if haveHash[i] {
			continue
		}
		if in.Filler == nil {
			res.MissingIndexes = append(res.MissingIndexes, uint32(i))
			continue
		}
		leaf, ok := in.Filler.Fill(in.BlockHash, uint32(i))
		if !ok {
			res.MissingIndexes = append(res.MissingIndexes, uint32(i))
			continue
		}
		hashes[i] = commit.LeafHash(leaf)
		haveHash[i] = true
		res.GapsResolved = true
	}

	if len(res.MissingIndexes) > 0 {
		// A gap nobody can fill. The root cannot be recomputed, so there is no
		// verdict — an ecosystem gap, deliberately not an accusation, and
		// equally deliberately not a pass (§2.5).
		res.Verdict = Unresolvable
		return res, nil
	}

	// Step 3. Recompute the root over all n positions.
	root := commit.RootFromLeafHashes(in.Network, in.BlockHash, hashes)
	res.Recomputed = root
	res.RootRecomputed = true

	if root != in.Commitment.Root {
		// Served ≠ committed, proven against the server's own signature. This
		// is the rung that catches targeted omission (§3.1, §1.4).
		res.Verdict = OmissionDetected
		return res, nil
	}

	res.Verdict = Clean
	return res, nil
}
```

- [ ] **Step 4: Confirm the leaf-hash root helper exists**

`Compare` works from leaf *hashes* rather than leaves, because a gap filled from
a server's retained hash never yields the leaf itself. That helper is
`commit.RootFromLeafHashes`, built in **Plan A Task 4** alongside `Root` and
tested against it for every set size — the two paths must never drift.

Run: `go doc github.com/Sky-walkerX/canary/commit RootFromLeafHashes`
Expected: the signature `func RootFromLeafHashes(net canonical.Network, blockHash [32]byte, leafHashes [][32]byte) [32]byte`. If it is missing, Plan A Task 4 has not landed and this task is blocked.

Step 3's `Compare` calls it as `commit.RootFromLeafHashes`.

- [ ] **Step 5: Run the tests and commit**

```bash
go test ./ladder/ ./commit/ -v
git add ladder/compare.go ladder/compare_test.go commit/
git commit -m "feat(ladder): §2.5 comparison with gap resolution before recomputation"
```

---

### Task 3: Coverage — the six states

**Files:**
- Create: `ladder/coverage.go`
- Test: `ladder/coverage_test.go`

**Interfaces:**
- Consumes: `Verdict` from Task 2.
- Produces: `type State`, `func FromVerdict(v Verdict) State`, `type Coverage struct { ... }`, `func (c *Coverage) Record(server [32]byte, height uint32, s State)`, `func (c *Coverage) Summary() Summary`.

**Why coverage rather than alarms (§4.4).** An alarm that never fires looks like a product that does nothing. Coverage is continuous, and it yields the line worth leading with: a balance computed over blocks that could not be verified is a lower bound, not a balance.

**The mapping from §2.5.** Comparison returns three terminal states per `(server, block)`; coverage aggregates them and adds two that comparison never produces. `Clean` becomes **Verified** where no gap existed and **Resolved** where one was filled. `Unresolvable` carries across. `OmissionDetected` becomes **Compromised**. **Unverified** comes from step 0 and **Disputed** from step 5.

- [ ] **Step 1: Write the failing test**

```go
// ladder/coverage_test.go
package ladder

import "testing"

func TestVerdictToStateMapping(t *testing.T) {
	cases := []struct {
		verdict Verdict
		gaps    bool
		want    State
	}{
		{Clean, false, Verified},
		{Clean, true, Resolved},
		{Unresolvable, false, StateUnresolvable},
		{OmissionDetected, false, Compromised},
		{Unverified, false, StateUnverified},
		{Refused, false, StateUnverified},
	}
	for _, c := range cases {
		if got := StateFor(c.verdict, c.gaps); got != c.want {
			t.Errorf("StateFor(%v, gaps=%v) = %v, want %v", c.verdict, c.gaps, got, c.want)
		}
	}
}

func TestUnresolvableIsNeitherPassNorAccusation(t *testing.T) {
	if StateUnresolvable == Verified || StateUnresolvable == Resolved {
		t.Error("unresolvable must not count as verified")
	}
	if StateUnresolvable == Compromised || StateUnresolvable == Disputed {
		t.Error("unresolvable must not count as an accusation")
	}
	if StateUnresolvable.IsVerified() {
		t.Error("IsVerified must be false for unresolvable — the root was never recomputed")
	}
}

func TestDisputedIsSeparateFromCompromised(t *testing.T) {
	// Root divergence names two servers without saying which lied. Collapsing
	// that into one alarm is exactly how an attacker gets an honest server
	// excluded (§4.4, §4.5).
	if Disputed == Compromised {
		t.Fatal("Disputed and Compromised must be distinct states")
	}
	if Disputed.Attributable() {
		t.Error("Disputed is not attributable — it names two servers")
	}
	if !Compromised.Attributable() {
		t.Error("Compromised is attributable — it names one server")
	}
}

func TestSummaryReportsALowerBoundWhenAnythingIsUnverified(t *testing.T) {
	c := NewCoverage()
	var s1 [32]byte
	s1[0] = 1

	c.Record(s1, 100, Verified)
	c.Record(s1, 101, Verified)
	if c.Summary().BalanceIsLowerBound {
		t.Error("fully verified coverage yields a real balance, not a lower bound")
	}

	c.Record(s1, 102, StateUnresolvable)
	if !c.Summary().BalanceIsLowerBound {
		t.Error("any unverified block makes the balance a lower bound (§4.4)")
	}
}

func TestSummaryCountsPerState(t *testing.T) {
	c := NewCoverage()
	var s1 [32]byte
	c.Record(s1, 1, Verified)
	c.Record(s1, 2, Resolved)
	c.Record(s1, 3, StateUnverified)

	sum := c.Summary()
	if sum.Counts[Verified] != 1 || sum.Counts[Resolved] != 1 || sum.Counts[StateUnverified] != 1 {
		t.Errorf("counts wrong: %+v", sum.Counts)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./ladder/ -run 'TestVerdictTo|TestUnresolvable|TestDisputed|TestSummary' -v`
Expected: FAIL — `undefined: State`.

- [ ] **Step 3: Write the implementation**

```go
// ladder/coverage.go
package ladder

import "sync"

// State is a coverage state. Six of them, because §4.4 and §4.5 keep Disputed
// and Compromised apart on purpose.
type State int

const (
	StateUnverified   State = iota // no commitment available; data used but unchecked
	Verified                       // root agreed, served set complete
	Resolved                       // a gap existed, was filled, and the root checked
	StateUnresolvable              // a gap nobody could fill; the root was never recomputed
	Disputed                       // roots diverge — two named servers, unattributed
	Compromised                    // attributed — one named server, one named block
)

func (s State) String() string {
	switch s {
	case Verified:
		return "verified"
	case Resolved:
		return "resolved"
	case StateUnresolvable:
		return "unresolvable"
	case Disputed:
		return "disputed"
	case Compromised:
		return "compromised"
	default:
		return "unverified"
	}
}

// IsVerified is true only where the root was actually recomputed and matched.
// Unresolvable is deliberately excluded: it is not a pass.
func (s State) IsVerified() bool { return s == Verified || s == Resolved }

// Attributable reports whether the state names a single guilty server.
// Disputed does not, which is why §4.5 forbids acting on it automatically.
func (s State) Attributable() bool { return s == Compromised }

// StateFor maps a §2.5 verdict onto a coverage state. gaps distinguishes a
// clean block that needed no filling from one that did.
func StateFor(v Verdict, gaps bool) State {
	switch v {
	case Clean:
		if gaps {
			return Resolved
		}
		return Verified
	case OmissionDetected:
		return Compromised
	case Unresolvable:
		return StateUnresolvable
	default: // Unverified, Refused
		return StateUnverified
	}
}

type Summary struct {
	Counts map[State]int
	// BalanceIsLowerBound is the line worth leading with: a balance computed
	// over blocks that could not be verified is a lower bound, not a balance
	// (§4.4). A wallet with such ranges says so rather than printing a
	// confident number.
	BalanceIsLowerBound bool
}

type key struct {
	server [32]byte
	height uint32
}

type Coverage struct {
	mu     sync.RWMutex
	states map[key]State
}

func NewCoverage() *Coverage {
	return &Coverage{states: map[key]State{}}
}

func (c *Coverage) Record(server [32]byte, height uint32, s State) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.states[key{server, height}] = s
}

func (c *Coverage) Summary() Summary {
	c.mu.RLock()
	defer c.mu.RUnlock()

	sum := Summary{Counts: map[State]int{}}
	for _, s := range c.states {
		sum.Counts[s]++
		if !s.IsVerified() {
			sum.BalanceIsLowerBound = true
		}
	}
	return sum
}
```

- [ ] **Step 4: Run the tests and commit**

```bash
go test ./ladder/ -v
git add ladder/coverage.go ladder/coverage_test.go
git commit -m "feat(ladder): six-state coverage with the lower-bound rule"
```

---

### Task 4: Alarms and the exclusion asymmetry

**Files:**
- Create: `ladder/alarm.go`
- Test: `ladder/alarm_test.go`

**Interfaces:**
- Consumes: `State`.
- Produces: `type Alarm struct { Server [32]byte; BlockHash [32]byte; TxID [32]byte; Kind AlarmKind }`, `func (s *Alarms) Raise(a Alarm)`, `func (s *Alarms) All() []Alarm`, `func (s *Alarms) ShouldDownRank(server [32]byte) bool`.

**The asymmetry (§4.5).** Automatic exclusion of a misbehaving server is itself an attack vector: if a third party can induce the detection, they can knock out honest servers and leave the victim with the attacker's. A self-consistency failure is attributable from the server's own signature against its own data, so it is safe to down-rank. Root divergence is not, and triggers nothing until rung 4 attributes it.

- [ ] **Step 1: Write the failing test**

```go
// ladder/alarm_test.go
package ladder

import "testing"

func TestAlarmsDeduplicateOnServerBlockTxid(t *testing.T) {
	a := NewAlarms()
	var srv, blk, tx [32]byte
	srv[0], blk[0], tx[0] = 1, 2, 3

	al := Alarm{Server: srv, BlockHash: blk, TxID: tx, Kind: SelfConsistencyFailure}
	a.Raise(al)
	a.Raise(al)
	a.Raise(al)

	if got := len(a.All()); got != 1 {
		t.Errorf("stored %d alarms, want 1 — dedup is on (server, block, txid) (§4.5)", got)
	}
}

func TestSelfConsistencyFailureIsSafeToDownRank(t *testing.T) {
	a := NewAlarms()
	var srv, blk [32]byte
	srv[0] = 7

	a.Raise(Alarm{Server: srv, BlockHash: blk, Kind: SelfConsistencyFailure})
	if !a.ShouldDownRank(srv) {
		t.Error("a self-consistency failure is attributable from the server's own signature")
	}
}

func TestRootDivergenceNeverTriggersAutomaticAction(t *testing.T) {
	a := NewAlarms()
	var s1, s2, blk [32]byte
	s1[0], s2[0] = 1, 2

	a.Raise(Alarm{Server: s1, BlockHash: blk, Kind: RootDivergence})
	a.Raise(Alarm{Server: s2, BlockHash: blk, Kind: RootDivergence})

	// It names two servers without saying which lied. Acting on it is how an
	// attacker gets the honest server excluded and leaves the victim with theirs.
	if a.ShouldDownRank(s1) || a.ShouldDownRank(s2) {
		t.Error("root divergence must trigger no automatic action until rung 4 attributes it")
	}
	if len(a.All()) != 2 {
		t.Error("both servers are still recorded — the evidence is kept, only the action is withheld")
	}
}

func TestAlarmsAreNeverAutoCleared(t *testing.T) {
	a := NewAlarms()
	var srv, blk [32]byte
	a.Raise(Alarm{Server: srv, BlockHash: blk, Kind: SelfConsistencyFailure})

	// There is no Clear method by design. Evidence does not decay (§4.2), and
	// an alarm that clears itself is an alarm an attacker waits out.
	if len(a.All()) != 1 {
		t.Error("alarms persist")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./ladder/ -run TestAlarm -v`
Expected: FAIL — `undefined: NewAlarms`.

- [ ] **Step 3: Write the implementation**

```go
// ladder/alarm.go
package ladder

import "sync"

type AlarmKind int

const (
	// SelfConsistencyFailure: the server's own data contradicts its own
	// signature. Attributable from that one server alone.
	SelfConsistencyFailure AlarmKind = iota
	// RootDivergence: two servers committed different roots for the same block.
	// One is lying; this does not say which.
	RootDivergence
	// PolicyContradiction: a gap under a declared full index (§2.3).
	PolicyContradiction
	// ChainContradiction: a height still contested past six confirmations (§4.6).
	ChainContradiction
)

// Alarm is a fact about (server, block, txid). Persisted, deduplicated on that
// triple, never auto-cleared — evidence does not decay (§4.2, §4.5).
type Alarm struct {
	Server    [32]byte
	BlockHash [32]byte
	TxID      [32]byte
	Kind      AlarmKind
}

type Alarms struct {
	mu    sync.RWMutex
	seen  map[Alarm]bool
	order []Alarm
}

func NewAlarms() *Alarms {
	return &Alarms{seen: map[Alarm]bool{}}
}

func (s *Alarms) Raise(a Alarm) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen[a] {
		return
	}
	s.seen[a] = true
	s.order = append(s.order, a)
}

func (s *Alarms) All() []Alarm {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Alarm, len(s.order))
	copy(out, s.order)
	return out
}

// ShouldDownRank reports whether a server may be automatically demoted.
//
// Only attributable alarms qualify. Automatic exclusion is itself an attack
// vector: a third party who can induce the detection can knock out honest
// servers and leave the victim with the attacker's (§4.5). Root divergence
// names two servers without saying which lied, so it triggers nothing.
func (s *Alarms) ShouldDownRank(server [32]byte) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, a := range s.order {
		if a.Server != server {
			continue
		}
		if a.Kind == SelfConsistencyFailure || a.Kind == PolicyContradiction {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run the tests and commit**

```bash
go test ./ladder/ -v
git add ladder/alarm.go ladder/alarm_test.go
git commit -m "feat(ladder): alarms with the automatic-exclusion asymmetry"
```

---

### Task 5: The evidence artifact and offline verification

**Files:**
- Create: `evidence/artifact.go`
- Test: `evidence/artifact_test.go`

**Interfaces:**
- Consumes: `feed.Commitment`, `commit.Prove`, `commit.VerifyProof`.
- Produces: `type Artifact`, `func Build(in BuildInput) (Artifact, error)`, `func (a Artifact) Verify() error`, `func Load(path string) (Artifact, error)`, `func (a Artifact) Save(path string) error`.

**The shape, from §4.7.** One file, offline-verifiable, holding the claim, the accused npub, the block, the raw signed commitment and policy events, an optional receipt, the missing leaf, and the Merkle proof. This file is the demo, and it is what would be attached to a public disclosure — an accusation nobody can independently check is worth little.

- [ ] **Step 1: Write the failing test**

```go
// evidence/artifact_test.go
package evidence

import (
	"encoding/hex"
	"net"
	"path/filepath"
	"testing"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/Sky-walkerX/canary/commit"
	"github.com/Sky-walkerX/canary/feed"
	"github.com/nbd-wtf/go-nostr"
)

const netRegtest = canonical.Network(0xdab5bffa)

func mkLeaves(n int) []canonical.Leaf {
	out := make([]canonical.Leaf, n)
	for i := range out {
		out[i].TxID[0] = byte(i + 1)
		out[i].Tweak[0] = 0x02
		out[i].Tweak[1] = byte(i)
	}
	return out
}

func buildTestArtifact(t *testing.T) Artifact {
	t.Helper()
	skHex := nostr.GeneratePrivateKey()
	b, _ := hex.DecodeString(skHex)
	var sk [32]byte
	copy(sk[:], b)

	leaves := mkLeaves(5)
	var bh [32]byte
	bh[0] = 0x42

	c := feed.Commitment{
		Network:   netRegtest,
		BlockHash: bh,
		N:         uint32(len(leaves)),
		Root:      commit.Root(netRegtest, bh, leaves),
	}
	ev, err := c.ToEvent(sk)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := commit.Prove(leaves, 2)
	if err != nil {
		t.Fatal(err)
	}

	a, err := Build(BuildInput{
		Claim:            ClaimOmission,
		SignedCommitment: ev,
		MissingLeaf:      leaves[2],
		Proof:            proof,
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestArtifactVerifies(t *testing.T) {
	if err := buildTestArtifact(t).Verify(); err != nil {
		t.Errorf("a well-formed artifact must verify: %v", err)
	}
}

func TestVerifyOpensNoSocket(t *testing.T) {
	a := buildTestArtifact(t)

	// canary verify requires no network (§4.7). Poison the dialer so any
	// attempt to reach out fails the test loudly rather than passing quietly
	// on a machine that happens to be online.
	orig := net.DefaultResolver.Dial
	net.DefaultResolver.Dial = func(_ interface{ Done() <-chan struct{} }, _, _ string) (net.Conn, error) {
		t.Fatal("Verify attempted a network call — the artifact must verify offline")
		return nil, nil
	}
	t.Cleanup(func() { net.DefaultResolver.Dial = orig })

	if err := a.Verify(); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestVerifyRejectsATamperedCommitment(t *testing.T) {
	a := buildTestArtifact(t)
	a.SignedCommitment.Content = "00"
	if err := a.Verify(); err == nil {
		t.Error("a tampered commitment must fail verification")
	}
}

func TestVerifyRejectsAProofForTheWrongLeaf(t *testing.T) {
	a := buildTestArtifact(t)
	a.MissingLeaf.TxID[0] ^= 0xFF
	if err := a.Verify(); err == nil {
		t.Error("a proof that does not cover the stated leaf must fail")
	}
}

func TestRoundTripThroughDisk(t *testing.T) {
	a := buildTestArtifact(t)
	path := filepath.Join(t.TempDir(), "evidence.json")
	if err := a.Save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := loaded.Verify(); err != nil {
		t.Errorf("an artifact must survive a round trip through disk: %v", err)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./evidence/ -v`
Expected: FAIL — the package does not exist.

- [ ] **Step 3: Write the implementation**

```go
// evidence/artifact.go
//
// Package evidence builds and checks the §4.7 artifact: one file, offline
// verifiable, that names an accused server and proves what it signed.
//
// This file is the demo (§8), and it is what gets attached to a bug report or a
// public disclosure. An accusation nobody can independently check is worth
// little, so Verify deliberately touches no network at all.
package evidence

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/Sky-walkerX/canary/commit"
	"github.com/Sky-walkerX/canary/feed"
	"github.com/nbd-wtf/go-nostr"
)

type Claim string

const (
	ClaimOmission          Claim = "omission"
	ClaimEquivocation      Claim = "equivocation"
	ClaimSelfContradiction Claim = "self-contradiction"
)

type Artifact struct {
	Claim   Claim  `json:"claim"`
	Accused string `json:"accused"` // npub of the signer

	BlockHash   string `json:"block_hash"` // display hex
	BlockHeight uint32 `json:"block_height"`

	SignedCommitment nostr.Event  `json:"signed_commitment"`
	SignedPolicy     *nostr.Event `json:"signed_policy,omitempty"`

	// Receipt is present only in the protocol layer (§3.8). Against an
	// unmodified indexer the victim knows and cannot prove it.
	Receipt json.RawMessage `json:"receipt,omitempty"`

	MissingLeaf leafJSON `json:"missing_leaf"`
	Proof       proofJSON `json:"merkle_proof"`
}

type leafJSON struct {
	TxID  string `json:"txid"`  // display hex
	Tweak string `json:"tweak"` // compressed SEC hex
}

type proofJSON struct {
	Index    uint32   `json:"index"`
	N        uint32   `json:"n"`
	Siblings []string `json:"siblings"`
}

type BuildInput struct {
	Claim            Claim
	SignedCommitment nostr.Event
	SignedPolicy     *nostr.Event
	Receipt          json.RawMessage
	MissingLeaf      canonical.Leaf
	Proof            commit.Proof
}

func displayHex(h [32]byte) string {
	var rev [32]byte
	for i := 0; i < 32; i++ {
		rev[i] = h[31-i]
	}
	return hex.EncodeToString(rev[:])
}

func parseDisplayHex(s string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, err
	}
	if len(b) != 32 {
		return out, fmt.Errorf("want 32 bytes, got %d", len(b))
	}
	for i := 0; i < 32; i++ {
		out[i] = b[31-i]
	}
	return out, nil
}

func Build(in BuildInput) (Artifact, error) {
	c, err := feed.FromEvent(in.SignedCommitment)
	if err != nil {
		return Artifact{}, fmt.Errorf("evidence: commitment does not verify: %w", err)
	}

	sibs := make([]string, len(in.Proof.Siblings))
	for i, s := range in.Proof.Siblings {
		sibs[i] = hex.EncodeToString(s[:])
	}

	return Artifact{
		Claim:            in.Claim,
		Accused:          in.SignedCommitment.PubKey,
		BlockHash:        displayHex(c.BlockHash),
		BlockHeight:      c.BlockHeight,
		SignedCommitment: in.SignedCommitment,
		SignedPolicy:     in.SignedPolicy,
		Receipt:          in.Receipt,
		MissingLeaf: leafJSON{
			TxID:  displayHex(in.MissingLeaf.TxID),
			Tweak: hex.EncodeToString(in.MissingLeaf.Tweak[:]),
		},
		Proof: proofJSON{Index: in.Proof.Index, N: in.Proof.N, Siblings: sibs},
	}, nil
}

var ErrProofDoesNotVerify = errors.New("evidence: merkle proof does not verify against the signed root")

// Verify checks the artifact end to end, offline.
//
// Three things must hold: the commitment event's signature is valid, the leaf
// is the one the artifact names, and the proof carries that leaf to the root
// the accused actually signed. Nothing here reaches the network — that is the
// property that makes the artifact worth sending to a stranger (§4.7).
func (a Artifact) Verify() error {
	c, err := feed.FromEvent(a.SignedCommitment)
	if err != nil {
		return fmt.Errorf("evidence: %w", err)
	}

	if a.SignedCommitment.PubKey != a.Accused {
		return fmt.Errorf("evidence: artifact accuses %s but the event is signed by %s",
			a.Accused, a.SignedCommitment.PubKey)
	}

	stated, err := parseDisplayHex(a.BlockHash)
	if err != nil {
		return fmt.Errorf("evidence: bad block hash: %w", err)
	}
	if stated != c.BlockHash {
		return errors.New("evidence: artifact block hash disagrees with the signed commitment")
	}

	var leaf canonical.Leaf
	if leaf.TxID, err = parseDisplayHex(a.MissingLeaf.TxID); err != nil {
		return fmt.Errorf("evidence: bad missing leaf txid: %w", err)
	}
	tweak, err := hex.DecodeString(a.MissingLeaf.Tweak)
	if err != nil || len(tweak) != 33 {
		return errors.New("evidence: missing leaf tweak is not 33 bytes")
	}
	copy(leaf.Tweak[:], tweak)

	p := commit.Proof{Index: a.Proof.Index, N: a.Proof.N}
	for _, s := range a.Proof.Siblings {
		b, err := hex.DecodeString(s)
		if err != nil || len(b) != 32 {
			return errors.New("evidence: malformed proof sibling")
		}
		var sib [32]byte
		copy(sib[:], b)
		p.Siblings = append(p.Siblings, sib)
	}

	if !commit.VerifyProof(c.Network, c.BlockHash, c.Root, leaf, p) {
		return ErrProofDoesNotVerify
	}
	return nil
}

func (a Artifact) Save(path string) error {
	b, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func Load(path string) (Artifact, error) {
	var a Artifact
	b, err := os.ReadFile(path)
	if err != nil {
		return a, err
	}
	if err := json.Unmarshal(b, &a); err != nil {
		return a, fmt.Errorf("evidence: parse %s: %w", path, err)
	}
	return a, nil
}
```

- [ ] **Step 4: Run the tests and commit**

```bash
go test ./evidence/ -v
git add evidence/
git commit -m "feat(evidence): offline-verifiable §4.7 artifact"
```

---

### Task 6: The tripwire

**Files:**
- Create: `tripwire/assert.go`, `tripwire/schedule.go`
- Test: `tripwire/assert_test.go`, `tripwire/schedule_test.go`

**Interfaces:**
- Consumes: `headers.Store`, `ladder`, `evidence`.
- Produces: `type Assertion struct { TxID [32]byte; BlockHash [32]byte; Height uint32; Prevouts []Prevout; SelfMade bool }`, `func Check(a Assertion, served []canonical.Leaf, in Context) (Outcome, error)`, `func NextDelay(rng *rand.Rand, meanSeconds float64) time.Duration`.

**What a negative result proves (§5.3).** Three innocent explanations must be excluded first: not yet indexed, reorg, and never confirmed. Only then is it omission.

**The one qualifier.** The tripwire attributes without a node *given an anchor*. The leaf and the proof genuinely need none — the client made the transaction, so it holds the prevouts. But the reorg check needs a chain fact from outside the indexer set, which under total collusion cannot come from the indexers by definition. Lacking a node, a pin, and a solution check, the result is *unresolvable*, still recorded and still signed, and becomes an accusation the moment an anchor arrives (§5.3).

- [ ] **Step 1: Write the failing test**

```go
// tripwire/assert_test.go
package tripwire

import (
	"testing"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/Sky-walkerX/canary/headers"
)

func txid(b byte) [32]byte {
	var t [32]byte
	t[0] = b
	return t
}

func servedWith(ids ...byte) []canonical.Leaf {
	out := make([]canonical.Leaf, 0, len(ids))
	for _, b := range ids {
		var l canonical.Leaf
		l.TxID = txid(b)
		l.Tweak[0] = 0x02
		out = append(out, l)
	}
	return out
}

func anchoredContext() Context {
	h := headers.New()
	var bh [32]byte
	bh[0] = 0x42
	h.Pin(100, bh)
	return Context{Headers: h, ServerHeight: 200, Tip: 200}
}

func selfMadeAssertion() Assertion {
	var bh [32]byte
	bh[0] = 0x42
	return Assertion{
		TxID:      txid(0xAA),
		BlockHash: bh,
		Height:    100,
		SelfMade:  true,
	}
}

func TestPassWhenTheServerReportsTheTransaction(t *testing.T) {
	out, err := Check(selfMadeAssertion(), servedWith(0x01, 0xAA, 0x03), anchoredContext())
	if err != nil {
		t.Fatal(err)
	}
	if out != Passed {
		t.Errorf("outcome = %v, want Passed", out)
	}
}

func TestOmissionWhenTheServerDoesNotReportIt(t *testing.T) {
	out, err := Check(selfMadeAssertion(), servedWith(0x01, 0x03), anchoredContext())
	if err != nil {
		t.Fatal(err)
	}
	if out != OmissionDetected {
		t.Errorf("outcome = %v, want OmissionDetected", out)
	}
}

func TestNotYetIndexedIsExcludedFirst(t *testing.T) {
	ctx := anchoredContext()
	ctx.ServerHeight = 50 // the server has not reached height 100

	out, err := Check(selfMadeAssertion(), nil, ctx)
	if err != nil {
		t.Fatal(err)
	}
	// An innocent explanation, and it must be excluded before any accusation
	// (§5.3 step 1).
	if out != NotYetIndexed {
		t.Errorf("outcome = %v, want NotYetIndexed", out)
	}
}

func TestWithoutAnAnchorTheResultIsUnresolvableNotAnAccusation(t *testing.T) {
	// No pin, no node, one server: chain membership is not derivable, so the
	// reorg explanation cannot be excluded (§5.3 step 2, §4.6).
	ctx := Context{Headers: headers.New(), ServerHeight: 200, Tip: 200}

	out, err := Check(selfMadeAssertion(), servedWith(0x01), ctx)
	if err != nil {
		t.Fatal(err)
	}
	if out == OmissionDetected {
		t.Fatal("without an anchor this must not be an accusation")
	}
	if out != Unresolvable {
		t.Errorf("outcome = %v, want Unresolvable", out)
	}
}

func TestOutOfBandAssertionCannotAttribute(t *testing.T) {
	a := selfMadeAssertion()
	a.SelfMade = false // a txid someone disclosed; we hold no prevouts

	out, err := Check(a, servedWith(0x01), anchoredContext())
	if err != nil {
		t.Fatal(err)
	}
	// Detection only. With no prevouts there is no tweak, so no leaf and no
	// artifact until a block source turns up (§5.1).
	if out != OmissionDetectedUnattributed {
		t.Errorf("outcome = %v, want OmissionDetectedUnattributed", out)
	}
}
```

```go
// tripwire/schedule_test.go
package tripwire

import (
	"math"
	"math/rand"
	"testing"
	"time"
)

func TestScheduleIsMemoryless(t *testing.T) {
	r := rand.New(rand.NewSource(42))
	const mean = 600.0

	var total float64
	const n = 20000
	for i := 0; i < n; i++ {
		total += NextDelay(r, mean).Seconds()
	}
	got := total / n

	// Exponential inter-arrivals have mean == the rate parameter. A fixed
	// interval is trivially whitelisted by an attacker; memorylessness is what
	// makes the last probe reveal nothing about the next (§5.2).
	if math.Abs(got-mean)/mean > 0.05 {
		t.Errorf("mean delay %.1fs, want ≈%.1fs", got, mean)
	}
}

func TestScheduleIsNeverConstant(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	first := NextDelay(r, 600)
	for i := 0; i < 50; i++ {
		if NextDelay(r, 600) != first {
			return
		}
	}
	t.Error("delays are constant — a periodic probe is trivially whitelisted (§5.2)")
}

func TestScheduleIsAlwaysPositive(t *testing.T) {
	r := rand.New(rand.NewSource(9))
	for i := 0; i < 1000; i++ {
		if d := NextDelay(r, 600); d <= 0 || d > 24*time.Hour {
			t.Fatalf("implausible delay %v", d)
		}
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./tripwire/ -v`
Expected: FAIL — the package does not exist.

- [ ] **Step 3: Write the implementation**

```go
// tripwire/assert.go
//
// Package tripwire implements §5: assert that a payment exists in a block, then
// check whether each indexer reports it.
//
// This is the rung of last resort, and the only one that survives all queried
// indexers colluding — because the client's knowledge originates outside the
// indexer system entirely.
package tripwire

import (
	"github.com/Sky-walkerX/canary/canonical"
	"github.com/Sky-walkerX/canary/headers"
)

type Outcome int

const (
	Passed Outcome = iota
	// NotYetIndexed, Unresolvable and NeverConfirmed are the innocent
	// explanations of §5.3, excluded before any accusation is made.
	NotYetIndexed
	NeverConfirmed
	Unresolvable
	// OmissionDetected is the attributable case: the client made the
	// transaction, so it holds the prevouts and can produce the missing leaf,
	// a proof, and a named accused party with no node and no auditor (§5.3).
	OmissionDetected
	// OmissionDetectedUnattributed is the out-of-band case. Detection only:
	// with no prevouts there is no tweak, no leaf and no artifact (§5.1).
	OmissionDetectedUnattributed
)

func (o Outcome) String() string {
	switch o {
	case Passed:
		return "passed"
	case NotYetIndexed:
		return "not-yet-indexed"
	case NeverConfirmed:
		return "never-confirmed"
	case Unresolvable:
		return "unresolvable"
	case OmissionDetected:
		return "omission-detected"
	case OmissionDetectedUnattributed:
		return "omission-detected-unattributed"
	default:
		return "unknown"
	}
}

type Assertion struct {
	TxID      [32]byte
	BlockHash [32]byte
	Height    uint32
	// SelfMade is true when the client made the transaction and therefore holds
	// its prevouts. It is the difference between an accusation with an artifact
	// and a bare detection (§5.1, §5.3).
	SelfMade bool
}

type Context struct {
	Headers      *headers.Store
	ServerHeight uint32 // the server's declared indexed height
	Tip          uint32
}

// Check runs §5.3: exclude the innocent explanations, then conclude.
func Check(a Assertion, served []canonical.Leaf, ctx Context) (Outcome, error) {
	// Step 1: not yet indexed. Wait until the server's declared height exceeds
	// the block's, plus margin.
	if ctx.ServerHeight < a.Height {
		return NotYetIndexed, nil
	}

	// Step 2: reorg. The block must be in the chain Canary believes in. With
	// two or more servers that is convergence; with one it rests on §4.6's
	// anchor, and a client with neither a node nor a pin cannot complete this
	// step at all.
	switch ctx.Headers.Status(a.Height, ctx.Tip) {
	case headers.Unknown, headers.Contested:
		// Not an accusation. The result is still recorded and still signed, and
		// becomes an accusation the moment an anchor is available. Evidence
		// does not decay (§4.2, §5.3).
		return Unresolvable, nil
	case headers.Contradicted:
		return Unresolvable, nil
	}

	// Step 3: never confirmed is the same check as step 2 for our purposes —
	// a transaction in no block has no block hash to agree about.

	for _, l := range served {
		if l.TxID == a.TxID {
			return Passed, nil
		}
	}

	// After the innocent explanations, it is omission.
	if !a.SelfMade {
		return OmissionDetectedUnattributed, nil
	}
	return OmissionDetected, nil
}
```

```go
// tripwire/schedule.go
package tripwire

import (
	"math"
	"math/rand"
	"time"
)

// NextDelay draws the next probe interval from an exponential distribution.
//
// Poisson scheduling is memoryless, so the last probe reveals nothing about the
// next. A probe every six blocks is trivially whitelisted by an attacker, which
// would defeat the one rung that survives total collusion (§5.2).
func NextDelay(rng *rand.Rand, meanSeconds float64) time.Duration {
	// Inverse transform sampling. rng.Float64() is [0,1), so 1-u is (0,1] and
	// the logarithm is always defined.
	u := rng.Float64()
	secs := -meanSeconds * math.Log(1-u)

	// Cap the tail. An exponential occasionally draws an enormous value, and a
	// probe scheduled three weeks out is a probe that never happens.
	const maxSecs = 6 * 3600
	if secs > maxSecs {
		secs = maxSecs
	}
	if secs < 1 {
		secs = 1
	}
	return time.Duration(secs * float64(time.Second))
}
```

- [ ] **Step 4: Run the tests and commit**

```bash
go test ./tripwire/ -v
git add tripwire/
git commit -m "feat(tripwire): expected-payment assertions and Poisson scheduling"
```

---

### Task 7: The proxy — refuse in path

**Files:**
- Create: `proxy/proxy.go`
- Test: `proxy/proxy_test.go`

**Interfaces:**
- Consumes: `ladder.Compare`, `ladder.Coverage`.
- Produces: `type Proxy`, `func New(cfg Config) *Proxy`, and `http.Handler`.

**Why a proxy and not an observer (§6.2).** A sidecar can sit beside the wallet or in the data path. Canary is in the data path, for three reasons: the wallet is genuinely unmodified — `blindbitd` works by changing one configuration line; observer behaviour falls out of proxy mode for free while the reverse does not; and **it closes §1.5's "a wallet that ignores the alarm"**, because a component in the data path can refuse to serve unverified data, where an observer can only write to a log the wallet never reads.

- [ ] **Step 1: Write the failing test**

```go
// proxy/proxy_test.go
package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Sky-walkerX/canary/ladder"
)

// stubVerifier lets the test choose the verdict without standing up an indexer.
type stubVerifier struct{ state ladder.State }

func (s stubVerifier) VerifyBlock(height uint32) (ladder.State, []byte, error) {
	return s.state, []byte(`{"tweaks":[]}`), nil
}

func TestServesVerifiedData(t *testing.T) {
	p := New(Config{Verifier: stubVerifier{state: ladder.Verified}})

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/tweaks/100", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestRefusesUnresolvableData(t *testing.T) {
	p := New(Config{Verifier: stubVerifier{state: ladder.StateUnresolvable}})

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/tweaks/100", nil))

	// The refusal, not a display, is the answer to §1.5's "a wallet that
	// ignores the alarm". An unmodified wallet cannot display what it cannot
	// see, so it must never receive a balance to print (§4.4, §6.2).
	if rec.Code == http.StatusOK {
		t.Error("unresolvable data must not be served — the wallet would print a confident wrong balance")
	}
	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", rec.Code)
	}
}

func TestRefusesCompromisedData(t *testing.T) {
	p := New(Config{Verifier: stubVerifier{state: ladder.Compromised}})

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/tweaks/100", nil))

	if rec.Code == http.StatusOK {
		t.Error("data from a compromised server must not be served")
	}
}

func TestObserveModeServesAnyway(t *testing.T) {
	p := New(Config{Verifier: stubVerifier{state: ladder.StateUnresolvable}, ObserveOnly: true})

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/tweaks/100", nil))

	// Observer behaviour falls out of proxy mode for free (§6.2). It is opt-in
	// because it is the weaker mode, not the default.
	if rec.Code != http.StatusOK {
		t.Errorf("observe-only mode must pass data through: status %d", rec.Code)
	}
}

func TestRefusalBodyNamesTheReason(t *testing.T) {
	p := New(Config{Verifier: stubVerifier{state: ladder.StateUnresolvable}})

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/tweaks/100", nil))

	if body := rec.Body.String(); body == "" {
		t.Error("a refusal must say why — a silent failure is the thing we are fixing")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./proxy/ -v`
Expected: FAIL — the package does not exist.

- [ ] **Step 3: Write the implementation**

```go
// proxy/proxy.go
//
// Package proxy is the blindbit-facing HTTP surface. canaryd sits IN the data
// path, not beside it: the wallet points at canaryd instead of the indexer, by
// changing one configuration line (§6.2).
package proxy

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/Sky-walkerX/canary/ladder"
)

// Verifier fetches a block's data from the upstream indexer and runs the ladder
// over it, returning the coverage state and the bytes that would be served.
type Verifier interface {
	VerifyBlock(height uint32) (ladder.State, []byte, error)
}

type Config struct {
	Verifier Verifier
	// ObserveOnly downgrades the proxy to an observer: it still verifies and
	// still records coverage, but passes everything through. Opt-in, because
	// an observer can only write to a log the wallet never reads (§6.2).
	ObserveOnly bool
}

type Proxy struct{ cfg Config }

func New(cfg Config) *Proxy { return &Proxy{cfg: cfg} }

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Only the endpoints blindbitd actually calls — a bounded list (§6.2).
	path := strings.TrimPrefix(r.URL.Path, "/")
	parts := strings.Split(path, "/")
	if len(parts) != 2 || parts[0] != "tweaks" {
		http.Error(w, "unsupported endpoint", http.StatusNotFound)
		return
	}

	height, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		http.Error(w, "bad height", http.StatusBadRequest)
		return
	}

	state, body, err := p.cfg.Verifier.VerifyBlock(uint32(height))
	if err != nil {
		http.Error(w, "verification failed", http.StatusBadGateway)
		return
	}

	if !p.cfg.ObserveOnly && !state.IsVerified() {
		// Refuse in path. This is the whole reason canaryd is a proxy: a
		// wallet that cannot see coverage must not receive a balance it would
		// print as if it were complete (§4.4, §6.2, §1.5).
		w.Header().Set("X-Canary-Coverage", state.String())
		http.Error(w, fmt.Sprintf(
			"canary: refusing to serve block %d — coverage is %s. "+
				"A balance computed over blocks that could not be verified is a lower bound, not a balance.",
			height, state), http.StatusConflict)
		return
	}

	w.Header().Set("X-Canary-Coverage", state.String())
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}
```

- [ ] **Step 4: Run the tests and commit**

```bash
go test ./proxy/ -v
git add proxy/
git commit -m "feat(proxy): refuse-in-path sidecar with opt-in observe mode"
```

---

### Task 8: The CLI and the daemon

**Files:**
- Create: `cmd/canary/main.go`, `cmd/canaryd/main.go`
- Test: `cmd/canary/main_test.go`

**Interfaces:**
- Consumes: everything.
- Produces: `canary status`, `canary verify <file>`, `canary probe`, `LoadConfig` with §3.6's manual pinning, and the `canaryd` daemon.

**`canary verify` is the repo path of §8.5.** A judge who never watches the video should reach a personally verified accusation in under sixty seconds, from a real artifact, with no node, no network and no build step beyond Go itself.

- [ ] **Step 1: Write the failing test**

```go
// cmd/canary/main_test.go
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyCommandAcceptsAGoodArtifact(t *testing.T) {
	path := filepath.Join("..", "..", "evidence", "testdata", "good-artifact.json")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("fixture not generated yet: %v", err)
	}

	var out strings.Builder
	code := runVerify(path, &out)
	if code != 0 {
		t.Errorf("exit code = %d, want 0; output: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "VERIFIED") {
		t.Errorf("output should say VERIFIED, got: %s", out.String())
	}
}

func TestVerifyCommandRejectsATamperedArtifact(t *testing.T) {
	path := filepath.Join("..", "..", "evidence", "testdata", "tampered-artifact.json")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("fixture not generated yet: %v", err)
	}

	var out strings.Builder
	code := runVerify(path, &out)
	if code == 0 {
		t.Error("a tampered artifact must produce a non-zero exit code")
	}
}

func TestVerifyCommandReportsAMissingFileClearly(t *testing.T) {
	var out strings.Builder
	if code := runVerify("/nonexistent/artifact.json", &out); code == 0 {
		t.Error("a missing file must be a non-zero exit")
	}
	if !strings.Contains(strings.ToLower(out.String()), "no such file") &&
		!strings.Contains(strings.ToLower(out.String()), "cannot") {
		t.Errorf("the error should name the problem, got: %s", out.String())
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./cmd/canary/ -v`
Expected: FAIL — `undefined: runVerify`.

- [ ] **Step 3: Write the CLI**

```go
// cmd/canary/main.go
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/Sky-walkerX/canary/evidence"
)

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}

	switch os.Args[1] {
	case "verify":
		if len(os.Args) != 3 {
			fmt.Fprintln(os.Stderr, "usage: canary verify <file>")
			os.Exit(2)
		}
		os.Exit(runVerify(os.Args[2], os.Stdout))
	case "status":
		os.Exit(runStatus(os.Stdout))
	case "probe":
		os.Exit(runProbe(os.Stdout))
	default:
		usage(os.Stderr)
		os.Exit(2)
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: canary <status|verify <file>|probe>")
}

// runVerify checks an evidence artifact. It opens no network connection: an
// accusation nobody can independently check is worth little, and requiring a
// server to check it would put the accuser back in the trusted position (§4.7).
func runVerify(path string, out io.Writer) int {
	a, err := evidence.Load(path)
	if err != nil {
		fmt.Fprintf(out, "cannot read artifact: %v\n", err)
		return 1
	}

	if err := a.Verify(); err != nil {
		fmt.Fprintf(out, "FAILED: %v\n", err)
		return 1
	}

	fmt.Fprintf(out, "VERIFIED\n\n")
	fmt.Fprintf(out, "  claim    %s\n", a.Claim)
	fmt.Fprintf(out, "  accused  %s\n", a.Accused)
	fmt.Fprintf(out, "  block    %s (height %d)\n", a.BlockHash, a.BlockHeight)
	fmt.Fprintf(out, "  txid     %s\n", a.MissingLeaf.TxID)
	fmt.Fprintf(out, "\nThe accused signed a commitment containing this transaction\n")
	fmt.Fprintf(out, "and served a set omitting it. Checked offline, with no network.\n")
	return 0
}
```

- [ ] **Step 4: Write the daemon's pinned-identity config**

§3.6 is a security requirement, not a convenience: client configuration is a set
of `(indexer_url, indexer_nostr_pubkey)` pairs, **pinned manually**. No
discovery, no web of trust, and **no trust-on-first-use**. An indexer's `/info`
may advertise its npub, but trusting that on first contact hands the key to
anyone able to intercept a single request — which is the whole attack, one layer
down.

```go
// cmd/canaryd/config.go
package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

type Indexer struct {
	URL    string `toml:"url"`
	Pubkey string `toml:"pubkey"` // 32-byte Nostr pubkey, hex. Pinned by hand.
}

type Config struct {
	Indexers []Indexer `toml:"indexer"`
	Relays   []string  `toml:"relays"`
	// Pin is an out-of-band (height, hash), §4.6's anchor for the
	// single-server case. Optional when a Core node is configured.
	PinHeight uint32 `toml:"pin_height"`
	PinHash   string `toml:"pin_hash"`
	CoreREST  string `toml:"core_rest"`
	ObserveOnly bool `toml:"observe_only"`
}

func LoadConfig(path string) (Config, error) {
	var c Config
	if _, err := toml.DecodeFile(path, &c); err != nil {
		return c, fmt.Errorf("canaryd: read config: %w", err)
	}
	if len(c.Indexers) == 0 {
		return c, fmt.Errorf("canaryd: no indexers configured")
	}
	for i, ix := range c.Indexers {
		b, err := hex.DecodeString(ix.Pubkey)
		if err != nil || len(b) != 32 {
			// Refusing to start beats silently running with an unpinned
			// indexer, which would put us back in the trusting position.
			return c, fmt.Errorf("canaryd: indexer %d (%s): pubkey must be 32 bytes of hex — pin it by hand (§3.6)", i, ix.URL)
		}
	}
	if c.PinHash == "" && c.CoreREST == "" {
		// Not fatal: §4.6 says convergence covers the multi-server case. But
		// with one indexer and no anchor the tripwire can only ever return
		// unresolvable, and the operator should know that up front (§5.3).
		fmt.Fprintln(os.Stderr,
			"canaryd: no chain anchor configured (pin_hash or core_rest). "+
				"With a single indexer, chain membership is underivable and tripwire "+
				"results will be unresolvable rather than accusations (§4.6, §5.3).")
	}
	return c, nil
}
```

Add a test that a missing or malformed pubkey fails to load, and that a config with no anchor loads but warns.

- [ ] **Step 5: Generate the two fixtures**

The fixtures come from a real run, not from a hand-built JSON file — §8.5 ships
this exact artifact in the repo, and a fabricated one would be the one faked
thing in a demo whose whole argument is that nothing is faked.

Add a `TestMain`-style helper to `evidence` that writes the good fixture from
the same builder Task 5 tests, so the fixture cannot drift from the code:

```go
// evidence/fixture_test.go
package evidence

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWriteFixtures regenerates the CLI's test fixtures from the live builder.
// Run with -run TestWriteFixtures -update.
func TestWriteFixtures(t *testing.T) {
	if os.Getenv("UPDATE_FIXTURES") == "" {
		t.Skip("set UPDATE_FIXTURES=1 to regenerate")
	}
	dir := "testdata"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	a := buildTestArtifact(t)
	if err := a.Save(filepath.Join(dir, "good-artifact.json")); err != nil {
		t.Fatal(err)
	}
	// The tampered copy flips one proof sibling, so it fails for a real reason
	// rather than because the JSON is malformed.
	if len(a.Proof.Siblings) == 0 {
		t.Fatal("fixture has no siblings to tamper with")
	}
	if a.Proof.Siblings[0][:2] == "00" {
		a.Proof.Siblings[0] = "11" + a.Proof.Siblings[0][2:]
	} else {
		a.Proof.Siblings[0] = "00" + a.Proof.Siblings[0][2:]
	}
	if err := a.Save(filepath.Join(dir, "tampered-artifact.json")); err != nil {
		t.Fatal(err)
	}
}
```

```bash
UPDATE_FIXTURES=1 go test ./evidence/ -run TestWriteFixtures -v
```

- [ ] **Step 6: Run the tests and commit**

```bash
go test ./cmd/... -v
git add cmd/ evidence/testdata
git commit -m "feat(cmd): canary CLI with offline verify"
```

---

### Task 9: Cross-check across servers, and the union

**Files:**
- Create: `ladder/crosscheck.go`
- Test: `ladder/crosscheck_test.go`

**Interfaces:**
- Consumes: `feed.Commitment`, `canonical.Leaf`, `State` from Task 3, `Alarm` from Task 4.
- Produces: `func CrossCheck(byAuthor map[[32]byte]feed.Commitment) CrossResult`, `type CrossResult struct { Agreed bool; Disputed bool; Authors [][32]byte; Roots [][32]byte }`, and `func Union(sets map[[32]byte][]canonical.Leaf) []canonical.Leaf`.

**Ordering note.** This task depends only on Tasks 2, 3 and 4 and can be done any time after them. It is numbered last because it was found missing during the plan self-review, not because it is least important — until it exists, `Disputed` is a coverage state with no producer, and §2.5's step 5 is unimplemented.

**Two separate things, both in §4.3's territory.**

*Cross-check* is §2.5 step 5 and the second half of §3.1: roots that disagree for the same block hash mean at least one server is lying. It costs 32 bytes per block per server as a continuous background check, and it is the rung that catches `committed ≠ canonical` — the case self-consistency cannot see, because a server that lies about `n` and renumbers passes its own signature check.

*Union* is §4.3. Omission wants the **union** across servers and commission wants the **intersection**, and they act at different stages, which resolves the conflict. Computing candidate outputs from tweaks is local and free — one EC multiplication, no network — so a tweak in **any** server's committed set is scanned. This is what defeats omission, at no privacy cost. The k-of-N rule belongs on *filters*, where the leak actually is, and v1 does not commit to filters, so that rule is unverified best effort and stays a note rather than a claim.

- [ ] **Step 1: Write the failing test**

```go
// ladder/crosscheck_test.go
package ladder

import (
	"testing"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/Sky-walkerX/canary/feed"
)

func author(b byte) [32]byte {
	var a [32]byte
	a[0] = b
	return a
}

func commitmentWithRoot(r byte) feed.Commitment {
	var c feed.Commitment
	c.BlockHash[0] = 0x42
	c.Root[0] = r
	c.N = 3
	return c
}

func TestCrossCheckAgreesWhenRootsMatch(t *testing.T) {
	res := CrossCheck(map[[32]byte]feed.Commitment{
		author(1): commitmentWithRoot(0xAA),
		author(2): commitmentWithRoot(0xAA),
	})
	if !res.Agreed {
		t.Error("identical roots must agree")
	}
	if res.Disputed {
		t.Error("identical roots are not disputed")
	}
}

func TestCrossCheckDisputesWhenRootsDiffer(t *testing.T) {
	res := CrossCheck(map[[32]byte]feed.Commitment{
		author(1): commitmentWithRoot(0xAA),
		author(2): commitmentWithRoot(0xBB),
	})
	if !res.Disputed {
		t.Fatal("divergent roots must be disputed")
	}
	if res.Agreed {
		t.Error("divergent roots do not agree")
	}
	// It names two servers without saying which lied. Both are recorded; the
	// verdict is withheld until rung 4 attributes it (§4.5).
	if len(res.Authors) != 2 {
		t.Errorf("named %d authors, want 2 — both are implicated", len(res.Authors))
	}
}

func TestCrossCheckNeedsTwoServers(t *testing.T) {
	res := CrossCheck(map[[32]byte]feed.Commitment{
		author(1): commitmentWithRoot(0xAA),
	})
	// One server agreeing with itself proves nothing. Self-consistency is the
	// single-server check; cross-check is not (§3.1).
	if res.Agreed {
		t.Error("a lone commitment is not agreement")
	}
	if res.Disputed {
		t.Error("a lone commitment is not a dispute either")
	}
}

func TestDisputeMapsToTheDisputedStateNotCompromised(t *testing.T) {
	res := CrossCheck(map[[32]byte]feed.Commitment{
		author(1): commitmentWithRoot(0xAA),
		author(2): commitmentWithRoot(0xBB),
	})
	if got := res.State(); got != Disputed {
		t.Errorf("state = %v, want Disputed", got)
	}
	if res.State() == Compromised {
		t.Fatal("divergence is never Compromised — that would name one server without evidence")
	}
}

// §4.3: the union, not the intersection.
func TestUnionTakesATweakFromAnyServer(t *testing.T) {
	var a, b canonical.Leaf
	a.TxID[0], a.Tweak[0] = 1, 0x02
	b.TxID[0], b.Tweak[0] = 2, 0x02

	// Server 1 has both; server 2 dropped the second. The union must keep it.
	out := Union(map[[32]byte][]canonical.Leaf{
		author(1): {a, b},
		author(2): {a},
	})
	if len(out) != 2 {
		t.Fatalf("union has %d leaves, want 2 — one honest source defeats omission (§4.3)", len(out))
	}
}

func TestUnionIsNotAnIntersection(t *testing.T) {
	var a, b canonical.Leaf
	a.TxID[0], a.Tweak[0] = 1, 0x02
	b.TxID[0], b.Tweak[0] = 2, 0x02

	// Disjoint sets. An intersection would return nothing, which is exactly the
	// attack: every server drops a different victim's tweak and all of them
	// vanish.
	out := Union(map[[32]byte][]canonical.Leaf{
		author(1): {a},
		author(2): {b},
	})
	if len(out) != 2 {
		t.Errorf("union of disjoint sets has %d leaves, want 2", len(out))
	}
}

func TestUnionDeduplicates(t *testing.T) {
	var a canonical.Leaf
	a.TxID[0], a.Tweak[0] = 1, 0x02

	out := Union(map[[32]byte][]canonical.Leaf{
		author(1): {a, a},
		author(2): {a},
	})
	if len(out) != 1 {
		t.Errorf("union has %d leaves, want 1 after dedup", len(out))
	}
}

func TestUnionIsDeterministic(t *testing.T) {
	var a, b, c canonical.Leaf
	a.TxID[0], b.TxID[0], c.TxID[0] = 1, 2, 3
	a.Tweak[0], b.Tweak[0], c.Tweak[0] = 0x02, 0x02, 0x02

	sets := map[[32]byte][]canonical.Leaf{
		author(1): {a, c},
		author(2): {b},
	}
	first := Union(sets)
	for i := 0; i < 20; i++ {
		got := Union(sets)
		if len(got) != len(first) {
			t.Fatal("union length varies between calls")
		}
		for j := range got {
			if got[j] != first[j] {
				t.Fatal("union order varies between calls — map iteration is leaking into the result")
			}
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./ladder/ -run 'TestCrossCheck|TestDispute|TestUnion' -v`
Expected: FAIL — `undefined: CrossCheck`.

- [ ] **Step 3: Write the implementation**

```go
// ladder/crosscheck.go
package ladder

import (
	"bytes"
	"sort"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/Sky-walkerX/canary/feed"
)

// CrossResult is the outcome of §2.5 step 5 for one block hash.
type CrossResult struct {
	Agreed   bool
	Disputed bool
	Authors  [][32]byte // every server that committed, sorted
	Roots    [][32]byte // the distinct roots seen, sorted
}

// State maps the result onto coverage.
//
// A dispute is Disputed and never Compromised. Root divergence names two
// servers without saying which lied, and collapsing that into one attributed
// alarm is exactly how an attacker gets an honest server excluded (§4.4, §4.5).
func (r CrossResult) State() State {
	if r.Disputed {
		return Disputed
	}
	if r.Agreed {
		return Verified
	}
	return StateUnverified
}

// CrossCheck compares the roots several servers published for the same block.
//
// This is the check self-consistency cannot do: a server that lies about n and
// renumbers passes its own signature check and fails only here (§3.1). It costs
// 32 bytes per block per server as a continuous background check (§2.5).
func CrossCheck(byAuthor map[[32]byte]feed.Commitment) CrossResult {
	var res CrossResult

	for a := range byAuthor {
		res.Authors = append(res.Authors, a)
	}
	sort.Slice(res.Authors, func(i, j int) bool {
		return bytes.Compare(res.Authors[i][:], res.Authors[j][:]) < 0
	})

	seen := map[[32]byte]bool{}
	for _, a := range res.Authors {
		root := byAuthor[a].Root
		if !seen[root] {
			seen[root] = true
			res.Roots = append(res.Roots, root)
		}
	}

	// Convergence needs two servers. One commitment is not agreement — there is
	// nothing to agree with.
	if len(byAuthor) < 2 {
		return res
	}

	if len(res.Roots) == 1 {
		res.Agreed = true
		return res
	}
	res.Disputed = true
	return res
}

// Union merges the leaf sets several servers served, in canonical order.
//
// §4.3: omission is an INTERSECTION attack, so one honest source defeats it and
// the union is the defence. Computing candidate outputs from tweaks is local
// and free, so scanning a tweak that only one server reported costs nothing and
// leaks nothing.
//
// The k-of-N rule that guards against commission belongs on filters, where the
// leak actually is — fetching block data on a filter match. v1 does not commit
// to filters, so that rule is unverified best effort and stays a note (§4.3,
// §1.5).
func Union(sets map[[32]byte][]canonical.Leaf) []canonical.Leaf {
	// Sort the authors first: ranging a map directly would make the output
	// order depend on Go's randomised map iteration, and §2.2's ordering is
	// load-bearing for attribution.
	authors := make([][32]byte, 0, len(sets))
	for a := range sets {
		authors = append(authors, a)
	}
	sort.Slice(authors, func(i, j int) bool {
		return bytes.Compare(authors[i][:], authors[j][:]) < 0
	})

	seen := map[canonical.Leaf]bool{}
	var out []canonical.Leaf
	for _, a := range authors {
		for _, l := range sets[a] {
			if seen[l] {
				continue
			}
			seen[l] = true
			out = append(out, l)
		}
	}

	// Sort by txid so the result does not depend on which server answered
	// first. Position within a block is recovered from the commitment, not from
	// this list.
	sort.Slice(out, func(i, j int) bool {
		if c := bytes.Compare(out[i].TxID[:], out[j].TxID[:]); c != 0 {
			return c < 0
		}
		return bytes.Compare(out[i].Tweak[:], out[j].Tweak[:]) < 0
	})
	return out
}
```

- [ ] **Step 4: Raise the alarm on a dispute**

Wire `CrossCheck` into the rung-1 loop: on `Disputed`, raise one `Alarm{Kind: RootDivergence}` per named author and record `Disputed` coverage for the block. Task 4's `ShouldDownRank` already refuses to act on that kind, which is the behaviour under test there.

- [ ] **Step 5: Run the tests and commit**

```bash
go test ./ladder/ -v
git add ladder/crosscheck.go ladder/crosscheck_test.go
git commit -m "feat(ladder): cross-server root comparison and the §4.3 union"
```

---

## Definition of done

- [ ] `go vet ./...` and `go test ./...` pass with no node, no relay and no network.
- [ ] `Compare` resolves gaps before recomputing the root, and an unfillable gap yields *Unresolvable* with `RootRecomputed == false`.
- [ ] All six coverage states exist, and *Unresolvable* is neither a pass nor an accusation.
- [ ] Root divergence never triggers automatic exclusion, and produces `Disputed` rather than `Compromised`.
- [ ] `Union` returns a tweak present in any one server's set, is deterministic, and is never an intersection.
- [ ] `headers` contains no proof-of-work validation and no most-work rule.
- [ ] `canary verify` checks a real artifact offline and exits non-zero on a tampered one.
- [ ] The proxy refuses unverified data by default and passes it through only under `ObserveOnly`.
- [ ] `canaryd` refuses to start with an unpinned indexer pubkey — no trust-on-first-use (§3.6).

**Handoff to §8:** Task 7's refusal and Task 8's `canary verify` are acts 4 and 5 of the demo. Task 5's artifact is what ships in `evidence/` for the judge who never watches the video (§8.5).
