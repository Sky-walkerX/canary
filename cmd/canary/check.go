package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"time"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/Sky-walkerX/canary/internal/core"
	"github.com/Sky-walkerX/canary/internal/state"
	"github.com/Sky-walkerX/canary/internal/ui/wording"
	"github.com/Sky-walkerX/canary/ladder"
	"github.com/Sky-walkerX/canary/wire"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

// requestTimeout bounds each request to Core or to a server.
const requestTimeout = 30 * time.Second

// checker carries one canary check run.
type checker struct {
	ctx  context.Context
	cmd  command
	cfg  checkConfig
	core *core.Client

	net    canonical.Network
	tip    core.ChainInfo
	blocks []chainBlock      // the checked range, from Core
	byHash map[[32]byte]int  // block hash to its index in blocks
	runs   []*serverRun      // in --indexer order
	known  map[[32]byte]bool // blocks Core was asked about for old findings
	txs    map[[32]byte]int  // transactions per block, as Core counts them
	runAt  time.Time         // when the run started
	fresh  []state.Finding   // this run's findings, in the order found
	ids    map[string]bool   // the ids in fresh
}

// chainBlock is one height of the checked range and the hash Core gives for
// it, in internal byte order. Blocks are compared by hash, never by height.
type chainBlock struct {
	height uint32
	hash   [32]byte
}

// serverRun is what one server did during the run.
type serverRun struct {
	cfg    serverConfig
	client *indexerClient
	info   *serverInfo // nil when /info did not answer

	// Per checked block, from the first pass: the record body as served
	// when it passed the checks, whether the record request got no answer,
	// whether the record passed the checks, and the n a valid record signs.
	records     [][]byte
	unreachable []bool
	valid       []bool
	n           []uint32

	// pinned is true once a record's signature verified under the pin, even
	// a record that then failed on its n. That proves the --indexer URL
	// reaches the server the pin names.
	pinned bool

	signs bool          // a list arrived with a valid receipt
	best  *wire.Receipt // the valid receipt with the highest signed tip

	// refused is the server's first answer outside the v1 API, on /info or
	// on a record request. Whether it stops the run waits for the end of
	// the record pass.
	refused *response

	// The server's last error: a plain sentence for the state file, and the
	// Go error's own text for the terminal only.
	lastErr    string
	lastDetail string

	// The /info error, kept apart because a later error replaces it as the
	// last error. The terminal still says the server's policy is unknown.
	infoErr    string
	infoDetail string
}

// note keeps sentence as the server's last error, and err's text as its
// technical detail. err may be nil.
func (s *serverRun) note(sentence string, err error) {
	s.lastErr, s.lastDetail = sentence, ""
	if err != nil {
		s.lastDetail = err.Error()
	}
}

// notAsked notes that Canary stopped asking the server. The detail stays
// the last failed request's, because that request is the cause.
func (s *serverRun) notAsked() {
	s.lastErr = wording.ServerNotAsked(maxDownStreak)
}

// refuse keeps r as the server's first answer outside the v1 API.
func (s *serverRun) refuse(r response) {
	if s.refused == nil {
		s.refused = &r
	}
}

// provesNothing reports, once the server's records are in, whether the run
// must stop for it. That holds only when none of its records verified under
// its pin, its /info gave no canary-info/1 answer, and at least one of its
// answers was outside the v1 API. Canary then can't tell a hostile server
// from a wrong --indexer URL, and a wrong URL is the likelier.
//
// A verified signature proves the URL reaches the server the pin names, and
// a canary-info/1 answer shows it reaches a v1 server. After either, an
// answer outside the API is the server refusing one block or its /info, and
// Canary records it like an outage. So a server cannot stop the run that
// would name it. A server that gave no answer at all is an outage too.
func (s *serverRun) provesNothing() bool {
	return s.refused != nil && s.info == nil && !s.pinned
}

// runCheck is canary check.
func runCheck(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	c := command{name: "check", stdout: stdout, stderr: stderr}
	fs, v := newCheckFlags()
	pos, done, code := c.parse(fs, args, wording.CheckUsage, wording.CheckFlags)
	if done {
		return code
	}
	cfg, msg := v.config(pos)
	if msg != "" {
		return c.usage(msg)
	}
	hc := &http.Client{Timeout: requestTimeout}
	client, err := core.New(cfg.coreREST, hc)
	if err != nil {
		return c.usage(wording.CheckBadCore(cfg.coreREST))
	}
	ch := &checker{ctx: ctx, cmd: c, cfg: cfg, core: client, runAt: now(), known: map[[32]byte]bool{}, txs: map[[32]byte]int{}}
	for _, s := range cfg.servers {
		ch.runs = append(ch.runs, &serverRun{cfg: s, client: &indexerClient{base: s.url, hc: hc}})
	}
	return ch.run()
}

// coreFailed reports a Core request that failed during the run. A request
// cut off by an interrupt is the interrupt, not a Core failure.
func (ch *checker) coreFailed(err error) int {
	if ch.ctx.Err() != nil {
		return ch.interrupted()
	}
	return ch.cmd.fail(exitFailure, wording.CheckCoreUnreachable(ch.cfg.coreREST), err)
}

// interrupted ends a run cut short, as by Ctrl-C or SIGTERM. A request the
// interrupt cut off says nothing about a server, so the run saves nothing
// and the previous state file stays as it was. Evidence files already
// written stay on disk, and a later run names them again.
func (ch *checker) interrupted() int {
	return ch.cmd.fail(exitFailure, wording.CheckInterrupted, nil)
}

func (ch *checker) run() int {
	// A state file this build cannot read, or one from a newer Canary, holds
	// findings that overwriting would lose.
	prev, err := state.Load(ch.cfg.statePath)
	var newer *state.NewerFormatError
	switch {
	case errors.Is(err, state.ErrMissing):
		prev = nil
	case errors.As(err, &newer):
		return ch.cmd.fail(exitCantRead, wording.CheckStateNewer(ch.cfg.statePath, newer.Found), nil)
	case err != nil:
		return ch.cmd.fail(exitCantRead, wording.CheckStateUnreadable(ch.cfg.statePath), err)
	}

	ch.tip, err = ch.core.ChainInfo(ch.ctx)
	if err != nil {
		return ch.coreFailed(err)
	}
	// A node still syncing would make honest signed tips look false.
	if ch.tip.InitialBlockDownload {
		return ch.cmd.fail(exitFailure, wording.CheckCoreSyncing, nil)
	}
	if ch.net, err = core.NetworkFromChain(ch.tip.Chain); err != nil {
		return ch.cmd.fail(exitFailure, wording.CheckCoreChain(ch.tip.Chain), nil)
	}
	netName := core.NetworkName(ch.net)
	if prev != nil && prev.Network.Magic != uint32(ch.net) {
		return ch.cmd.fail(exitCantRead, wording.CheckStateOtherNetwork(ch.cfg.statePath, prev.Network.Name, netName), nil)
	}

	from, to := uint32(0), ch.tip.Height
	if ch.cfg.from != nil {
		from = *ch.cfg.from
	}
	if ch.cfg.to != nil {
		if *ch.cfg.to > ch.tip.Height {
			return ch.cmd.usage(wording.CheckRangeAboveTip(*ch.cfg.to, ch.tip.Height))
		}
		to = *ch.cfg.to
	}
	if from > to {
		return ch.cmd.usage(wording.CheckRangeBackwards(from, to))
	}

	if netName != "regtest" {
		fmt.Fprintln(ch.cmd.stdout, wording.NetworkBadge(netName))
	}
	fmt.Fprintln(ch.cmd.stdout, wording.CheckStarting(from, to, len(ch.runs)))

	// Core maps each height to a hash. That is the chain fact every server
	// is held to.
	ch.byHash = make(map[[32]byte]int, int(to-from)+1)
	for h := from; ; h++ {
		hash, err := ch.core.BlockHash(ch.ctx, h)
		if err != nil {
			return ch.coreFailed(err)
		}
		ch.byHash[hash] = len(ch.blocks)
		ch.blocks = append(ch.blocks, chainBlock{height: h, hash: hash})
		if h == to {
			break
		}
	}

	payments, code := ch.resolvePayments()
	if code != 0 {
		return code
	}
	if code := ch.fetchInfo(); code != 0 {
		return code
	}
	if code := ch.fetchRecords(); code != 0 {
		return code
	}
	blocks, rows, code := ch.evaluate(payments)
	if code != 0 {
		return code
	}
	if ch.ctx.Err() != nil {
		return ch.interrupted()
	}

	finished := now()
	findings, dropped, code := ch.carryForward(prev, finished)
	if code != 0 {
		return code
	}
	f := &state.File{
		Format:      state.Format,
		GeneratedAt: utc(finished),
		Canary:      state.Build{Version: version, Build: buildID()},
		Network:     state.Network{Name: netName, Magic: uint32(ch.net)},
		ChainTip:    state.ChainTip{Height: ch.tip.Height, Hash: core.DisplayHex(ch.tip.BestHash), Source: "core"},
		Checked:     state.Range{From: from, To: to},
		EvidenceDir: ch.cfg.evidenceDir,
		Servers:     ch.serverStates(),
		Blocks:      blocks,
		Findings:    findings,
	}
	f.Coverage, f.Counts = coverage(blocks)
	f.ExpectedPayments = rows
	if ch.ctx.Err() != nil {
		return ch.interrupted()
	}
	if err := state.Save(ch.cfg.statePath, f); err != nil {
		return ch.cmd.fail(exitFailure, wording.CheckWriteState(ch.cfg.statePath), err)
	}

	for _, x := range dropped {
		fmt.Fprintln(ch.cmd.stdout, wording.CheckDroppedFinding(x.ID, x.Block.Hash))
	}
	ch.printServerErrors()
	printSummary(ch.cmd.stdout, f)
	fmt.Fprintln(ch.cmd.stdout, wording.CheckSaved(ch.cfg.statePath))
	// Only findings change the exit code. A block that reads Can't be
	// checked or Not checked does not.
	if len(ch.fresh) > 0 {
		return exitFound
	}
	return exitOK
}

// fetchInfo reads each server's /info. A server that does not answer, or
// answers with something other than canary-info/1, declares no policy in
// this run. Whether an answer outside the API stops the run waits for the
// end of the record pass, in fetchRecords.
func (ch *checker) fetchInfo() int {
	for _, s := range ch.runs {
		info, r := s.client.info(ch.ctx)
		switch {
		case info != nil:
			s.info = info
		case r.kind == answerStopped:
			return ch.interrupted()
		case r.kind == answerDown:
			s.note(wording.ServerInfoFailed, r.err)
		case r.kind == answerSkipped:
			s.notAsked()
		default:
			s.note(wording.ServerInfoUnusable, r.err)
			s.refuse(r)
		}
		if s.info == nil {
			s.infoErr, s.infoDetail = s.lastErr, s.lastDetail
		}
	}
	return 0
}

// fetchRecords is the first pass: every pinned server's signed record for
// every checked block. It comes before any list, because a missing record
// raises a warning only when the server signed records on both sides of it.
//
// An answer outside the v1 API marks its block unreachable. Whether it
// stops the run waits for the end of the server's pass, so the order of the
// blocks never decides it. The run stops only for a server that proves
// nothing (provesNothing).
func (ch *checker) fetchRecords() int {
	n := len(ch.blocks)
	for _, s := range ch.runs {
		s.records, s.unreachable, s.valid, s.n = make([][]byte, n), make([]bool, n), make([]bool, n), make([]uint32, n)
		if code := ch.fetchServerRecords(s); code != 0 {
			return code
		}
		if s.provesNothing() {
			msg := wording.CheckServerUnusable(s.cfg.label, s.cfg.url)
			if s.cfg.pubkey == nil {
				msg = wording.CheckServerUnusablePinnedNone(s.cfg.label, s.cfg.url)
			}
			return ch.cmd.fail(exitFailure, msg, s.refused.err)
		}
	}
	return 0
}

// fetchServerRecords asks one server for its record for every block.
func (ch *checker) fetchServerRecords(s *serverRun) int {
	if s.cfg.pubkey == nil {
		// A server pinned as none signs nothing, so there is no record to
		// ask for. Without /info it is simply unreachable.
		for i := range s.unreachable {
			s.unreachable[i] = s.info == nil
		}
		return 0
	}
	for i, b := range ch.blocks {
		r := s.client.commitment(ch.ctx, b.hash)
		switch r.kind {
		case answerOK:
			// The ladder checks the record again. This pass only learns
			// which blocks the server signed for. It keeps a record's bytes
			// only when they pass, because the ladder reaches the same
			// result for a record that fails as for no record. Bytes that
			// fail are dropped here, so they cost the run nothing.
			rec, err := ladder.CheckRecord(r.body, *s.cfg.pubkey, b.hash, ch.net)
			if err != nil {
				s.note(wording.ServerRecordRejected(b.height), err)
				continue
			}
			s.pinned = true
			n := rec.Commitment.N
			fits, txs, err := ch.fits(b.hash, n)
			if err != nil {
				return ch.coreFailed(err)
			}
			if !fits {
				// The ladder would accept the signature, so it gets no
				// record for this block, as for unknown_block.
				s.note(wording.ServerRecordTooLarge(b.height, n, txs),
					fmt.Errorf("canary: record for block %s: n=%d, and Core's block holds %d transactions", core.DisplayHex(b.hash), n, txs))
				continue
			}
			s.records[i], s.valid[i], s.n[i] = r.body, true, n
		case answerNone:
		case answerDown:
			s.unreachable[i] = true
			s.note(wording.ServerRecordUnanswered(b.height), r.err)
		case answerSkipped:
			s.unreachable[i] = true
			s.notAsked()
		case answerStopped:
			return ch.interrupted()
		default:
			s.unreachable[i] = true
			s.note(wording.ServerRecordRefused(b.height), r.err)
			s.refuse(r)
		}
	}
	return 0
}

// fits reports whether the block can hold a record's n entries, and the
// block's transaction count when Core was asked. BIP-352 gives at most one
// entry per transaction and none for the coinbase, so n is at most the count
// less one. A record that claims more contradicts the user's own node.
//
// The check bounds what one record can cost the run. Without it, a record
// can sign any n, and a list of n absent positions inside the window makes
// one finding per position. Core is asked once per block, and only for an n
// above zero.
func (ch *checker) fits(hash [32]byte, n uint32) (bool, int, error) {
	if n == 0 {
		return true, 0, nil
	}
	txs, ok := ch.txs[hash]
	if !ok {
		blk, err := ch.core.Block(ch.ctx, chainhash.Hash(hash))
		if err != nil {
			return false, 0, err
		}
		txs = len(blk.Transactions)
		ch.txs[hash] = txs
	}
	return int64(n) < int64(txs), txs, nil
}

// coreChain answers the ladder's one question about Core's active chain.
type coreChain struct {
	ctx context.Context
	c   *core.Client
}

// maxCoreHeight is the highest height Core's REST interface reads. Core
// parses the height as a signed 32-bit number and answers 400 to anything
// larger, so no chain it serves has a block above it.
const maxCoreHeight = math.MaxInt32

// ActiveHash returns Core's block hash at height. The height comes from a
// server's signed receipt, so the server picks it. Core answers a height
// above maxCoreHeight with 400, not 404, and that error would stop the run
// and blame Core. So Canary answers that height itself: no block is there.
// It does not answer locally for every height above this run's tip, because
// Core may reach that height during a long run and confirm an honest tip.
func (x coreChain) ActiveHash(height uint32) ([32]byte, bool, error) {
	if height > maxCoreHeight {
		return [32]byte{}, false, nil
	}
	h, err := x.c.BlockHash(x.ctx, height)
	if errors.Is(err, core.ErrNotFound) {
		return [32]byte{}, false, nil
	}
	if err != nil {
		return [32]byte{}, false, err
	}
	return h, true, nil
}

// evaluate is the second pass. For each block it fetches the list from every
// server that signed a valid record, runs the ladder, and records the
// block's state, its findings and their evidence files. It also returns the
// state file's row for each declared payment, in --expect order.
//
// A block's ladder result holds its records, gaps and proofs. evaluate keeps
// it only while it reads that block, and takes the rows of the payments in
// the block from it then. Keeping every result to the end would let one
// server grow the run's memory with every block in the range.
func (ch *checker) evaluate(payments []declared) ([]state.Block, []state.Payment, int) {
	below, above := ch.neighbours()
	for _, s := range ch.runs {
		s.client.newPass()
	}
	out := make([]state.Block, 0, len(ch.blocks))
	rows := make([]state.Payment, len(payments))
	for k, d := range payments {
		if d.block < 0 {
			rows[k] = ch.paymentState(d, ladder.BlockResult{})
		}
	}
	for i, b := range ch.blocks {
		if ch.ctx.Err() != nil {
			return nil, nil, ch.interrupted()
		}
		servers := make([]ladder.Server, len(ch.runs))
		lists := make([]*ladder.List, len(ch.runs))
		for j, s := range ch.runs {
			ls := ladder.Server{
				Label:       s.cfg.label,
				Pubkey:      s.cfg.pubkey,
				Unreachable: s.unreachable[i],
				Record:      s.records[i],
				RecordBelow: below[j][i],
				RecordAbove: above[j][i],
			}
			if s.info != nil {
				tip := s.info.tipHeight
				ls.Tip = &tip
				if s.info.policy != nil {
					p := *s.info.policy
					p.Network = ch.net
					ls.Policy = &p
				}
			}
			if s.valid[i] {
				r := s.client.tweaks(ch.ctx, b.hash, s.n[i])
				switch r.kind {
				case answerOK:
					lists[j] = &ladder.List{Body: r.body, Receipt: r.header.Get(wire.ReceiptHeader)}
					ls.List = lists[j]
				case answerNone, answerDown:
					s.note(wording.ServerListUnanswered(b.height), r.err)
				case answerSkipped:
					// Canary never asked for this list, so the server refused
					// nothing. The block reads Not checked for it, with no
					// warning.
					ls.Unreachable = true
					s.notAsked()
				case answerStopped:
					return nil, nil, ch.interrupted()
				default:
					// An answer outside the v1 API. The server signed a
					// valid record for this block, so its URL is proven,
					// and the answer is a list not served. Like any refused
					// list, it reads Can't be checked, with the warning
					// inside the window.
					s.note(wording.ServerListUnanswered(b.height), r.err)
				}
			}
			servers[j] = ls
		}

		res, err := ladder.Evaluate(ladder.Block{
			Hash:     b.hash,
			Height:   b.height,
			Core:     ladder.Core{Network: ch.net, TipHeight: ch.tip.Height, Chain: coreChain{ch.ctx, ch.core}},
			Servers:  servers,
			Payments: paymentsIn(payments, i),
		})
		if err != nil {
			return nil, nil, ch.coreFailed(err)
		}
		for k, d := range payments {
			if d.block == i {
				rows[k] = ch.paymentState(d, res)
			}
		}
		ch.noteServers(b, res)
		if code := ch.recordFindings(b, res, lists); code != 0 {
			return nil, nil, code
		}
		out = append(out, blockState(b, res))
	}
	return out, rows, 0
}

// neighbours says, per server and block, whether the server signed a valid
// record for a lower and for a higher block in this run.
func (ch *checker) neighbours() (below, above [][]bool) {
	for _, s := range ch.runs {
		n := len(s.valid)
		b, a := make([]bool, n), make([]bool, n)
		for i := 1; i < n; i++ {
			b[i] = b[i-1] || s.valid[i-1]
		}
		for i := n - 2; i >= 0; i-- {
			a[i] = a[i+1] || s.valid[i+1]
		}
		below, above = append(below, b), append(above, a)
	}
	return below, above
}

// noteServers keeps what the servers' results say about each server for the
// state file: receipts, the best signed tip, and the last error.
func (ch *checker) noteServers(b chainBlock, res ladder.BlockResult) {
	for j, sr := range res.Servers {
		s := ch.runs[j]
		if sr.Signed && sr.Receipt != nil {
			s.signs = true
			if s.best == nil || sr.Receipt.TipHeight > s.best.TipHeight {
				rc := *sr.Receipt
				s.best = &rc
			}
		}
		if sr.ReceiptErr != nil {
			s.note(wording.ServerReceiptRejected(b.height), sr.ReceiptErr)
		}
		if sr.ListErr != nil {
			s.note(wording.ServerListRejected(b.height), sr.ListErr)
		}
	}
}

// printServerErrors puts each server's last error on stderr, with the Go
// error's own text under it. The state file keeps the plain sentence only.
// When a later error replaced a failed /info as the last error, the /info
// error comes first, because it is why the server's policy is unknown.
func (ch *checker) printServerErrors() {
	line := func(text, detail string) {
		fmt.Fprintf(ch.cmd.stderr, "canary %s: %s\n", ch.cmd.name, text)
		if detail != "" {
			fmt.Fprintln(ch.cmd.stderr, wording.CLIDetails(detail))
		}
	}
	for _, s := range ch.runs {
		if s.infoErr != "" && s.infoErr != s.lastErr {
			line(wording.CheckServerInfoError(s.cfg.label, s.infoErr), s.infoDetail)
		}
		if s.lastErr != "" {
			line(wording.CheckServerLastError(s.cfg.label, s.lastErr), s.lastDetail)
		}
	}
}

// blockState is the state file's detail for one block.
func blockState(b chainBlock, res ladder.BlockResult) state.Block {
	out := state.Block{
		Height:  b.height,
		Hash:    core.DisplayHex(b.hash),
		State:   res.State,
		Reason:  res.Reason,
		Servers: make([]state.BlockServer, 0, len(res.Servers)),
	}
	for _, sr := range res.Servers {
		bs := state.BlockServer{
			Label:     sr.Label,
			State:     sr.State,
			Reason:    sr.Reason,
			Positions: sr.Positions,
			Filled:    uint32(sr.Filled),
			Signed:    sr.Signed,
		}
		if sr.Record != nil {
			id := sr.Record.Event.ID
			n := sr.Record.Commitment.N
			root := fmt.Sprintf("%x", sr.Record.Commitment.Root[:])
			bs.RecordEventID, bs.N, bs.Root = &id, &n, &root
		}
		if sr.Signed && sr.Receipt != nil {
			bs.Tip = &state.Tip{Height: sr.Receipt.TipHeight, Hash: core.DisplayHex(sr.Receipt.TipHash)}
		}
		out.Servers = append(out.Servers, bs)
	}
	return out
}

// coverage merges consecutive heights with the same state and reason into
// ranges, and counts blocks per state.
func coverage(blocks []state.Block) ([]state.CoverageRange, state.Counts) {
	var out []state.CoverageRange
	var c state.Counts
	for _, b := range blocks {
		if n := len(out); n > 0 && out[n-1].State == b.State && out[n-1].Reason == b.Reason && out[n-1].To+1 == b.Height {
			out[n-1].To = b.Height
		} else {
			out = append(out, state.CoverageRange{From: b.Height, To: b.Height, State: b.State, Reason: b.Reason})
		}
		switch b.State {
		case state.Verified:
			c.Verified++
		case state.Resolved:
			c.Resolved++
		case state.Unresolvable:
			c.Unresolvable++
		case state.Unverified:
			c.Unverified++
		case state.Disputed:
			c.Disputed++
		case state.Compromised:
			c.Compromised++
		}
	}
	return out, c
}

// serverStates is the state file's servers array.
func (ch *checker) serverStates() []state.Server {
	out := make([]state.Server, 0, len(ch.runs))
	for _, s := range ch.runs {
		published := false
		for _, v := range s.valid {
			published = published || v
		}
		st := state.Server{
			Label:            s.cfg.label,
			URL:              s.cfg.url,
			Pubkey:           pubkeyHex(s.cfg.pubkey),
			PublishesRecords: published,
			SignsReceipts:    s.signs,
			Reachable:        s.info != nil,
		}
		switch {
		case s.best != nil:
			st.Tip = &state.ServerTip{Height: s.best.TipHeight, Hash: core.DisplayHex(s.best.TipHash), Signed: true}
		case s.info != nil:
			st.Tip = &state.ServerTip{Height: s.info.tipHeight, Hash: s.info.tipHash}
		}
		if s.info != nil && s.info.policy != nil {
			p := s.info.policy
			st.Policy = &state.Policy{PrunesSpent: p.PrunesSpent, DustThresholdSat: p.DustThresholdSat, DustConfigurable: p.DustConfigurable}
		}
		if s.lastErr != "" {
			e := s.lastErr
			st.Error = &e
		}
		out = append(out, st)
	}
	return out
}

// coreKnows reports whether Core has the block with this display-order hash,
// on its active chain or not. A reorg keeps a block known. A wiped regtest
// chain does not.
func (ch *checker) coreKnows(display string) (bool, error) {
	h, err := core.ParseDisplayHash(display)
	if err != nil {
		return false, nil
	}
	if _, ok := ch.byHash[h]; ok {
		return true, nil
	}
	if known, ok := ch.known[h]; ok {
		return known, nil
	}
	_, err = ch.core.Block(ch.ctx, chainhash.Hash(h))
	switch {
	case errors.Is(err, core.ErrNotFound):
		ch.known[h] = false
		return false, nil
	case err != nil:
		return false, err
	}
	ch.known[h] = true
	return true, nil
}
