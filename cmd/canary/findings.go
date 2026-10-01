package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/Sky-walkerX/canary/evidence"
	"github.com/Sky-walkerX/canary/internal/core"
	"github.com/Sky-walkerX/canary/internal/state"
	"github.com/Sky-walkerX/canary/internal/ui/wording"
	"github.com/Sky-walkerX/canary/ladder"
	"github.com/Sky-walkerX/canary/wire"
)

// recordFindings turns one block's result into findings.
//
// A withheld finding names one server and one position, or one declared
// payment when the entry sits at no position. A server that left out
// several entries gets one finding for each, so each finding's id stays the
// same when a later run recovers an entry an earlier run could not. A
// disagreement names two servers and accuses neither. A warning names a
// server but proves nothing.
func (ch *checker) recordFindings(b chainBlock, res ladder.BlockResult, lists []*ladder.List) int {
	for j, sr := range res.Servers {
		if sr.State == state.Compromised {
			if code := ch.withheld(b, j, sr, lists[j]); code != 0 {
				return code
			}
		}
		for _, w := range sr.Warnings {
			ch.add(ch.finding(state.KindWarning, w, []int{j}, b, nil, nil))
		}
	}
	for _, d := range res.Disagreements {
		ch.add(ch.finding(state.KindDisagree, state.RecordsDiffer, []int{ch.index(d.First), ch.index(d.Second)}, b, nil, nil))
	}
	return 0
}

// withheld adds the findings for one compromised server.
func (ch *checker) withheld(b chainBlock, j int, sr ladder.ServerResult, list *ladder.List) int {
	before := len(ch.fresh)
	for _, g := range sr.Gaps {
		reason := state.Reason("")
		switch {
		case g.Wrong:
			// Data at a committed position that differs from what the root
			// commits to is never permitted, at any depth.
			reason = state.ServedContradictsRecord
		case g.Served == wire.KindAbsent && (sr.Reason == state.AbsentInWindow || sr.Reason == state.FalseChainClaim):
			// The retention rule judges a list as a whole, so every absent
			// position in it carries the server's reason.
			reason = sr.Reason
		default:
			continue
		}
		pos := g.Position
		var txid *[32]byte
		if g.Entry != nil {
			txid = &g.Entry.TxID
		}
		f := ch.finding(state.KindWithheld, reason, []int{j}, b, &pos, txid)
		// canary-evidence/1 makes one claim: the record includes the entry
		// and the served list did not carry it. A false chain claim needs a
		// node to check, so it gets no file.
		if g.Entry != nil && g.Proof != nil && reason != state.FalseChainClaim {
			name, provable, err := ch.writeEvidence(sr, list, g)
			if err != nil {
				return ch.cmd.fail(exitFailure, wording.CheckWriteEvidence(filepath.Join(ch.cfg.evidenceDir, name)), err)
			}
			if name != "" {
				f.Evidence, f.Provable = &name, provable
			}
		}
		ch.add(f)
	}

	for _, p := range sr.Payments {
		switch p.Reason {
		case state.ExpectedPaymentNotInRecord:
			// The entry sits at no position in the record, so the finding is
			// keyed by the transaction.
			txid := p.TxID
			ch.add(ch.finding(state.KindWithheld, p.Reason, []int{j}, b, nil, &txid))
		case state.ExpectedPaymentNotInList:
			txid := p.TxID
			var pos *uint32
			for _, g := range sr.Gaps {
				if g.Entry != nil && g.Entry.TxID == p.TxID {
					at := g.Position
					pos = &at
					break
				}
			}
			ch.add(ch.finding(state.KindWithheld, p.Reason, []int{j}, b, pos, &txid))
		}
	}

	// A list that failed to decode, or whose length or root differs from the
	// record without a position to name, still names the server once.
	if len(ch.fresh) == before {
		ch.add(ch.finding(state.KindWithheld, sr.Reason, []int{j}, b, nil, nil))
	}
	return 0
}

// index returns the position of a server label in --indexer order.
func (ch *checker) index(label string) int {
	for i, s := range ch.runs {
		if s.cfg.label == label {
			return i
		}
	}
	return -1
}

// finding builds a finding and its stable id. servers index ch.runs.
func (ch *checker) finding(kind string, reason state.Reason, servers []int, b chainBlock, pos *uint32, txid *[32]byte) state.Finding {
	refs := make([]state.ServerRef, 0, len(servers))
	var keys []string
	for _, j := range servers {
		s := ch.runs[j]
		pk := pubkeyHex(s.cfg.pubkey)
		refs = append(refs, state.ServerRef{Label: s.cfg.label, Pubkey: pk})
		if pk != nil {
			keys = append(keys, *pk)
		}
	}
	var tx *string
	if txid != nil {
		s := core.DisplayHex(*txid)
		tx = &s
	}
	hash := core.DisplayHex(b.hash)
	return state.Finding{
		ID:       state.FindingID(kind, keys, hash, state.FindingSubject(kind, reason, pos, tx)),
		Kind:     kind,
		Reason:   reason,
		Servers:  refs,
		Block:    state.BlockRef{Height: b.height, Hash: hash},
		Position: pos,
		Txid:     tx,
	}
}

// add keeps a finding of this run once, by id.
func (ch *checker) add(f state.Finding) {
	for _, x := range ch.fresh {
		if x.ID == f.ID {
			return
		}
	}
	ch.fresh = append(ch.fresh, f)
}

// writeEvidence writes the evidence file for one recovered gap and returns
// its name, or "" when there is no file to name. evidence.Build runs the
// file through the same checks as canary verify first, so canary check
// never writes a file that does not check out.
//
// Evidence does not expire, so a file that carries a receipt is never
// overwritten. A file without one proves less, and a file that carries a
// receipt replaces it. A file is named only when it accuses the same server
// of leaving out the same entry at the same position of the same block. The
// name alone does not fix that: after a regtest chain is wiped and mined
// again, the same height can hold another block.
func (ch *checker) writeEvidence(sr ladder.ServerResult, list *ladder.List, g ladder.Gap) (string, bool, error) {
	s := ch.runs[ch.index(sr.Label)]
	in := evidence.Input{
		Record: sr.Record.Event,
		Entry:  *g.Entry,
		Index:  g.Position,
		Proof:  g.Proof,
		Context: &evidence.Context{
			ServerLabel: s.cfg.label,
			ServerURL:   s.cfg.url,
			FoundBy:     g.FoundBy,
			WrittenBy:   writtenBy(),
			WrittenAt:   ch.runAt.UTC().Format(time.RFC3339),
		},
	}
	// Only a valid receipt lets others check what the server sent.
	if sr.Signed && list != nil {
		in.Served, in.Receipt = list.Body, list.Receipt
	}
	f, err := evidence.Build(in)
	if err != nil {
		// The case does not fit the one claim the format makes.
		return "", false, nil
	}
	name := f.Name()
	path := filepath.Join(ch.cfg.evidenceDir, name)
	withReceipt := in.Receipt != ""

	old, err := os.ReadFile(path)
	switch {
	case err == nil:
		rep, verr := evidence.Verify(old)
		about, readable := reportSubject(rep)
		switch {
		case !readable && rep.Code == evidence.CodeUnsupportedFormat:
			// A newer Canary's file may carry a receipt this build cannot
			// read. Leave it alone.
			return "", false, nil
		case readable && about != fileSubject(f):
			// Another finding's file under the same name. Leave it alone
			// and name no file.
			return "", false, nil
		case rep.HasReceipt && verr == nil:
			return name, rep.Code == evidence.CodeOK, nil
		case rep.HasReceipt:
			// Never overwrite a file that carries a receipt, and never name
			// one that does not check out.
			return "", false, nil
		case verr == nil && !withReceipt:
			return name, false, nil
		}
	case !errors.Is(err, fs.ErrNotExist):
		return name, false, err
	}

	b, err := f.Marshal()
	if err != nil {
		return name, false, err
	}
	if err := os.MkdirAll(ch.cfg.evidenceDir, 0o755); err != nil {
		return name, false, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return name, false, err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return name, false, err
	}
	return name, withReceipt, nil
}

// subject is what one evidence file accuses: a server of leaving out an
// entry at a position of a block. Hashes and txids are display order, as
// evidence files and the state file both hold them.
type subject struct {
	magic   uint32
	block   string
	index   uint32
	txid    string
	accused string
}

// fileSubject is the subject of a file canary check built.
func fileSubject(f evidence.File) subject {
	return subject{magic: f.Network.Magic, block: f.Block.Hash, index: f.Proof.Index, txid: f.Missing.TxID, accused: f.Accused}
}

// reportSubject is the subject a file on disk names. ok is false when verify
// could not read the file far enough to name one.
func reportSubject(rep evidence.VerifyReport) (subject, bool) {
	if rep.Network == nil || rep.Block == nil || rep.Missing == nil || rep.Accused == nil {
		return subject{}, false
	}
	return subject{magic: rep.Network.Magic, block: rep.Block.Hash, index: rep.Missing.Index, txid: rep.Missing.TxID, accused: rep.Accused.Pubkey}, true
}

// findingSubject is the subject a finding's evidence file must name. ok is
// false for a finding no evidence file can be about.
func (ch *checker) findingSubject(f state.Finding) (subject, bool) {
	if f.Position == nil || f.Txid == nil || len(f.Servers) != 1 || f.Servers[0].Pubkey == nil {
		return subject{}, false
	}
	return subject{magic: uint32(ch.net), block: f.Block.Hash, index: *f.Position, txid: *f.Txid, accused: *f.Servers[0].Pubkey}, true
}

// recheckEvidence keeps a finding's evidence and provable fields true to the
// file on disk now. The finding names the file only while it reads, names
// this finding's subject and checks out. It is provable only while the file
// also carries a receipt that checks out. A file that was changed, replaced
// or removed since an earlier run loses both fields, and stays on disk if it
// is there.
func (ch *checker) recheckEvidence(f *state.Finding) {
	if f.Evidence == nil {
		f.Provable = false
		return
	}
	keep, provable := false, false
	if b, err := os.ReadFile(filepath.Join(ch.cfg.evidenceDir, *f.Evidence)); err == nil {
		rep, verr := evidence.Verify(b)
		about, ok := reportSubject(rep)
		want, wok := ch.findingSubject(*f)
		keep = verr == nil && ok && wok && about == want
		provable = keep && rep.HasReceipt && rep.Code == evidence.CodeOK
	}
	if !keep {
		f.Evidence = nil
	}
	f.Provable = provable
}

// carryForward merges this run's findings into the previous state file's.
//
// A finding seen before keeps every field from the first run that saw it,
// except last_seen, and its evidence once this run wrote a file with a
// receipt where the old one had none, or named a file where it named none.
//
// A finding whose block Core no longer knows is dropped, as after a regtest
// chain is wiped. It comes back in dropped, so the caller prints its id only
// once the state file is saved. Its evidence file stays on disk.
//
// Last, every finding's evidence is checked against the file on disk, so a
// carried finding never claims a file that no longer checks out. provable
// means the file carries a receipt and checks out, and that must hold for
// this run's state file, not only for the run that wrote the file.
func (ch *checker) carryForward(prev *state.File, finished time.Time) (out, dropped []state.Finding, code int) {
	seen := utc(finished)
	at := map[string]int{}
	if prev != nil {
		for _, f := range prev.Findings {
			known, err := ch.coreKnows(f.Block.Hash)
			if err != nil {
				return nil, nil, ch.coreFailed(err)
			}
			if !known {
				dropped = append(dropped, f)
				continue
			}
			at[f.ID] = len(out)
			out = append(out, f)
		}
	}
	for _, f := range ch.fresh {
		f.FirstSeen, f.LastSeen = seen, seen
		i, ok := at[f.ID]
		if !ok {
			at[f.ID] = len(out)
			out = append(out, f)
			continue
		}
		old := &out[i]
		old.LastSeen = seen
		if f.Provable && !old.Provable || old.Evidence == nil && f.Evidence != nil {
			old.Evidence, old.Provable = f.Evidence, f.Provable
		}
	}
	for i := range out {
		ch.recheckEvidence(&out[i])
	}
	return out, dropped, 0
}
