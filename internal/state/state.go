// Package state reads and writes the state file, format canary-state/1.
//
// canary check writes one state file per run. canary status prints it, and
// canary ui renders it. The v1 formats document fixes every field; this package
// mirrors that document and rejects anything it does not describe.
//
// A reader never guesses. Load returns ErrMissing when there is no file,
// ErrNewerFormat when a later Canary wrote it, and ErrUnreadable for anything
// else it cannot trust. Save writes a temporary file and renames it over the
// old one, so a reader never sees half a file.
package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Format is the only state-file format this package reads and writes.
const Format = "canary-state/1"

const formatPrefix = "canary-state/"

// Errors returned by Load and Parse. Match them with errors.Is.
var (
	// ErrMissing means there is no state file yet. The dashboard shows its
	// "No check yet" page.
	ErrMissing = errors.New("state: no state file")

	// ErrUnreadable means the file exists but is not a canary-state/1 file
	// this package can trust: bad JSON, an unknown field, or a value the
	// format does not allow.
	ErrUnreadable = errors.New("state: state file unreadable")

	// ErrNewerFormat means a later version of Canary wrote the file. The
	// error is a *NewerFormatError, which names the format found.
	ErrNewerFormat = errors.New("state: newer format")
)

// NewerFormatError reports a state file written in a format newer than
// canary-state/1. errors.Is(err, ErrNewerFormat) is true for it.
type NewerFormatError struct {
	// Found is the file's format string, for example "canary-state/2".
	Found string
}

func (e *NewerFormatError) Error() string {
	return fmt.Sprintf("state: newer format: file is %s, this build reads %s", e.Found, Format)
}

// Is makes errors.Is(err, ErrNewerFormat) match.
func (e *NewerFormatError) Is(target error) bool { return target == ErrNewerFormat }

// StateCode is one of the six coverage states. The code is stable and never
// shown on screen; the wording table maps it to a label.
type StateCode string

// The six state codes, in the order every screen lists them.
const (
	Verified     StateCode = "verified"
	Resolved     StateCode = "resolved"
	Unresolvable StateCode = "unresolvable"
	Unverified   StateCode = "unverified"
	Disputed     StateCode = "disputed"
	Compromised  StateCode = "compromised"
)

// States lists the six codes in display order.
var States = []StateCode{Verified, Resolved, Unresolvable, Unverified, Disputed, Compromised}

// Passed reports whether the state means the root was recomputed and matched:
// Checked, or Checked with a gap filled.
func (s StateCode) Passed() bool { return s == Verified || s == Resolved }

// Valid reports whether s is one of the six codes.
func (s StateCode) Valid() bool {
	for _, c := range States {
		if s == c {
			return true
		}
	}
	return false
}

// Reason explains a state. Every state carries one.
type Reason string

// Reason codes, grouped by the state they belong to.
const (
	RecordsAgree    Reason = "records_agree"
	ExpectedPayment Reason = "expected_payment"
	OwnRecord       Reason = "own_record"

	FilledFromServer          Reason = "filled_from_server"
	FilledFromExpectedPayment Reason = "filled_from_expected_payment"
	HashRetained              Reason = "hash_retained"

	GapUnfilled    Reason = "gap_unfilled"
	TipUnconfirmed Reason = "tip_unconfirmed"
	ListNotServed  Reason = "list_not_served"
	ListUnreadable Reason = "list_unreadable"

	NoRecords         Reason = "no_records"
	NoRecordForBlock  Reason = "no_record_for_block"
	NotIndexedYet     Reason = "not_indexed_yet"
	ServerUnreachable Reason = "server_unreachable"

	RecordsDiffer Reason = "records_differ"

	AbsentInWindow             Reason = "absent_in_window"
	FalseChainClaim            Reason = "false_chain_claim"
	ServedContradictsRecord    Reason = "served_contradicts_record"
	ExpectedPaymentNotInRecord Reason = "expected_payment_not_in_record"
	ExpectedPaymentNotInList   Reason = "expected_payment_not_in_list"

	// HashWithoutPolicy is a warning only. It never becomes a server's or a
	// block's reason, so it has no state.
	HashWithoutPolicy Reason = "hash_without_policy"
)

// reasonStates maps every state reason to the one state it explains.
var reasonStates = map[Reason]StateCode{
	RecordsAgree:               Verified,
	ExpectedPayment:            Verified,
	OwnRecord:                  Verified,
	FilledFromServer:           Resolved,
	FilledFromExpectedPayment:  Resolved,
	HashRetained:               Resolved,
	GapUnfilled:                Unresolvable,
	TipUnconfirmed:             Unresolvable,
	ListNotServed:              Unresolvable,
	ListUnreadable:             Unresolvable,
	NoRecords:                  Unverified,
	NoRecordForBlock:           Unverified,
	NotIndexedYet:              Unverified,
	ServerUnreachable:          Unverified,
	RecordsDiffer:              Disputed,
	AbsentInWindow:             Compromised,
	FalseChainClaim:            Compromised,
	ServedContradictsRecord:    Compromised,
	ExpectedPaymentNotInRecord: Compromised,
	ExpectedPaymentNotInList:   Compromised,
}

// StateOf returns the state a reason belongs to. ok is false for the
// warning-only reason and for unknown codes.
func StateOf(r Reason) (s StateCode, ok bool) {
	s, ok = reasonStates[r]
	return s, ok
}

// Finding kinds.
const (
	KindWithheld = "withheld"
	KindDisagree = "disagree"
	KindWarning  = "warning"
)

// warningReasons are the reasons a warning finding may carry.
var warningReasons = map[Reason]bool{
	NoRecordForBlock:  true,
	ListNotServed:     true,
	ListUnreadable:    true,
	HashWithoutPolicy: true,
}

// Declared-payment outcomes. The per-server outcomes are a subset of the
// overall ones.
var (
	serverOutcomes  = []string{"found", "withheld", "hash_only", "not_indexed_yet", "unresolvable"}
	overallOutcomes = []string{"found", "withheld", "hash_only", "not_indexed_yet", "unresolvable", "not_eligible", "pending"}
)

// Time is a JSON time in the state file: RFC 3339, UTC, whole seconds, with a
// Z suffix. It reads any RFC 3339 time and converts it to UTC.
type Time struct{ time.Time }

// MarshalJSON writes the time as the formats document requires.
func (t Time) MarshalJSON() ([]byte, error) {
	return []byte(`"` + t.UTC().Truncate(time.Second).Format(time.RFC3339) + `"`), nil
}

// UnmarshalJSON reads an RFC 3339 time.
func (t *Time) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("time must be a string: %w", err)
	}
	p, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return fmt.Errorf("time %q is not RFC 3339: %w", s, err)
	}
	t.Time = p.UTC()
	return nil
}

// File is one state file. Field names and nullability follow the formats
// document exactly. A nil pointer is written as JSON null.
type File struct {
	Format           string          `json:"format"`
	GeneratedAt      Time            `json:"generated_at"`
	Canary           Build           `json:"canary"`
	Network          Network         `json:"network"`
	ChainTip         ChainTip        `json:"chain_tip"`
	Checked          Range           `json:"checked"`
	EvidenceDir      string          `json:"evidence_dir"`
	Servers          []Server        `json:"servers"`
	Coverage         []CoverageRange `json:"coverage"`
	Counts           Counts          `json:"counts"`
	Blocks           []Block         `json:"blocks"`
	Findings         []Finding       `json:"findings"`
	ExpectedPayments []Payment       `json:"expected_payments"`
}

// Build names the canary program that wrote the file.
type Build struct {
	Version string `json:"version"`
	Build   string `json:"build"`
}

// ID returns the build id, "<version>+<build>".
func (b Build) ID() string { return b.Version + "+" + b.Build }

// Network is the chain Canary checked against.
type Network struct {
	Name  string `json:"name"`
	Magic uint32 `json:"magic"`
}

// ChainTip is Core's best block at the time of the run.
type ChainTip struct {
	Height uint32 `json:"height"`
	Hash   string `json:"hash"`
	Source string `json:"source"`
}

// Range is an inclusive height range.
type Range struct {
	From uint32 `json:"from"`
	To   uint32 `json:"to"`
}

// Len returns the number of heights in the range.
func (r Range) Len() int { return int(r.To) - int(r.From) + 1 }

// Server is one configured index server.
type Server struct {
	Label  string  `json:"label"`
	URL    string  `json:"url"`
	Pubkey *string `json:"pubkey"`
	// PublishesRecords is true when the server returned a valid signed
	// record for any block in this run.
	PublishesRecords bool `json:"publishes_records"`
	// SignsReceipts is true when any list in this run arrived with a valid
	// receipt.
	SignsReceipts bool `json:"signs_receipts"`
	// Reachable is true when /info answered in this run.
	Reachable bool       `json:"reachable"`
	Tip       *ServerTip `json:"tip"`
	Policy    *Policy    `json:"policy"`
	// Error is the last error, in plain words.
	Error *string `json:"error"`
}

// ServerTip is a server's best block as Canary last saw it.
type ServerTip struct {
	Height uint32 `json:"height"`
	Hash   string `json:"hash"`
	// Signed is true when the tip came from a valid receipt, false when it
	// came from the unsigned /info.
	Signed bool `json:"signed"`
}

// Policy is what a server declares it leaves out. v1 policies are unsigned.
type Policy struct {
	PrunesSpent      bool   `json:"prunes_spent"`
	DustThresholdSat uint64 `json:"dust_threshold_sat"`
	DustConfigurable bool   `json:"dust_configurable"`
	Signed           bool   `json:"signed"`
}

// CoverageRange is a run of consecutive heights with one state and reason.
type CoverageRange struct {
	From   uint32    `json:"from"`
	To     uint32    `json:"to"`
	State  StateCode `json:"state"`
	Reason Reason    `json:"reason"`
}

// Len returns the number of blocks in the range.
func (c CoverageRange) Len() int { return int(c.To) - int(c.From) + 1 }

// Counts holds the number of blocks in each state. All six keys are always
// present in the file.
type Counts struct {
	Verified     uint32 `json:"verified"`
	Resolved     uint32 `json:"resolved"`
	Unresolvable uint32 `json:"unresolvable"`
	Unverified   uint32 `json:"unverified"`
	Disputed     uint32 `json:"disputed"`
	Compromised  uint32 `json:"compromised"`
}

// Get returns the count for one state code.
func (c Counts) Get(s StateCode) uint32 {
	switch s {
	case Verified:
		return c.Verified
	case Resolved:
		return c.Resolved
	case Unresolvable:
		return c.Unresolvable
	case Unverified:
		return c.Unverified
	case Disputed:
		return c.Disputed
	case Compromised:
		return c.Compromised
	}
	return 0
}

// Total returns the number of blocks across all six states.
func (c Counts) Total() int {
	return int(c.Verified) + int(c.Resolved) + int(c.Unresolvable) +
		int(c.Unverified) + int(c.Disputed) + int(c.Compromised)
}

// NotPassed returns the number of blocks that are neither Checked nor
// Checked with a gap filled.
func (c Counts) NotPassed() int {
	return int(c.Unresolvable) + int(c.Unverified) + int(c.Disputed) + int(c.Compromised)
}

// UnmarshalJSON requires all six keys and rejects any other.
func (c *Counts) UnmarshalJSON(b []byte) error {
	var m map[string]*uint32
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	fields := map[StateCode]*uint32{
		Verified: &c.Verified, Resolved: &c.Resolved, Unresolvable: &c.Unresolvable,
		Unverified: &c.Unverified, Disputed: &c.Disputed, Compromised: &c.Compromised,
	}
	for k := range m {
		if _, ok := fields[StateCode(k)]; !ok {
			return fmt.Errorf("counts: unknown key %q", k)
		}
	}
	for code, dst := range fields {
		v, ok := m[string(code)]
		if !ok || v == nil {
			return fmt.Errorf("counts: key %q is missing", code)
		}
		*dst = *v
	}
	return nil
}

// Block is the detail for one block, keyed by hash.
type Block struct {
	Height  uint32        `json:"height"`
	Hash    string        `json:"hash"`
	State   StateCode     `json:"state"`
	Reason  Reason        `json:"reason"`
	Servers []BlockServer `json:"servers"`
}

// BlockServer is one server's result for one block.
type BlockServer struct {
	Label         string     `json:"label"`
	State         StateCode  `json:"state"`
	Reason        Reason     `json:"reason"`
	RecordEventID *string    `json:"record_event_id"`
	N             *uint32    `json:"n"`
	Root          *string    `json:"root"`
	Positions     *Positions `json:"positions"`
	Filled        uint32     `json:"filled"`
	Signed        bool       `json:"signed"`
	Tip           *Tip       `json:"tip"`
}

// Positions counts what each position in a served list carried.
type Positions struct {
	Full   uint32 `json:"full"`
	Hash   uint32 `json:"hash"`
	Absent uint32 `json:"absent"`
}

// Tip is a height and a display-order hash.
type Tip struct {
	Height uint32 `json:"height"`
	Hash   string `json:"hash"`
}

// BlockRef names a block by height and display-order hash.
type BlockRef struct {
	Height uint32 `json:"height"`
	Hash   string `json:"hash"`
}

// Finding is a fact about a server and a block.
type Finding struct {
	ID        string      `json:"id"`
	Kind      string      `json:"kind"`
	Reason    Reason      `json:"reason"`
	Servers   []ServerRef `json:"servers"`
	Block     BlockRef    `json:"block"`
	Position  *uint32     `json:"position"`
	Txid      *string     `json:"txid"`
	Evidence  *string     `json:"evidence"`
	Provable  bool        `json:"provable"`
	FirstSeen Time        `json:"first_seen"`
	LastSeen  Time        `json:"last_seen"`
}

// ServerRef names a server in a finding.
type ServerRef struct {
	Label  string  `json:"label"`
	Pubkey *string `json:"pubkey"`
}

// Payment is a payment the user declared with --expect.
type Payment struct {
	Txid    string          `json:"txid"`
	Block   *BlockRef       `json:"block"`
	Outcome string          `json:"outcome"`
	Servers []PaymentServer `json:"servers"`
}

// PaymentServer is what one server did with a declared payment.
type PaymentServer struct {
	Label   string `json:"label"`
	Outcome string `json:"outcome"`
}

// Read returns the raw bytes of the state file. A missing file gives
// ErrMissing. Any other read failure gives ErrUnreadable.
func Read(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %w", ErrMissing, err)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnreadable, err)
	}
	return b, nil
}

// Load reads and parses the state file at path.
func Load(path string) (*File, error) {
	b, err := Read(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse checks the format version first, then decodes the rest strictly and
// validates every value. A newer format gives a *NewerFormatError, so the
// dashboard can say so instead of calling the file broken.
func Parse(b []byte) (*File, error) {
	var head struct {
		Format *string `json:"format"`
	}
	if err := json.Unmarshal(b, &head); err != nil {
		return nil, fmt.Errorf("%w: not JSON: %v", ErrUnreadable, err)
	}
	if head.Format == nil {
		return nil, fmt.Errorf("%w: no format field", ErrUnreadable)
	}
	if err := checkFormat(*head.Format); err != nil {
		return nil, err
	}

	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var f File
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnreadable, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: data after the JSON object", ErrUnreadable)
	}
	if err := f.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnreadable, err)
	}
	return &f, nil
}

// checkFormat accepts canary-state/1, reports a later canary-state/N as
// newer, and rejects everything else as unreadable.
func checkFormat(format string) error {
	if format == Format {
		return nil
	}
	if v, ok := strings.CutPrefix(format, formatPrefix); ok {
		n, err := strconv.ParseUint(v, 10, 32)
		if err == nil && n > 1 && v == strconv.FormatUint(n, 10) {
			return &NewerFormatError{Found: format}
		}
	}
	return fmt.Errorf("%w: format %q is not %s", ErrUnreadable, format, Format)
}

var (
	labelRE    = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	findingRE  = regexp.MustCompile(`^[0-9a-f]{12}$`)
	evidenceRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*\.json$`)
)

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func checkHash(what, s string) error {
	if !isHex(s, 64) {
		return fmt.Errorf("%s %q is not 64 lowercase hex characters", what, s)
	}
	return nil
}

func checkOptHash(what string, s *string) error {
	if s == nil {
		return nil
	}
	return checkHash(what, *s)
}

// ValidEvidenceName reports whether name is a plain evidence file name: no
// directory part, no leading dot, and a .json suffix.
func ValidEvidenceName(name string) bool {
	return evidenceRE.MatchString(name) && !strings.Contains(name, "..")
}

// ValidFindingID reports whether id has the shape of a finding id: 12
// lowercase hex characters.
func ValidFindingID(id string) bool {
	return findingRE.MatchString(id)
}

func checkReason(where string, s StateCode, r Reason) error {
	if !s.Valid() {
		return fmt.Errorf("%s: unknown state %q", where, s)
	}
	got, ok := reasonStates[r]
	if !ok {
		return fmt.Errorf("%s: unknown reason %q", where, r)
	}
	if got != s {
		return fmt.Errorf("%s: reason %q belongs to %q, not %q", where, r, got, s)
	}
	return nil
}

// Validate checks every value the formats document constrains. It does not
// compare blocks with coverage, because a file may carry detail for only some
// blocks.
func (f *File) Validate() error {
	if f.Format != Format {
		return fmt.Errorf("format %q is not %s", f.Format, Format)
	}
	if f.GeneratedAt.IsZero() {
		return errors.New("generated_at is missing")
	}
	if f.Canary.Version == "" || f.Canary.Build == "" {
		return errors.New("canary version and build are required")
	}
	if f.Network.Name == "" {
		return errors.New("network name is missing")
	}
	if err := checkHash("chain_tip hash", f.ChainTip.Hash); err != nil {
		return err
	}
	if f.Checked.From > f.Checked.To {
		return fmt.Errorf("checked range %d to %d runs backwards", f.Checked.From, f.Checked.To)
	}
	if err := f.validateServers(); err != nil {
		return err
	}
	if err := f.validateCoverage(); err != nil {
		return err
	}
	for i, b := range f.Blocks {
		where := fmt.Sprintf("blocks[%d]", i)
		if err := checkHash(where+" hash", b.Hash); err != nil {
			return err
		}
		if err := checkReason(where, b.State, b.Reason); err != nil {
			return err
		}
		for j, s := range b.Servers {
			w := fmt.Sprintf("%s.servers[%d]", where, j)
			if !labelRE.MatchString(s.Label) {
				return fmt.Errorf("%s: bad label %q", w, s.Label)
			}
			if err := checkReason(w, s.State, s.Reason); err != nil {
				return err
			}
			if err := checkOptHash(w+" record_event_id", s.RecordEventID); err != nil {
				return err
			}
			if err := checkOptHash(w+" root", s.Root); err != nil {
				return err
			}
			if s.Tip != nil {
				if err := checkHash(w+" tip hash", s.Tip.Hash); err != nil {
					return err
				}
			}
		}
	}
	if err := f.validateFindings(); err != nil {
		return err
	}
	for i, p := range f.ExpectedPayments {
		where := fmt.Sprintf("expected_payments[%d]", i)
		if err := checkHash(where+" txid", p.Txid); err != nil {
			return err
		}
		if p.Block != nil {
			if err := checkHash(where+" block hash", p.Block.Hash); err != nil {
				return err
			}
		}
		if !contains(overallOutcomes, p.Outcome) {
			return fmt.Errorf("%s: unknown outcome %q", where, p.Outcome)
		}
		for j, s := range p.Servers {
			if !contains(serverOutcomes, s.Outcome) {
				return fmt.Errorf("%s.servers[%d]: unknown outcome %q", where, j, s.Outcome)
			}
		}
	}
	return nil
}

func (f *File) validateServers() error {
	seen := map[string]bool{}
	for i, s := range f.Servers {
		where := fmt.Sprintf("servers[%d]", i)
		if !labelRE.MatchString(s.Label) {
			return fmt.Errorf("%s: label %q must be 1 to 32 of a-z, 0-9 and -", where, s.Label)
		}
		if seen[s.Label] {
			return fmt.Errorf("%s: label %q appears twice", where, s.Label)
		}
		seen[s.Label] = true
		if err := checkOptHash(where+" pubkey", s.Pubkey); err != nil {
			return err
		}
		if s.Tip != nil {
			if err := checkHash(where+" tip hash", s.Tip.Hash); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateCoverage checks that the ranges are sorted, do not overlap, stay
// inside the checked range, and add up to the counts.
func (f *File) validateCoverage() error {
	var sums Counts
	next := int64(f.Checked.From)
	for i, c := range f.Coverage {
		where := fmt.Sprintf("coverage[%d]", i)
		if err := checkReason(where, c.State, c.Reason); err != nil {
			return err
		}
		if c.From > c.To {
			return fmt.Errorf("%s: range %d to %d runs backwards", where, c.From, c.To)
		}
		if int64(c.From) < next {
			return fmt.Errorf("%s: range starts at %d, which overlaps or is out of order", where, c.From)
		}
		if c.To > f.Checked.To {
			return fmt.Errorf("%s: range ends at %d, past the checked range", where, c.To)
		}
		next = int64(c.To) + 1
		n := uint32(c.Len())
		switch c.State {
		case Verified:
			sums.Verified += n
		case Resolved:
			sums.Resolved += n
		case Unresolvable:
			sums.Unresolvable += n
		case Unverified:
			sums.Unverified += n
		case Disputed:
			sums.Disputed += n
		case Compromised:
			sums.Compromised += n
		}
	}
	if sums != f.Counts {
		return fmt.Errorf("counts %+v do not match the coverage ranges %+v", f.Counts, sums)
	}
	if f.Counts.Total() != f.Checked.Len() {
		return fmt.Errorf("counts add up to %d blocks, but the checked range holds %d", f.Counts.Total(), f.Checked.Len())
	}
	return nil
}

func (f *File) validateFindings() error {
	ids := map[string]bool{}
	for i, x := range f.Findings {
		where := fmt.Sprintf("findings[%d]", i)
		if !findingRE.MatchString(x.ID) {
			return fmt.Errorf("%s: id %q is not 12 lowercase hex characters", where, x.ID)
		}
		if ids[x.ID] {
			return fmt.Errorf("%s: id %s appears twice", where, x.ID)
		}
		ids[x.ID] = true
		want := 1
		switch x.Kind {
		case KindWithheld:
			if reasonStates[x.Reason] != Compromised {
				return fmt.Errorf("%s: a withheld finding cannot carry reason %q", where, x.Reason)
			}
		case KindDisagree:
			if x.Reason != RecordsDiffer {
				return fmt.Errorf("%s: a disagree finding must carry reason %q", where, RecordsDiffer)
			}
			want = 2
		case KindWarning:
			if !warningReasons[x.Reason] {
				return fmt.Errorf("%s: a warning cannot carry reason %q", where, x.Reason)
			}
		default:
			return fmt.Errorf("%s: unknown kind %q", where, x.Kind)
		}
		if len(x.Servers) != want {
			return fmt.Errorf("%s: a %s finding names %d server(s), not %d", where, x.Kind, want, len(x.Servers))
		}
		for j, s := range x.Servers {
			if !labelRE.MatchString(s.Label) {
				return fmt.Errorf("%s.servers[%d]: bad label %q", where, j, s.Label)
			}
			if err := checkOptHash(fmt.Sprintf("%s.servers[%d] pubkey", where, j), s.Pubkey); err != nil {
				return err
			}
		}
		if err := checkHash(where+" block hash", x.Block.Hash); err != nil {
			return err
		}
		if err := checkOptHash(where+" txid", x.Txid); err != nil {
			return err
		}
		if x.Evidence != nil && !ValidEvidenceName(*x.Evidence) {
			return fmt.Errorf("%s: evidence %q is not a plain .json file name", where, *x.Evidence)
		}
		if x.Provable && x.Evidence == nil {
			return fmt.Errorf("%s: provable without an evidence file", where)
		}
		if x.FirstSeen.IsZero() || x.LastSeen.IsZero() {
			return fmt.Errorf("%s: first_seen and last_seen are required", where)
		}
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// Marshal validates f and returns the bytes Save would write: indented JSON
// with a trailing newline, and empty arrays written as [] rather than null.
func Marshal(f *File) ([]byte, error) {
	c := normalized(f)
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("state: refuse to write an invalid file: %w", err)
	}
	b, err := json.MarshalIndent(&c, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("state: encode: %w", err)
	}
	return append(b, '\n'), nil
}

// Save writes f to path atomically. It writes <path>.tmp, syncs it, and
// renames it over path, so canary ui never reads half a file.
func Save(path string, f *File) error {
	b, err := Marshal(f)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("state: create directory: %w", err)
	}
	tmp := path + ".tmp"
	w, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("state: create temporary file: %w", err)
	}
	_, werr := w.Write(b)
	serr := w.Sync()
	cerr := w.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("state: write temporary file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("state: replace state file: %w", err)
	}
	return nil
}

func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// normalized returns a copy of f whose arrays are never nil, so they encode
// as [] as the formats document shows.
func normalized(f *File) File {
	c := *f
	c.Servers = orEmpty(c.Servers)
	c.Coverage = orEmpty(c.Coverage)
	c.Blocks = make([]Block, len(f.Blocks))
	for i, b := range f.Blocks {
		b.Servers = orEmpty(b.Servers)
		c.Blocks[i] = b
	}
	c.Findings = make([]Finding, len(f.Findings))
	for i, x := range f.Findings {
		x.Servers = orEmpty(x.Servers)
		c.Findings[i] = x
	}
	c.ExpectedPayments = make([]Payment, len(f.ExpectedPayments))
	for i, p := range f.ExpectedPayments {
		p.Servers = orEmpty(p.Servers)
		c.ExpectedPayments[i] = p
	}
	return c
}

// ETag returns the update-check value for the dashboard: the first 16 bytes,
// as 32 hex characters, of SHA-256(state file bytes ‖ 0x00 ‖ build id). A
// missing state file counts as zero bytes. The build id is part of the hash
// because a new binary may render the same file differently.
func ETag(stateBytes []byte, buildID string) string {
	h := sha256.New()
	h.Write(stateBytes)
	h.Write([]byte{0})
	h.Write([]byte(buildID))
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:16])
}

// FindingSubject returns the <subject> part of a finding id: reason:<reason>
// for a warning, pos:<position> when the position is known, txid:<txid> when
// only the transaction is known, and "-" otherwise.
func FindingSubject(kind string, reason Reason, position *uint32, txid *string) string {
	switch {
	case kind == KindWarning:
		return "reason:" + string(reason)
	case kind == KindWithheld && position != nil:
		return "pos:" + strconv.FormatUint(uint64(*position), 10)
	case kind == KindWithheld && txid != nil:
		return "txid:" + *txid
	}
	return "-"
}

// FindingID returns the stable 12-hex id of a finding: the first 12 hex
// characters of SHA-256("<kind>|<pubkeys>|<block hash>|<subject>"), with the
// pubkeys sorted and joined by commas. The block hash is in display order.
func FindingID(kind string, pubkeys []string, blockHash, subject string) string {
	keys := append([]string(nil), pubkeys...)
	sort.Strings(keys)
	s := kind + "|" + strings.Join(keys, ",") + "|" + blockHash + "|" + subject
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// Network magics Canary knows by name, as decimal uint32 values.
const (
	MagicMain    uint32 = 3652501241
	MagicSignet  uint32 = 1087308554
	MagicRegtest uint32 = 3669344250
)

// NetworkName returns main, signet or regtest for a known magic, and unknown
// for any other.
func NetworkName(magic uint32) string {
	switch magic {
	case MagicMain:
		return "main"
	case MagicSignet:
		return "signet"
	case MagicRegtest:
		return "regtest"
	}
	return "unknown"
}
