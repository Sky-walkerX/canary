package core

import (
	"encoding/binary"
	"fmt"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/btcsuite/btcd/wire"
)

// minOutputSize is the smallest serialized output: an 8-byte value and a
// 1-byte script length for an empty script.
const minOutputSize = 9

// DecodeSpentOutputs reads the body of Core's /rest/spenttxouts/<hash>.bin.
// It returns one list per transaction in block order, and each list holds the
// output that each of the transaction's inputs spends, in input order.
//
// Core's REST doc does not describe the binary layout. This reader follows
// SerializeBlockUndo in src/rest.cpp, which is the same in v30.0 and later:
//
//	compact size   the number of transactions in the block
//	compact size   0, for the coinbase, which spends nothing
//	then, for each other transaction, in block order:
//	  compact size   the number of inputs
//	  for each input, the output it spends:
//	    8 bytes        value in satoshis, int64 little-endian
//	    compact size   script length, then the scriptPubKey bytes
//
// Each output uses the ordinary transaction-output serialization, not the
// compressed form in Core's undo files. The reader rejects a non-canonical
// compact size, a negative value, a truncated body and trailing bytes.
func DecodeSpentOutputs(b []byte) ([][]*wire.TxOut, error) {
	r := byteReader{buf: b}

	ntx, err := r.compactSize()
	if err != nil {
		return nil, fmt.Errorf("core: decode spent outputs: transaction count: %w", err)
	}
	// Each list takes at least one byte, so a count beyond the body is false.
	// Checking before allocating stops a short body from claiming millions.
	if ntx > uint64(r.remaining()) {
		return nil, fmt.Errorf("core: decode spent outputs: %d transactions declared, only %d bytes follow", ntx, r.remaining())
	}

	out := make([][]*wire.TxOut, 0, ntx)
	for i := uint64(0); i < ntx; i++ {
		nin, err := r.compactSize()
		if err != nil {
			return nil, fmt.Errorf("core: decode spent outputs: transaction %d input count: %w", i, err)
		}
		if nin > uint64(r.remaining())/minOutputSize {
			return nil, fmt.Errorf("core: decode spent outputs: transaction %d declares %d outputs, only %d bytes follow", i, nin, r.remaining())
		}

		list := make([]*wire.TxOut, 0, nin)
		for j := uint64(0); j < nin; j++ {
			txOut, err := r.txOut()
			if err != nil {
				return nil, fmt.Errorf("core: decode spent outputs: transaction %d input %d: %w", i, j, err)
			}
			list = append(list, txOut)
		}
		out = append(out, list)
	}

	if r.remaining() != 0 {
		return nil, fmt.Errorf("core: decode spent outputs: %d bytes left after %d transactions", r.remaining(), ntx)
	}
	return out, nil
}

// byteReader walks a byte slice and fails, rather than panics, when a field
// runs past the end.
type byteReader struct {
	buf []byte
	off int
}

func (r *byteReader) remaining() int { return len(r.buf) - r.off }

func (r *byteReader) take(n uint64) ([]byte, error) {
	if n > uint64(r.remaining()) {
		return nil, fmt.Errorf("needs %d bytes, %d remain", n, r.remaining())
	}
	b := r.buf[r.off : r.off+int(n)]
	r.off += int(n)
	return b, nil
}

// compactSize reads Bitcoin's variable-length integer. Like Core, it rejects
// a value written in more bytes than it needs, so each value has one encoding.
func (r *byteReader) compactSize() (uint64, error) {
	first, err := r.take(1)
	if err != nil {
		return 0, err
	}
	var size uint64
	var floor uint64
	switch first[0] {
	case 0xfd:
		b, err := r.take(2)
		if err != nil {
			return 0, err
		}
		size, floor = uint64(binary.LittleEndian.Uint16(b)), 0xfd
	case 0xfe:
		b, err := r.take(4)
		if err != nil {
			return 0, err
		}
		size, floor = uint64(binary.LittleEndian.Uint32(b)), 0x10000
	case 0xff:
		b, err := r.take(8)
		if err != nil {
			return 0, err
		}
		size, floor = binary.LittleEndian.Uint64(b), 0x100000000
	default:
		return uint64(first[0]), nil
	}
	if size < floor {
		return 0, fmt.Errorf("non-canonical compact size %d", size)
	}
	return size, nil
}

func (r *byteReader) txOut() (*wire.TxOut, error) {
	v, err := r.take(8)
	if err != nil {
		return nil, fmt.Errorf("value: %w", err)
	}
	value := int64(binary.LittleEndian.Uint64(v))
	if value < 0 {
		return nil, fmt.Errorf("negative value %d", value)
	}
	n, err := r.compactSize()
	if err != nil {
		return nil, fmt.Errorf("script length: %w", err)
	}
	script, err := r.take(n)
	if err != nil {
		return nil, fmt.Errorf("script: %w", err)
	}
	// Copy, so the output does not pin the whole response body in memory.
	return wire.NewTxOut(value, append([]byte{}, script...)), nil
}

// BlockPrevouts holds the output that each input of one block spends. It is
// the canonical.PrevoutSource for that block.
type BlockPrevouts struct {
	outs map[wire.OutPoint]*wire.TxOut
}

var _ canonical.PrevoutSource = (*BlockPrevouts)(nil)

// NewBlockPrevouts pairs the lists from DecodeSpentOutputs with the inputs
// of blk. It fails unless the lists fit the block exactly: one list per
// transaction, an empty list for the coinbase, and one output per input.
func NewBlockPrevouts(blk *wire.MsgBlock, spent [][]*wire.TxOut) (*BlockPrevouts, error) {
	if len(spent) != len(blk.Transactions) {
		return nil, fmt.Errorf("core: pair spent outputs: Core listed %d transactions, the block has %d", len(spent), len(blk.Transactions))
	}

	outs := make(map[wire.OutPoint]*wire.TxOut)
	for i, tx := range blk.Transactions {
		if i == 0 {
			if len(spent[0]) != 0 {
				return nil, fmt.Errorf("core: pair spent outputs: Core listed %d outputs for the coinbase, which spends nothing", len(spent[0]))
			}
			continue
		}
		if len(spent[i]) != len(tx.TxIn) {
			return nil, fmt.Errorf("core: pair spent outputs: transaction %d has %d inputs, Core listed %d outputs", i, len(tx.TxIn), len(spent[i]))
		}
		for j, in := range tx.TxIn {
			if _, dup := outs[in.PreviousOutPoint]; dup {
				return nil, fmt.Errorf("core: pair spent outputs: outpoint %s is spent twice in the block", in.PreviousOutPoint)
			}
			outs[in.PreviousOutPoint] = spent[i][j]
		}
	}
	return &BlockPrevouts{outs: outs}, nil
}

// Prevout returns the output that op names. An outpoint the block does not
// spend is an error, never a nil output, because a missing prevout must stop
// the canonical set rather than drop a transaction from it.
func (p *BlockPrevouts) Prevout(op wire.OutPoint) (*wire.TxOut, error) {
	out, ok := p.outs[op]
	if !ok {
		return nil, fmt.Errorf("core: prevout: %s is not spent in this block", op)
	}
	return out, nil
}
