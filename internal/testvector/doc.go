// Package testvector loads and runs Canary's self-contained test vectors, the
// JSON files in testdata/vectors.
//
// BIP-352 ships vectors for the tweak of a given set of inputs, but none for
// the index level: which transactions of a block are eligible, in what order,
// and what root they produce. These vectors fill that gap. Each one carries a
// whole block plus every output its transactions spend, so any implementation
// can run it with no node and no network.
//
// Run recomputes the canonical set with the canonical package and the root
// with the commit package, then compares both with the vector's expected
// values. Checking the root as well as the entries means a vector also tests
// the tagged hashes, the odd-node rule of the Merkle tree and the byte order of
// every hash input.
//
// Who calls it: this package's own tests, which run every committed vector
// under plain go test. That is the whole CI contract: hermetic, no node, no
// network. A generator that rebuilds the vectors from a regtest node is not
// written yet. testdata/vectors/README.md describes the format.
package testvector
