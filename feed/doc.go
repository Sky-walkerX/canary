// Package feed turns a server's signed record for one block into a Nostr
// event and back, and fetches records from relays.
//
// A signed record says: for this block hash, the canonical set has n entries
// and this root. The design doc calls it a commitment, which is why the Go type
// is Commitment. Records use Nostr kind 1352, a regular kind, so relays keep
// every version and a server cannot overwrite one it already published. The
// block hash rides in the single-letter b tag, because relays index no other
// tag names.
//
// Who calls it: the reference indexer calls ToEvent to sign each block's
// record and serves the event at GET /commitment/{blockhash}. The checker
// calls FromEvent on every record it reads, which verifies the event id and
// signature before it returns anything. Feed and NewRelayFeed fetch records
// from relays. v1 fetches records over HTTP from each server, so the relay
// path is not yet in the v1 flow.
//
// Two things this package never does. It never uses created_at, which the
// author sets and can backdate: Nostr gives publication, not timestamping, and
// order comes from the chain. And it never returns an event it could not
// verify, or one from an author or block the caller did not ask for.
//
// Byte order: tags carry block hashes in display order, and Commitment holds
// them in internal order. displayHex and parseDisplayHex convert in one place.
//
// The design doc's "Commitment format and Nostr transport" section gives the
// reasons.
package feed
