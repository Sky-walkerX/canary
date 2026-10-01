// Package ladder decides what one block's tweak lists are worth. For each
// index server it turns the signed record, the served tweak list, its receipt
// and entries from other sources into one state and one reason. It then
// combines the servers into the block's state.
//
// The steps run in a fixed order for each server:
//
//  1. Record. Check the signature against the pinned key, the block hash and
//     the network. A record that fails counts as no record.
//  2. List. A server that signed a record and served no list reads Can't be
//     checked. Inside the window it also gets a warning.
//  3. Receipt. A missing receipt, or one the pinned key did not sign, leaves
//     the list unsigned, and any finding about it unprovable to others.
//     canary check reads servers over https, or plain http to this computer
//     only, so an unsigned list is still the bytes the server sent. A
//     receipt the pinned key signed for other bytes or another request means
//     the list changed on the way. It counts as not served, and names nobody.
//  4. Decode. A list that fails the reader rules, or whose length differs
//     from the record's n, stops here.
//  5. Window. An absent position inside the retention window is an omission.
//     Outside it, the server's chain claim is checked against Core. Core can
//     refute a claim only about a height it has reached, so a signed tip
//     above Core's tip is never an accusation. A list with no receipt is
//     measured from Core's tip, allowing for a Core node that is behind.
//  6. Fill. Every hash or absent position is looked up in other servers'
//     lists for the same root and in the user's declared payments.
//  7. Root. The root is recomputed only after filling, over all n positions.
//  8. Cross-check. Two servers that signed different roots disagree.
//  9. Declared payments. A payment missing from a matching record, or held
//     back from the list while Core shows it unspent above the dust threshold
//     the receipt signs, names the server.
//
// Filling comes before recomputing, and the order matters. Recomputing over
// a hole cannot match, so a server that sent a hole would never be checked.
// A block whose root was never recomputed is never Checked. It reads Can't
// be checked, which is neither a pass nor an accusation.
//
// Canary makes tweak sourcing accountable. It does not remove the need to
// trust a server. It looks for entries a server left out, never for entries
// it faked. Servers disagree names two servers without saying which lied.
// Only Data withheld names one.
//
// The inputs are plain values with no network access, so canary check, the
// tests and a later proxy can share this package.
package ladder
