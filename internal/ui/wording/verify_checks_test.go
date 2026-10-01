package wording

import "testing"

// verifyCheckTexts returns every verify check text, so the honesty and
// sentence-length rules cover them too.
func verifyCheckTexts() []string {
	return []string{
		VerifyReadOK("canary-evidence/1", "omission"), VerifyReadMalformed, VerifyReadUnsupported,
		VerifyRecordSignatureOK, VerifyRecordSignatureBad, VerifyRecordMalformed,
		VerifySignerOK, VerifySignerBad,
		VerifyBlockOK(205, "regtest", 3669344250), VerifyBlockOK(205, "unknown", 7), VerifyBlockBad,
		VerifyInclusionOK(1, 3), VerifyInclusionBad(1, 3), VerifyInclusionWrongSize(1, 3), VerifyInclusionWrongSize(4, 3),
		VerifyReceiptOK(137), VerifyReceiptMalformed, VerifyReceiptWrongKey, VerifyReceiptOtherNetwork,
		VerifyReceiptOtherBlock, VerifyReceiptOtherResource, VerifyReceiptOtherBody(137),
		VerifyServedAbsent(3, 1), VerifyServedOtherEntry(3, 1), VerifyServedOtherHash(3, 1), VerifyServedMalformed,
		VerifyServedWrongSize(2, 3), VerifyServedEntry(1), VerifyServedEntryHash(1),
		VerifyWindowInside(212, 7, 144), VerifyWindowInside(212, 1, 144), VerifyWindowAboveTip(200, 144),
		VerifyWindowOutside(400, 195, 144), VerifyWindowNotNeeded(1),
	}
}

// The passing texts must match the report example in the v1 formats doc word
// for word, because that example is what every screen shows.
func TestVerifyCheckTextsMatchTheFormatsDoc(t *testing.T) {
	tests := []struct{ got, want string }{
		{VerifyReadOK("canary-evidence/1", "omission"), "Format canary-evidence/1, claim omission."},
		{VerifyRecordSignatureOK, "The signed record's id and signature are valid."},
		{VerifySignerOK, "The record is signed by the accused key."},
		{VerifyBlockOK(205, "regtest", 3669344250), "The record names block 205 on regtest, the block this file names."},
		{VerifyInclusionOK(1, 3), "Entry 1 of 3 proves into the signed root."},
		{VerifyReceiptOK(137), "The receipt is signed by the same key, names the same block and covers these 137 bytes."},
		{VerifyServedAbsent(3, 1), "The served list has 3 positions, and position 1 is marked absent."},
		{VerifyWindowInside(212, 7, 144), "The server's signed tip was 212, so the block was 7 blocks deep, inside the 144-block window."},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("got  %q\nwant %q", tt.got, tt.want)
		}
	}
}

func TestVerifyCheckTextsCountCorrectly(t *testing.T) {
	tests := []struct{ got, want string }{
		{VerifyBlockOK(9, "unknown", 7), "The record names block 9 on network 7, the block this file names."},
		{VerifyInclusionWrongSize(1, 3), "The proof is for 1 entry, but the record signs for 3."},
		{VerifyServedWrongSize(1, 3), "The served list has 1 position, but the record signs for 3."},
		{VerifyWindowInside(206, 1, 144), "The server's signed tip was 206, so the block was 1 block deep, inside the 144-block window."},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("got  %q\nwant %q", tt.got, tt.want)
		}
	}
}
