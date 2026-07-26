package filetransfer

import "testing"

func FuzzParseOffer(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte(offerMagic))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			t.Skip()
		}
		_, _ = ParseOffer(b, Limits{MaxOfferBytes: 1 << 20, MaxManifestBytes: 1 << 20})
	})
}

func FuzzParseResumeToken(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte(resumeMagic))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			t.Skip()
		}
		_, _ = ParseResumeToken(b, Limits{MaxResumeBytes: 1 << 20})
	})
}

func FuzzParseEncryptedChunk(f *testing.F) {
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			t.Skip()
		}
		_, _ = ParseEncryptedChunk(b, 1<<20)
	})
}
