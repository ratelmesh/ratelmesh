package filetransfer

import (
	"bytes"
	"context"
	"sync"
	"testing"
)

func TestConcurrentOutOfOrderChunks(t *testing.T) {
	s, offer, keys, _ := newTransfer(t, bytes.Repeat([]byte("parallel"), 3000), 113)
	r, err := OpenReceiver(context.Background(), t.TempDir(), offer, keys.recipient, keys.senderPeer, keys.now, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	var wg sync.WaitGroup
	errs := make(chan error, s.Manifest().ChunkCount())
	for i := uint32(0); i < s.Manifest().ChunkCount(); i++ {
		wg.Add(1)
		go func(index uint32) {
			defer wg.Done()
			c, err := s.EncryptChunk(context.Background(), index)
			if err == nil {
				err = r.ReceiveChunk(context.Background(), c)
			}
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	if !r.Complete() {
		t.Fatal("parallel transfer incomplete")
	}
}
