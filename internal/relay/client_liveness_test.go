package relay

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ratelmesh/ratelmesh/internal/types"
)

type blockedWriteConn struct {
	net.Conn
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *blockedWriteConn) Write([]byte) (int, error) {
	c.once.Do(func() { close(c.entered) })
	<-c.release
	return 0, net.ErrClosed
}

func (c *blockedWriteConn) Close() error {
	select {
	case <-c.release:
	default:
		close(c.release)
	}
	return nil
}

func TestClientCloseInterruptsBlockedSend(t *testing.T) {
	conn := &blockedWriteConn{entered: make(chan struct{}), release: make(chan struct{})}
	client := &Client{nc: conn}
	sendDone := make(chan error, 1)
	go func() { sendDone <- client.Send(types.Key{}, []byte("frame")) }()
	select {
	case <-conn.entered:
	case <-time.After(time.Second):
		t.Fatal("send did not enter the blocked connection")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- client.Close() }()
	select {
	case <-closeDone:
	case <-time.After(100 * time.Millisecond):
		_ = conn.Close()
		<-sendDone
		<-closeDone
		t.Fatal("Close waited behind a blocked Send; relay recovery can deadlock")
	}
	if err := <-sendDone; err == nil {
		t.Fatal("blocked send succeeded after the connection was closed")
	}
}
