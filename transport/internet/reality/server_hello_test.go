package reality

import (
	"io"
	"net"
	"sync"
	"testing"
)

// Cleanup can overlap reads from a real-certificate camouflage connection.
func TestServerHelloObserverConcurrentCleanup(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	observer := &serverHelloConn{Conn: client}
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		defer server.Close()
		for range 1000 {
			if _, err := server.Write([]byte{20, 3, 3, 0, 1, 1}); err != nil {
				return
			}
		}
	}()
	go func() {
		defer workers.Done()
		io.Copy(io.Discard, observer)
	}()
	for range 1000 {
		observer.clear()
	}
	workers.Wait()
	if len(observer.finalHello()) != 0 {
		t.Fatal("observer retained handshake data after cleanup")
	}
}
