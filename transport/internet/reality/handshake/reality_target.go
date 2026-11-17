package reality

import (
	"bytes"
	"context"
	"crypto/mlkem"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Keep target EOF observable while the retry reader waits on the client. The
// bounded queue preserves normal fallback bytes; it never retains application
// traffic after Server returns and closes the target.
type retryTargetConn struct {
	net.Conn
	packets   chan targetPacket
	closed    chan struct{}
	closeOnce sync.Once
	readMutex sync.Mutex
	pending   []byte
	readErr   error
	waiting   atomic.Bool
	failed    atomic.Bool
	client    net.Conn
}

type targetPacket struct {
	data []byte
	err  error
}

func newRetryTargetConn(target, client net.Conn) *retryTargetConn {
	// Leave room for a six-byte CCS split across individual reads, plus EOF,
	// while the handshake reader is waiting on the second ClientHello.
	c := &retryTargetConn{Conn: target, client: client, packets: make(chan targetPacket, 8), closed: make(chan struct{})}
	go func() {
		defer close(c.packets)
		buf := make([]byte, size)
		for {
			n, err := target.Read(buf)
			if err != nil {
				c.failed.Store(true)
				if c.waiting.Load() {
					client.Close()
				}
			}
			if n != 0 || err != nil {
				select {
				case c.packets <- targetPacket{bytes.Clone(buf[:n]), err}:
				case <-c.closed:
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	return c
}

func (c *retryTargetConn) Read(p []byte) (int, error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if len(c.pending) == 0 {
		packet, ok := <-c.packets
		if !ok {
			return 0, io.EOF
		}
		c.pending, c.readErr = packet.data, packet.err
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	if len(c.pending) == 0 {
		err := c.readErr
		c.readErr = nil
		return n, err
	}
	return n, nil
}

func (c *retryTargetConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func (c *retryTargetConn) CloseWrite() error {
	if half, ok := c.Conn.(CloseWriteConn); ok {
		return half.CloseWrite()
	}
	return nil
}

func (c *retryTargetConn) beginRetry() {
	c.waiting.Store(true)
	if c.failed.Load() {
		c.client.Close()
	}
}

// readTargetServerHello assembles handshake fragments, while preserving record
// boundaries for both the retry relay and the final authenticated ServerHello.
// The caller holds the handshake mutex.
func (hs *serverHandshakeStateTLS13) readTargetServerHello(conn, target net.Conn, mutex *sync.Mutex, pending []byte) ([]byte, error) {
	closePeers := func() { conn.Close(); target.Close() }
	timer := time.AfterFunc(10*time.Second, closePeers)
	defer timer.Stop()
	stopCancel := context.AfterFunc(hs.ctx, closePeers)
	defer stopCancel()
	var wire, message []byte
	var lengths []int
	buf := make([]byte, size)
	fail := func() ([]byte, error) {
		if hs.c.didHRR {
			conn.Close()
			target.Close()
		}
		return append(wire, pending...), errors.New("REALITY: invalid target ServerHello")
	}
	for {
		for len(pending) < recordHeaderLen || len(pending) < recordHeaderLen+Value(pending[3:5]...) {
			if len(pending) >= size {
				return fail()
			}
			n, err := target.Read(buf[:size-len(pending)])
			pending = append(pending, buf[:n]...)
			if err != nil && n == 0 {
				return fail()
			}
		}
		length := recordHeaderLen + Value(pending[3:5]...)
		if length > size || Value(pending[1:3]...) != VersionTLS12 {
			return fail()
		}
		record := pending[:length]
		if recordType(record[0]) == recordTypeChangeCipherSpec && hs.helloRetryRequest != nil {
			if hs.sentDummyCCS || len(message) != 0 || !bytes.Equal(record, []byte{20, 3, 3, 0, 1, 1}) {
				return fail()
			}
			if n, err := conn.Write(record); err != nil || n != len(record) {
				conn.Close()
				target.Close()
				return nil, io.ErrShortWrite
			}
			hs.sentDummyCCS, hs.c.out.handshakeLen[1] = true, len(record)
			pending = pending[length:]
			continue
		}
		if recordType(record[0]) != recordTypeHandshake || length == recordHeaderLen || len(wire)+length > size {
			return fail()
		}
		message = append(message, record[recordHeaderLen:]...)
		if len(message) < 4 || len(message) < 4+Value(message[1:4]...) {
			wire = append(wire, record...)
			lengths = append(lengths, length-recordHeaderLen)
			pending = pending[length:]
			continue
		}
		if message[0] != typeServerHello || len(message) != 4+Value(message[1:4]...) {
			return fail()
		}
		hello := new(serverHelloMsg)
		if !hello.unmarshal(message) || hello.vers != VersionTLS12 || hello.supportedVersion != VersionTLS13 || cipherSuiteTLS13ByID(hello.cipherSuite) == nil {
			return fail()
		}
		hs.hello = hello
		wire = append(wire, record...)
		lengths = append(lengths, length-recordHeaderLen)
		pending = pending[length:]
		if bytes.Equal(hello.random, helloRetryRequestRandom) {
			if err := hs.retryTargetHello(conn, target, mutex, wire); err != nil {
				conn.Close()
				target.Close()
				return nil, err
			}
			wire, message, lengths = nil, nil, nil
			continue
		}
		valid := false
		if curve, ok := curveForCurveID(hello.serverShare.group); ok {
			_, err := curve.NewPublicKey(hello.serverShare.data)
			valid = err == nil
		} else if hello.serverShare.group == X25519MLKEM768 {
			valid = len(hello.serverShare.data) == mlkem.CiphertextSize768+32
		}
		if !valid || (hs.helloRetryRequest != nil && hello.serverShare.group != hs.helloRetryRequest.selectedGroup) {
			return fail()
		}
		hs.c.out.handshakeLen[0] = len(wire)
		hs.serverHelloRecordLengths = lengths
		return pending, nil
	}
}
