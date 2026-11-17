package reality

import (
	"bytes"
	"encoding/binary"
	"net"
	"sync"

	utls "github.com/refraction-networking/utls"
)

// uTLS publishes the final ServerHello only after certificate verification.
// Keep its public wire bytes available during ML-DSA verification after a retry.
// This observer stops at the final ServerHello, before encrypted records, and
// releases its buffers when UClient's handshake returns.
type serverHelloConn struct {
	net.Conn
	mu       sync.Mutex
	records  []byte
	messages []byte
	hello    []byte
	done     bool
}

func (c *serverHelloConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	if !c.done {
		c.observe(p[:n])
	}
	c.mu.Unlock()
	return n, err
}

func (c *serverHelloConn) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clearLocked()
}

func (c *serverHelloConn) finalHello() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.hello)
}

func (c *serverHelloConn) clearLocked() {
	c.records, c.messages, c.hello = nil, nil, nil
	c.done = true
}

func (c *serverHelloConn) observe(data []byte) {
	const limit = 1 << 16
	if len(c.records)+len(data) > limit {
		c.clearLocked()
		return
	}
	c.records = append(c.records, data...)
	for len(c.records) >= 5 {
		if c.records[0] == 23 {
			c.clearLocked()
			return
		}
		length := 5 + int(binary.BigEndian.Uint16(c.records[3:5]))
		if length > limit {
			c.clearLocked()
			return
		}
		if len(c.records) < length {
			return
		}
		if c.records[0] == 22 {
			if len(c.messages)+length-5 > limit {
				c.clearLocked()
				return
			}
			c.messages = append(c.messages, c.records[5:length]...)
			for len(c.messages) >= 4 {
				size := 4 + int(c.messages[1])<<16 + int(c.messages[2])<<8 + int(c.messages[3])
				if size > limit {
					c.clearLocked()
					return
				}
				if len(c.messages) < size {
					break
				}
				if c.messages[0] == 2 {
					if hello := utls.UnmarshalServerHello(c.messages[:size]); hello != nil && hello.ServerShare.Group != 0 {
						c.hello = bytes.Clone(hello.Raw)
						c.records, c.messages, c.done = nil, nil, true
						return
					}
				}
				c.messages = c.messages[size:]
			}
		}
		c.records = c.records[length:]
	}
}
