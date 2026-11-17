package reality_test

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	xraw "github.com/xtls/xray-core/transport/internet/tcp"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/cryptobyte"
)

type targetBehavior struct {
	fragmentHello   bool
	closeAfterRetry bool
	retryClose      <-chan struct{}
}

type targetWireListener struct {
	net.Listener
	behavior targetBehavior
}

func (l *targetWireListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &targetWireConn{Conn: conn, behavior: l.behavior}, nil
}

type targetWireConn struct {
	net.Conn
	behavior targetBehavior
}

func (c *targetWireConn) Write(packet []byte) (int, error) {
	var output []byte
	closeRetry := false
	for offset := 0; offset < len(packet); {
		if len(packet)-offset < 5 {
			return 0, io.ErrUnexpectedEOF
		}
		length := 5 + int(binary.BigEndian.Uint16(packet[offset+3:offset+5]))
		if length > len(packet)-offset {
			return 0, io.ErrUnexpectedEOF
		}
		record := packet[offset : offset+length]
		if record[0] == 22 && length > 5 && record[5] == 2 {
			if hello := utls.UnmarshalServerHello(record[5:]); hello != nil && hello.SelectedGroup != 0 {
				closeRetry = c.behavior.closeAfterRetry
			}
			if c.behavior.fragmentHello && length > 8 {
				body := record[5:]
				// Split the handshake header itself as well as its body.
				for _, part := range [][]byte{body[:1], body[1:3], body[3:]} {
					header := append([]byte(nil), record[:5]...)
					binary.BigEndian.PutUint16(header[3:5], uint16(len(part)))
					output = append(output, header...)
					output = append(output, part...)
				}
			} else {
				output = append(output, record...)
			}
		} else {
			output = append(output, record...)
		}
		offset += length
	}
	n, err := c.Conn.Write(output)
	if closeRetry {
		go func() { <-c.behavior.retryClose; c.Conn.Close() }()
	}
	if err != nil {
		return 0, err
	}
	if n != len(output) {
		return 0, io.ErrShortWrite
	}
	return len(packet), nil
}

func fingerprintSupportsCurve(t *testing.T, name string, curve tls.CurveID) bool {
	t.Helper()
	id := utls.HelloChrome_Auto
	if name == "firefox" {
		id = utls.HelloFirefox_Auto
	}
	spec, err := utls.UTLSIdToSpec(id)
	if err != nil {
		t.Fatal(err)
	}
	for _, extension := range spec.Extensions {
		if groups, ok := extension.(*utls.SupportedCurvesExtension); ok {
			for _, advertised := range groups.Curves {
				if uint16(advertised) == uint16(curve) {
					return true
				}
			}
		}
	}
	return false
}

// These are wire mutations, not a second implementation of retry policy.
// Production validation must reject them before emitting its final ServerHello.
func mutateRetryExtensions(packet []byte, kind string) []byte {
	raw := packet[5:]
	data := cryptobyte.String(raw)
	var ignored, extensions cryptobyte.String
	if !data.Skip(4+2+32) || !data.ReadUint8LengthPrefixed(&ignored) || !data.ReadUint16LengthPrefixed(&ignored) || !data.ReadUint8LengthPrefixed(&ignored) || !data.ReadUint16LengthPrefixed(&extensions) {
		return packet
	}
	extensionStart := len(raw) - len(extensions)
	var spans [][2]int
	unknown := -1
	for !extensions.Empty() {
		start := len(raw) - len(extensions)
		var id uint16
		if !extensions.ReadUint16(&id) || !extensions.ReadUint16LengthPrefixed(&ignored) {
			return packet
		}
		spans = append(spans, [2]int{5 + start, 5 + len(raw) - len(extensions)})
		if id&0x0f0f == 0x0a0a {
			unknown = len(spans) - 1
		}
	}
	if len(spans) < 2 || unknown < 0 {
		return packet
	}
	if kind == "retry-extension-order" {
		a, b := spans[0], spans[1]
		output := append([]byte(nil), packet[:a[0]]...)
		output = append(output, packet[b[0]:b[1]]...)
		output = append(output, packet[a[0]:a[1]]...)
		return append(output, packet[b[1]:]...)
	}
	span := spans[unknown]
	if kind == "retry-extension" {
		packet[span[0]] ^= 0x10
		return packet
	}
	output := append([]byte(nil), packet[:span[0]]...)
	output = append(output, packet[span[1]:]...)
	binary.BigEndian.PutUint16(output[3:5], uint16(len(output)-5))
	bodyLength := len(output) - 9
	output[6], output[7], output[8] = byte(bodyLength>>16), byte(bodyLength>>8), byte(bodyLength)
	lengthOffset := 5 + extensionStart - 2
	length := int(binary.BigEndian.Uint16(output[lengthOffset:lengthOffset+2])) - (span[1] - span[0])
	binary.BigEndian.PutUint16(output[lengthOffset:lengthOffset+2], uint16(length))
	return output
}

func TestREALITYRetryCancellation(t *testing.T) {
	for _, closeTarget := range []bool{false, true} {
		name := "stalled-client"
		if closeTarget {
			name = "target-closed"
		}
		t.Run(name, func(t *testing.T) {
			signal := make(chan struct{})
			finishTarget := sync.OnceFunc(func() { close(signal) })
			defer finishTarget()
			target := newTarget(t, tls.CurveP384, targetBehavior{closeAfterRetry: closeTarget, retryClose: signal})
			server, client := realityConfigs(t, target)
			port := tcp.PickPort()
			listener, err := xraw.ListenTCP(context.Background(), xnet.LocalHostIP, port, &internet.MemoryStreamConfig{
				ProtocolName: "tcp", ProtocolSettings: &xraw.Config{}, SecurityType: "reality", SecuritySettings: server,
			}, func(c stat.Connection) { c.Close(); t.Error("stalled client was admitted") })
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			raw, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port.String()), 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			blocked := &stallRetryConn{Conn: raw, ready: make(chan struct{}), release: make(chan struct{})}
			release := sync.OnceFunc(func() { close(blocked.release) })
			defer release()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() {
				c, err := reality.UClient(blocked, client, ctx, xnet.TCPDestination(xnet.LocalHostIP, port))
				if c != nil {
					c.Close()
				}
				result <- err
			}()
			select {
			case <-blocked.ready:
			case err := <-result:
				t.Fatalf("client did not reach retry: %v", err)
			case <-ctx.Done():
				t.Fatal("client did not reach retry")
			}
			start := time.Now()
			if closeTarget {
				finishTarget()
			}
			raw.SetReadDeadline(time.Now().Add(12 * time.Second))
			_, err = io.Copy(io.Discard, raw)
			var timeout net.Error
			if errors.As(err, &timeout) && timeout.Timeout() {
				t.Fatal("server did not close the stalled retry")
			}
			if closeTarget && time.Since(start) > 2*time.Second {
				t.Fatal("target EOF did not interrupt the retry promptly")
			}
			release()
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("stalled retry succeeded")
				}
			case <-ctx.Done():
				t.Fatal("retry client did not stop")
			}
		})
	}
}

type stallRetryConn struct {
	net.Conn
	hellos  int
	ready   chan struct{}
	release chan struct{}
}

func (c *stallRetryConn) Write(packet []byte) (int, error) {
	if len(packet) > 5 && packet[0] == 22 && packet[5] == 1 {
		c.hellos++
		if c.hellos == 2 {
			close(c.ready)
			<-c.release
			return 0, io.ErrClosedPipe
		}
	}
	return c.Conn.Write(packet)
}
