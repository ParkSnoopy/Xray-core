package reality_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/splithttp"
	"github.com/xtls/xray-core/transport/internet/stat"
	xraw "github.com/xtls/xray-core/transport/internet/tcp"
)

// Exercise the actual transport listeners and the unchanged REALITY client.
// The P-256-only target requires a HelloRetryRequest with these fingerprints.
func TestREALITYTargetCurves(t *testing.T) {
	for _, curve := range []struct {
		name string
		id   tls.CurveID
	}{
		{"p256", tls.CurveP256},
		{"p256-mldsa", tls.CurveP256},
		{"p256-fragmented", tls.CurveP256},
		{"p256-mldsa-fragmented", tls.CurveP256},
		{"p384", tls.CurveP384},
		{"p384-mldsa-fragmented", tls.CurveP384},
		{"p521", tls.CurveP521},
		{"p521-mldsa-fragmented", tls.CurveP521},
		{"x25519", tls.X25519},
		{"x25519mlkem768", tls.X25519MLKEM768},
		{"x25519mlkem768-mldsa", tls.X25519MLKEM768},
	} {
		for _, transport := range []string{"raw", "xhttp"} {
			for _, fingerprint := range []string{"chrome", "firefox"} {
				t.Run(curve.name+"/"+transport+"/"+fingerprint, func(t *testing.T) {
					if !fingerprintSupportsCurve(t, fingerprint, curve.id) {
						t.Skip("browser fingerprint does not advertise this curve")
					}
					target := newTarget(t, curve.id, targetBehavior{fragmentHello: strings.Contains(curve.name, "fragmented")})
					if curve.id == tls.CurveP256 && fingerprint == "firefox" {
						// Establish the pinned fingerprint's ordinary TLS baseline.
						roots := x509.NewCertPool()
						roots.AddCert(target.Certificate())
						conn, err := net.DialTimeout("tcp", target.Listener.Addr().String(), 3*time.Second)
						if err != nil {
							t.Fatal(err)
						}
						conn.SetDeadline(time.Now().Add(3 * time.Second))
						baseline := utls.UClient(conn, &utls.Config{RootCAs: roots, ServerName: "camouflage.example.test"}, utls.HelloFirefox_Auto)
						err = baseline.Handshake()
						conn.Close()
						if err != nil {
							if err.Error() == "tls: invalid server key share" {
								t.Skipf("pinned Firefox fingerprint fails ordinary P-256 TLS: %v", err)
							}
							t.Fatal(err)
						}
					}
					server, client := realityConfigs(t, target)
					if strings.Contains(curve.name, "mldsa") {
						key, err := mldsa.GenerateKey(mldsa.MLDSA65())
						if err != nil {
							t.Fatal(err)
						}
						server.Mldsa65Seed = key.Bytes()
						client.Mldsa65Verify = key.PublicKey().Bytes()
					}
					client.Fingerprint = fingerprint
					if address := os.Getenv("XRAY_REALITY_TARGET"); address != "" {
						name := os.Getenv("XRAY_REALITY_SERVER_NAME")
						if name == "" {
							t.Fatal("XRAY_REALITY_SERVER_NAME is required with a live target")
						}
						server.Dest, server.ServerNames, client.ServerName = address, []string{name}, name
					}
					port := tcp.PickPort()
					settings := &internet.MemoryStreamConfig{SecurityType: "reality", SecuritySettings: server}
					var listen func(context.Context, xnet.Address, xnet.Port, *internet.MemoryStreamConfig, internet.ConnHandler) (internet.Listener, error)
					var dial func(context.Context, xnet.Destination, *internet.MemoryStreamConfig) (stat.Connection, error)
					if transport == "raw" {
						settings.ProtocolName, settings.ProtocolSettings = "tcp", &xraw.Config{}
						listen, dial = xraw.ListenTCP, xraw.Dial
					} else {
						settings.ProtocolName, settings.ProtocolSettings = "splithttp", &splithttp.Config{Path: "/test", Mode: "stream-one"}
						listen, dial = splithttp.ListenXH, splithttp.Dial
					}
					listener, err := listen(context.Background(), xnet.LocalHostIP, port, settings, func(conn stat.Connection) {
						go func() {
							defer conn.Close()
							var request [4]byte
							if _, err := io.ReadFull(conn, request[:]); err == nil && string(request[:]) == "ping" {
								conn.Write([]byte("authenticated pong"))
							}
						}()
					})
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { listener.Close() })
					clientSettings := *settings
					clientSettings.SecuritySettings = client
					ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
					defer cancel()
					conn, err := dial(ctx, xnet.TCPDestination(xnet.LocalHostIP, port), &clientSettings)
					if err != nil {
						t.Fatal(err)
					}
					defer conn.Close()
					stop := context.AfterFunc(ctx, func() { conn.Close() })
					defer stop()
					if _, err := conn.Write([]byte("ping")); err != nil {
						t.Fatal(err)
					}
					response := make([]byte, len("authenticated pong"))
					if _, err := io.ReadFull(conn, response); err != nil {
						t.Fatal(err)
					}
					if string(response) != "authenticated pong" {
						t.Fatalf("unexpected response %q", response)
					}
					if raw, ok := conn.(*reality.UConn); ok {
						if !raw.Verified || uint16(raw.HandshakeState.ServerHello.ServerShare.Group) != uint16(curve.id) {
							t.Fatal("REALITY authentication or negotiated curve mismatch")
						}
					}
				})
			}
		}
	}
}

func TestREALITYP256AuthenticationAndFallback(t *testing.T) {
	target := newTarget(t, tls.CurveP256, targetBehavior{})
	server, client := realityConfigs(t, target)
	signingKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	server.Mldsa65Seed, client.Mldsa65Verify = signingKey.Bytes(), signingKey.PublicKey().Bytes()
	port := tcp.PickPort()
	var admitted atomic.Int64
	listener, err := xraw.ListenTCP(context.Background(), xnet.LocalHostIP, port, &internet.MemoryStreamConfig{
		ProtocolName: "tcp", ProtocolSettings: &xraw.Config{}, SecurityType: "reality", SecuritySettings: server,
	}, func(conn stat.Connection) { admitted.Add(1); conn.Close() })
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	address := net.JoinHostPort("127.0.0.1", port.String())
	for _, kind := range []string{"wrong-short-id", "wrong-public-key", "wrong-mldsa-key", "retry-random", "retry-session", "retry-name", "retry-point", "retry-extension", "retry-extension-presence", "retry-extension-order"} {
		t.Run(kind, func(t *testing.T) {
			bad := &reality.Config{Fingerprint: "chrome", ServerName: client.ServerName, PublicKey: client.PublicKey, ShortId: client.ShortId, Mldsa65Verify: client.Mldsa65Verify}
			if kind == "wrong-short-id" {
				bad.ShortId = []byte("rejected")
			} else if kind == "wrong-public-key" {
				key, err := ecdh.X25519().GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				bad.PublicKey = key.PublicKey().Bytes()
			} else if kind == "wrong-mldsa-key" {
				key, err := mldsa.GenerateKey(mldsa.MLDSA65())
				if err != nil {
					t.Fatal(err)
				}
				bad.Mldsa65Verify = key.PublicKey().Bytes()
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			tampered := &retryTamperConn{Conn: conn, kind: kind}
			if c, err := reality.UClient(tampered, bad, ctx, xnet.TCPDestination(xnet.LocalHostIP, port)); err == nil {
				c.Close()
				t.Fatal("invalid REALITY credentials accepted")
			}
			if strings.HasPrefix(kind, "retry-") && !tampered.changed {
				t.Fatal("test did not alter the second ClientHello")
			}
			if strings.HasPrefix(kind, "retry-") && tampered.sawFinalHello {
				t.Fatal("server emitted a final ServerHello for a modified retry")
			}
		})
	}
	roots := x509.NewCertPool()
	roots.AddCert(target.Certificate())
	visitor, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", address, &tls.Config{
		RootCAs: roots, ServerName: client.ServerName, MinVersion: tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer visitor.Close()
	visitor.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(visitor, "GET / HTTP/1.1\r\nHost: camouflage.example.test\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(visitor), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent || response.Header.Get("X-Camouflage") != "target" || admitted.Load() != 0 {
		t.Fatal("unauthenticated visitor bypassed camouflage fallback")
	}
}

type retryTamperConn struct {
	net.Conn
	kind          string
	hellos        int
	changed       bool
	sawFinalHello bool
	records       []byte
}

func (c *retryTamperConn) Write(packet []byte) (int, error) {
	originalLength := len(packet)
	if len(packet) > 5 && packet[0] == 22 && packet[5] == 1 {
		c.hellos++
		if c.hellos == 2 {
			modified := bytes.Clone(packet)
			if hello := utls.UnmarshalClientHello(modified[5:]); hello != nil {
				switch c.kind {
				case "retry-random":
					hello.Random[0] ^= 1
				case "retry-session":
					hello.SessionId[0] ^= 1
				case "retry-name":
					if i := bytes.Index(modified, []byte("camouflage.example.test")); i >= 0 {
						modified[i] = 'x'
					}
				case "retry-point":
					if len(hello.KeyShares) == 1 && len(hello.KeyShares[0].Data) > 0 {
						hello.KeyShares[0].Data[0] = 0
					}
				case "retry-extension", "retry-extension-presence", "retry-extension-order":
					modified = mutateRetryExtensions(modified, c.kind)
				}
			}
			c.changed = !bytes.Equal(packet, modified)
			packet = modified
		}
	}
	n, err := c.Conn.Write(packet)
	if err == nil && n == len(packet) {
		return originalLength, nil
	}
	return n, err
}

func (c *retryTamperConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if c.hellos >= 2 && len(c.records)+n < 65536 {
		c.records = append(c.records, p[:n]...)
		for len(c.records) >= 5 {
			length := 5 + int(binary.BigEndian.Uint16(c.records[3:5]))
			if len(c.records) < length {
				break
			}
			if c.records[0] == 22 && length > 5 && c.records[5] == 2 {
				c.sawFinalHello = true
			}
			c.records = c.records[length:]
		}
	}
	return n, err
}

func newTarget(t *testing.T, curve tls.CurveID, behavior targetBehavior) *httptest.Server {
	t.Helper()
	certificate, _ := cert.MustGenerate(nil, cert.DNSNames("camouflage.example.test"), func(c *x509.Certificate) {
		// Leave enough room in the real target flight for ML-DSA's signature.
		c.ExtraExtensions = []pkix.Extension{{Id: []int{1, 3, 6, 1, 4, 1, 55555, 1}, Value: make([]byte, 4096)}}
	})
	chain, key := certificate.ToPEM()
	pair, err := tls.X509KeyPair(chain, key)
	if err != nil {
		t.Fatal(err)
	}
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Camouflage", "target")
		w.WriteHeader(http.StatusNoContent)
	}))
	target.TLS = &tls.Config{
		Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{curve},
	}
	target.EnableHTTP2 = true
	if behavior.fragmentHello || behavior.closeAfterRetry {
		target.Listener = &targetWireListener{Listener: target.Listener, behavior: behavior}
	}
	target.StartTLS()
	t.Cleanup(target.Close)
	return target
}

func realityConfigs(t *testing.T, target *httptest.Server) (*reality.Config, *reality.Config) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := []byte("accepted")
	return &reality.Config{
		Type: "tcp", Dest: target.Listener.Addr().String(), ServerNames: []string{"camouflage.example.test"},
		PrivateKey: key.Bytes(), ShortIds: [][]byte{id}, MaxTimeDiff: 60000,
	}, &reality.Config{
		Fingerprint: "chrome", ServerName: "camouflage.example.test", PublicKey: key.PublicKey().Bytes(), ShortId: id,
	}
}
