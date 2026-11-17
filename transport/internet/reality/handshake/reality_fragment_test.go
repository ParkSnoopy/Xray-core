package reality

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"testing"
)

// Exercise the real ServerHello writer with the coalesced encrypted-flight
// buffer selected by the target scanner for records larger than 512 bytes.
func TestFragmentedServerHelloWithBufferedFlight(t *testing.T) {
	for _, headerSplit := range []bool{true, false} {
		name := "split-header"
		if !headerSplit {
			name = "continuation-starts-with-finished"
		}
		t.Run(name, func(t *testing.T) {
			key, err := ecdh.P384().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			random := make([]byte, 32)
			if _, err := rand.Read(random); err != nil {
				t.Fatal(err)
			}
			random[0] = typeFinished
			hello := &serverHelloMsg{
				vers: VersionTLS12, supportedVersion: VersionTLS13, random: random,
				cipherSuite: TLS_AES_128_GCM_SHA256,
				serverShare: keyShare{group: CurveP384, data: key.PublicKey().Bytes()},
			}
			hello.original, err = hello.marshal()
			if err != nil {
				t.Fatal(err)
			}
			clientHello := &clientHelloMsg{vers: VersionTLS12, random: random, compressionMethods: []byte{0}}
			clientHello.original, err = clientHello.marshal()
			if err != nil {
				t.Fatal(err)
			}
			c := &Conn{config: &Config{}, vers: VersionTLS13, buffering: true}
			c.in.version, c.out.version = VersionTLS13, VersionTLS13
			c.out.handshakeLen[2] = 1024
			c.out.handshakeBuf = make([]byte, 0, c.out.handshakeLen[2])
			suite := cipherSuiteTLS13ByID(hello.cipherSuite)
			lengths := []int{1, 2, len(hello.original) - 3}
			if !headerSplit {
				lengths = []int{6, len(hello.original) - 6}
			}
			hs := &serverHandshakeStateTLS13{
				c: c, ctx: context.Background(), clientHello: clientHello, hello: hello,
				suite: suite, transcript: suite.hash.New(), sentDummyCCS: true,
				sharedKey: make([]byte, suite.hash.Size()), serverHelloRecordLengths: lengths,
			}
			if err := hs.sendServerParameters(); err != nil {
				t.Fatal(err)
			}
			var expected []byte
			offset := 0
			for _, length := range lengths {
				header := []byte{byte(recordTypeHandshake), 3, 3, 0, 0}
				binary.BigEndian.PutUint16(header[3:5], uint16(length))
				expected = append(expected, header...)
				expected = append(expected, hello.original[offset:offset+length]...)
				offset += length
			}
			if !bytes.Equal(c.sendBuf, expected) {
				t.Fatal("ServerHello fragments were diverted into the encrypted-flight buffer")
			}
			extensions, err := new(encryptedExtensionsMsg).marshal()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(c.out.handshakeBuf, extensions) {
				t.Fatal("ServerHello continuation changed the encrypted-flight buffer")
			}
			transcript := suite.hash.New()
			transcript.Write(clientHello.original)
			transcript.Write(hello.original)
			transcript.Write(extensions)
			if !bytes.Equal(hs.transcript.Sum(nil), transcript.Sum(nil)) {
				t.Fatal("fragmentation changed the handshake transcript")
			}
		})
	}
}
