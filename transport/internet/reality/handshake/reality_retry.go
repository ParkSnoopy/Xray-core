package reality

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"slices"
	"sync"

	"golang.org/x/crypto/cryptobyte"
)

// retryTargetHello relays one ECDH retry from the target. Authentication stays
// bound to the original X25519 ClientHello; only the TLS traffic key changes.
// The caller holds mutex, as does the initial ClientHello reader in Server.
func (hs *serverHandshakeStateTLS13) retryTargetHello(conn, target net.Conn, mutex *sync.Mutex, record []byte) error {
	retry := hs.hello
	curve, supported := curveForCurveID(retry.selectedGroup)
	if hs.helloRetryRequest != nil || !supported ||
		!slices.Contains(hs.clientHello.supportedCurves, retry.selectedGroup) ||
		!slices.Contains(hs.clientHello.cipherSuites, retry.cipherSuite) ||
		!bytes.Equal(retry.sessionId, hs.clientHello.sessionId) || hs.c.handLen() != 0 {
		return errors.New("REALITY: invalid target HelloRetryRequest")
	}
	for _, share := range hs.clientHello.keyShares {
		if share.group == retry.selectedGroup {
			return errors.New("REALITY: target retried an offered key share")
		}
	}
	if monitored, ok := target.(*retryTargetConn); ok {
		monitored.beginRetry()
		defer monitored.waiting.Store(false)
	}
	if n, err := conn.Write(record); err != nil {
		return err
	} else if n != len(record) {
		return io.ErrShortWrite
	}

	hs.c.conn = &MirrorConn{Mutex: mutex, Conn: conn, Target: target}
	msg, err := hs.c.readHandshake(nil)
	hs.c.conn = conn
	if err != nil {
		return err
	}
	next, ok := msg.(*clientHelloMsg)
	if !ok {
		return errors.New("REALITY: expected second ClientHello")
	}
	first := *hs.clientHello
	first.cookie = retry.cookie
	if next.earlyData || len(next.keyShares) != 1 ||
		next.keyShares[0].group != retry.selectedGroup || illegalClientHelloChange(next, &first) ||
		!unchangedRetryExtensions(hs.clientHello, next) {
		return errors.New("REALITY: invalid second ClientHello")
	}
	if _, err := curve.NewPublicKey(next.keyShares[0].data); err != nil {
		return errors.New("REALITY: invalid ECDH client key share")
	}

	hs.firstClientHello = hs.clientHello
	hs.clientHello = next
	hs.helloRetryRequest = retry
	hs.c.didHRR = true
	return nil
}

// Preserve every encoded extension, including unknown extensions and ordering.
// Only RFC 8446 retry changes are normalized; authentication remains bound to
// the first hello, and the final TLS transcript covers the second hello.
func unchangedRetryExtensions(first, next *clientHelloMsg) bool {
	previous := 0
	for _, identity := range next.pskIdentities {
		for previous < len(first.pskIdentities) && !bytes.Equal(identity.label, first.pskIdentities[previous].label) {
			previous++
		}
		if previous == len(first.pskIdentities) {
			return false
		}
		previous++
	}
	a, ok := immutableRetryExtensions(first.original, len(next.pskIdentities) == 0)
	if !ok {
		return false
	}
	b, ok := immutableRetryExtensions(next.original, len(next.pskIdentities) == 0)
	return ok && bytes.Equal(a, b)
}

func immutableRetryExtensions(raw []byte, dropPSK bool) ([]byte, bool) {
	data := cryptobyte.String(raw)
	var ignored, extensions cryptobyte.String
	if !data.Skip(4+2+32) || !data.ReadUint8LengthPrefixed(&ignored) ||
		!data.ReadUint16LengthPrefixed(&ignored) || !data.ReadUint8LengthPrefixed(&ignored) ||
		!data.ReadUint16LengthPrefixed(&extensions) || !data.Empty() {
		return nil, false
	}
	var immutable []byte
	for !extensions.Empty() {
		var id uint16
		var body cryptobyte.String
		if !extensions.ReadUint16(&id) || !extensions.ReadUint16LengthPrefixed(&body) {
			return nil, false
		}
		switch id {
		case extensionCookie, extensionEarlyData:
			continue
		case 21: // RFC 7685 padding must contain only zero bytes.
			for _, b := range body {
				if b != 0 {
					return nil, false
				}
			}
			continue
		case extensionPreSharedKey:
			if dropPSK {
				continue
			}
			body = nil // ticket ages and binders change on retry
		case extensionKeyShare:
			body = nil // the requested group and public point are validated above
		}
		immutable = binary.BigEndian.AppendUint16(immutable, id)
		immutable = binary.BigEndian.AppendUint16(immutable, uint16(len(body)))
		immutable = append(immutable, body...)
	}
	return immutable, true
}
