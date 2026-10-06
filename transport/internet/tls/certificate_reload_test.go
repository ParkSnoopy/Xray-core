package tls_test

import (
	"bytes"
	"crypto"
	gotls "crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol/tls/cert"
	. "github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/crypto/ocsp"
	"google.golang.org/protobuf/proto"
)

func TestSnooCertificateReloadSnapshots(t *testing.T) {
	ca, _ := cert.MustGenerate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageCertSign))
	issuer, err := x509.ParseCertificate(ca.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.ParsePKCS8PrivateKey(ca.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	var replies sync.Map
	responder := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		request, err := ocsp.ParseRequest(data)
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		response, ok := replies.Load(request.SerialNumber.String())
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(response.([]byte))
	}))
	defer responder.Close()
	first, _ := cert.MustGenerate(ca, cert.CommonName("DUMMY.example"), cert.DNSNames("DUMMY.example"), func(c *x509.Certificate) {
		c.OCSPServer = []string{responder.URL}
	})
	second, _ := cert.MustGenerate(ca, cert.CommonName("DUMMY.example"), cert.DNSNames("DUMMY.example"), func(c *x509.Certificate) {
		c.OCSPServer = []string{responder.URL}
	})
	response := func(c *cert.Certificate, offset time.Duration) []byte {
		t.Helper()
		leaf, err := x509.ParseCertificate(c.Certificate)
		if err != nil {
			t.Fatal(err)
		}
		data, err := ocsp.CreateResponse(issuer, issuer, ocsp.Response{
			Status: ocsp.Good, SerialNumber: leaf.SerialNumber,
			ThisUpdate: time.Now().Add(offset), NextUpdate: time.Now().Add(time.Hour),
		}, key.(crypto.Signer))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ocsp.ParseResponse(data, issuer); err != nil {
			t.Fatal(err)
		}
		replies.Store(leaf.SerialNumber.String(), data)
		return data
	}
	initialStaple := response(first, -time.Minute)
	issuerPEM, _ := ca.ToPEM()
	dir := t.TempDir()
	writePair := func(c *cert.Certificate) {
		t.Helper()
		chain, key := c.ToPEM()
		chain = append(chain, issuerPEM...)
		if err := os.WriteFile(filepath.Join(dir, "certificate.pem"), chain, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "key.pem"), key, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writePair(first)
	entry := ParseCertificate(first)
	entry.Certificate, err = os.ReadFile(filepath.Join(dir, "certificate.pem"))
	if err != nil {
		t.Fatal(err)
	}
	entry.CertificatePath, entry.KeyPath = filepath.Join(dir, "certificate.pem"), filepath.Join(dir, "key.pem")
	entry.OcspStapling = 1
	original := proto.Clone(entry)
	config := (&Config{Certificate: []*Certificate{entry}}).GetTLSConfig()
	hello := &gotls.ClientHelloInfo{ServerName: "DUMMY.example"}
	waitFor := func(check func(*gotls.Certificate) bool) *gotls.Certificate {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			current, err := config.GetCertificate(hello)
			if err != nil {
				t.Fatal(err)
			}
			if check(current) {
				return current
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatal("certificate update was not published")
		return nil
	}
	held := waitFor(func(c *gotls.Certificate) bool { return bytes.Equal(c.OCSPStaple, initialStaple) })
	done := make(chan struct{})
	var readers sync.WaitGroup
	for range 4 {
		readers.Go(func() {
			tick := time.NewTicker(time.Millisecond)
			defer tick.Stop()
			for {
				select {
				case <-done:
					return
				case <-tick.C:
					current, err := config.GetCertificate(hello)
					if err != nil || current == nil || current.Leaf == nil || len(current.OCSPStaple) == 0 {
						t.Error("concurrent certificate selection failed", err)
						return
					}
					_ = held.OCSPStaple
				}
			}
		})
	}
	defer func() { close(done); readers.Wait() }()
	updatedStaple := response(first, -2*time.Minute)
	waitFor(func(c *gotls.Certificate) bool { return bytes.Equal(c.OCSPStaple, updatedStaple) })
	if !bytes.Equal(held.OCSPStaple, initialStaple) {
		t.Fatal("OCSP refresh mutated a certificate retained by a handshake")
	}
	reloadedStaple := response(second, -time.Minute)
	writePair(second)
	waitFor(func(c *gotls.Certificate) bool {
		return bytes.Equal(c.Certificate[0], second.Certificate) && bytes.Equal(c.OCSPStaple, reloadedStaple)
	})
	if !bytes.Equal(held.Certificate[0], first.Certificate) || !bytes.Equal(held.OCSPStaple, initialStaple) {
		t.Fatal("reload mutated a retained certificate")
	}
	if !proto.Equal(entry, original) {
		t.Fatal("reload mutated the shared protobuf configuration")
	}
}
