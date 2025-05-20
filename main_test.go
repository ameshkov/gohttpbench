package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func Test_run_plainHTTP(t *testing.T) {
	srv := newHTTPServer(t, nil)
	t.Cleanup(func() {
		srv.Shutdown(t)
	})

	opts := &Options{
		URL:           srv.URL,
		Connections:   5,
		Timeout:       10,
		RequestsCount: 100,
	}

	state := run(opts)

	require.Equal(t, opts.RequestsCount, state.processed)
	require.Equal(t, opts.RequestsCount, srv.Count())
	require.Equal(t, opts.RequestsCount, state.requestsSent)
	require.Equal(t, 0, state.requestsToSend)
	require.Equal(t, 0, state.errors)
}

func Test_run_HTTPS(t *testing.T) {
	tlsConf, _ := createServerTLSConfig(t, "example.org")
	srv := newHTTPServer(t, tlsConf)
	t.Cleanup(func() {
		srv.Shutdown(t)
	})

	opts := &Options{
		URL:                srv.URL,
		Connections:        5,
		Timeout:            10,
		RequestsCount:      100,
		InsecureSkipVerify: true,
	}

	state := run(opts)

	require.Equal(t, opts.RequestsCount, state.processed)
	require.Equal(t, opts.RequestsCount, srv.Count())
	require.Equal(t, opts.RequestsCount, state.requestsSent)
	require.Equal(t, 0, state.requestsToSend)
	require.Equal(t, 0, state.errors)
}

// createServerTLSConfig creates a TLS configuration to be used by the server.
func createServerTLSConfig(
	t *testing.T,
	tlsServerName string,
) (tlsConfig *tls.Config, certPem []byte) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	require.NoError(t, err)

	notBefore := time.Now()
	notAfter := notBefore.Add(5 * 365 * time.Hour * 24)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"AdGuard Tests"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	template.DNSNames = append(template.DNSNames, tlsServerName)

	derBytes, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		publicKey(privateKey),
		privateKey,
	)
	require.NoError(t, err)

	certPem = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	cert, err := tls.X509KeyPair(certPem, keyPem)
	require.NoError(t, err)

	tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}, ServerName: tlsServerName}

	return tlsConfig, certPem
}

// publicKey returns a public key extracted from the specified private key.
func publicKey(priv any) (pk any) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

// httpServer is a helper for running HTTP/HTTPS test servers that count requests.
type httpServer struct {
	Server     *http.Server
	Listener   net.Listener
	URL        string
	TLS        bool
	RequestCnt int64
}

// newHTTPServer starts a new HTTP or HTTPS server. If tlsConfig is nil, HTTP is used.
func newHTTPServer(t *testing.T, tlsConfig *tls.Config) *httpServer {
	h := &httpServer{}

	h.Server = &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			atomic.AddInt64(&h.RequestCnt, 1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))
		}),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
	}

	var ln net.Listener
	var err error
	if tlsConfig != nil {
		ln, err = tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
		h.TLS = true
	} else {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	h.Listener = ln
	addr := ln.Addr().String()
	if h.TLS {
		h.URL = "https://" + addr
	} else {
		h.URL = "http://" + addr
	}

	go func() {
		if h.TLS {
			_ = h.Server.Serve(ln)
		} else {
			_ = h.Server.Serve(ln)
		}
	}()

	return h
}

// Shutdown gracefully shuts down the server.
func (h *httpServer) Shutdown(t *testing.T) {
	_ = h.Listener.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	if err := h.Server.Shutdown(ctx); err != nil {
		t.Fatalf("failed to shutdown server: %v", err)
	}
}

// Count returns the number of requests received.
func (h *httpServer) Count() int {
	return int(atomic.LoadInt64(&h.RequestCnt))
}
