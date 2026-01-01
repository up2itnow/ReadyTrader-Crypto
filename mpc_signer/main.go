package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/coinbase/cb-mpc/demos-go/cb-mpc-go/api/curve"
	"github.com/coinbase/cb-mpc/demos-go/cb-mpc-go/api/mpc"
	"github.com/coinbase/cb-mpc/demos-go/cb-mpc-go/api/transport/mtls"
	"golang.org/x/crypto/sha3"
)

type config struct {
	RoleIndex int

	// HTTP server (external control plane for orchestration + signing requests)
	HTTPListenAddr string

	// MPC transport (mTLS messenger) addresses for the CB-MPC parties.
	Party0Addr string
	Party1Addr string

	CaCertPath  string
	CertPath    string
	KeyPath     string
	Party0Cert  string
	Party1Cert  string
	PeerHTTPURL string // leader only: where to reach follower control-plane

	KeySharePath string
}

func mustEnv(name string) string {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		log.Fatalf("Missing required env var: %s", name)
	}
	return v
}

func envDefault(name, def string) string {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	return v
}

func loadConfig() config {
	roleRaw := mustEnv("MPC_ROLE_INDEX")
	var role int
	_, err := fmt.Sscanf(roleRaw, "%d", &role)
	if err != nil || (role != 0 && role != 1) {
		log.Fatalf("Invalid MPC_ROLE_INDEX=%q (expected 0 or 1)", roleRaw)
	}

	cfg := config{
		RoleIndex:     role,
		HTTPListenAddr: envDefault("MPC_HTTP_LISTEN", "0.0.0.0:8787"),
		Party0Addr:     mustEnv("MPC_PARTY0_ADDR"),
		Party1Addr:     mustEnv("MPC_PARTY1_ADDR"),
		CaCertPath:     mustEnv("MPC_CA_CERT"),
		CertPath:       mustEnv("MPC_CERT"),
		KeyPath:        mustEnv("MPC_KEY"),
		Party0Cert:     mustEnv("MPC_PARTY0_CERT"),
		Party1Cert:     mustEnv("MPC_PARTY1_CERT"),
		KeySharePath:   envDefault("MPC_KEYSHARE_PATH", "data/mpc_keyshare.bin"),
	}
	if role == 0 {
		cfg.PeerHTTPURL = mustEnv("MPC_PEER_HTTP_URL")
	}
	return cfg
}

type state struct {
	cfg config

	mu sync.Mutex

	// messenger is initialized asynchronously on startup; endpoints should refuse
	// operations until ready.
	messenger *mtls.MTLSMessenger
	pnames    []string

	curve curve.Curve

	keyShareLoaded bool
	keyShare       mpc.ECDSA2PCKey

	// outstanding background operations (follower)
	lastErr string
}

func (s *state) setErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastErr = err.Error()
}

func (s *state) clearErr() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastErr = ""
}

func (s *state) statusJSON() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return map[string]any{
		"role_index":       s.cfg.RoleIndex,
		"messenger_ready":  s.messenger != nil,
		"key_share_loaded": s.keyShareLoaded,
		"last_error":       s.lastErr,
	}
}

func (s *state) loadKeyShareIfPresent() error {
	path := s.cfg.KeySharePath
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var k mpc.ECDSA2PCKey
	if err := k.UnmarshalBinary(b); err != nil {
		return err
	}
	s.keyShare = k
	s.keyShareLoaded = true
	return nil
}

func (s *state) saveKeyShare() error {
	if !s.keyShareLoaded {
		return fmt.Errorf("no key share to save")
	}
	b, err := s.keyShare.MarshalBinary()
	if err != nil {
		return err
	}
	p := s.cfg.KeySharePath
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func ethAddressFromUncompressedPubkey(pubUncompressed []byte) (string, error) {
	// Input must be 65 bytes: 0x04 || X32 || Y32.
	if len(pubUncompressed) != 65 || pubUncompressed[0] != 0x04 {
		return "", fmt.Errorf("expected uncompressed SEC1 pubkey (65 bytes starting with 0x04)")
	}
	h := sha3.NewLegacyKeccak256()
	_, _ = h.Write(pubUncompressed[1:]) // X||Y
	sum := h.Sum(nil)
	addr := sum[len(sum)-20:]
	return "0x" + hex.EncodeToString(addr), nil
}

func (s *state) publicKeyAndAddress() (string, string, error) {
	if !s.keyShareLoaded {
		return "", "", fmt.Errorf("key share not initialized")
	}
	Q, err := s.keyShare.Q()
	if err != nil {
		return "", "", err
	}
	defer Q.Free()
	pad32 := func(b []byte) []byte {
		if len(b) >= 32 {
			if len(b) == 32 {
				return b
			}
			return b[len(b)-32:]
		}
		p := make([]byte, 32)
		copy(p[32-len(b):], b)
		return p
	}
	x := pad32(Q.GetX())
	y := pad32(Q.GetY())
	pub := make([]byte, 1+32+32)
	pub[0] = 0x04
	copy(pub[1:33], x)
	copy(pub[33:], y)
	addr, err := ethAddressFromUncompressedPubkey(pub)
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(pub), addr, nil
}

func (s *state) buildMessengerWithRetry(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		m, pnames, err := buildMessenger(s.cfg)
		if err == nil {
			s.mu.Lock()
			s.messenger = m
			s.pnames = pnames
			s.mu.Unlock()
			log.Printf("MPC messenger ready (role=%d)", s.cfg.RoleIndex)
			return
		}
		s.setErr(err)
		log.Printf("MPC messenger init failed (will retry): %v", err)
		time.Sleep(2 * time.Second)
	}
}

func buildMessenger(cfg config) (*mtls.MTLSMessenger, []string, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load TLS cert/key: %w", err)
	}
	caCert, err := os.ReadFile(cfg.CaCertPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read CA cert: %w", err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)

	party0CertPEM, err := os.ReadFile(cfg.Party0Cert)
	if err != nil {
		return nil, nil, fmt.Errorf("read party0 cert: %w", err)
	}
	party1CertPEM, err := os.ReadFile(cfg.Party1Cert)
	if err != nil {
		return nil, nil, fmt.Errorf("read party1 cert: %w", err)
	}
	p0Der, _ := pem.Decode(party0CertPEM)
	if p0Der == nil || len(p0Der.Bytes) == 0 {
		return nil, nil, fmt.Errorf("parse party0 cert: expected PEM certificate")
	}
	p0, err := x509.ParseCertificate(p0Der.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse party0 cert: %w", err)
	}
	p1Der, _ := pem.Decode(party1CertPEM)
	if p1Der == nil || len(p1Der.Bytes) == 0 {
		return nil, nil, fmt.Errorf("parse party1 cert: expected PEM certificate")
	}
	p1, err := x509.ParseCertificate(p1Der.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse party1 cert: %w", err)
	}
	p0Name, err := mtls.PartyNameFromCertificate(p0)
	if err != nil {
		return nil, nil, fmt.Errorf("party0 pname: %w", err)
	}
	p1Name, err := mtls.PartyNameFromCertificate(p1)
	if err != nil {
		return nil, nil, fmt.Errorf("party1 pname: %w", err)
	}
	pnames := []string{p0Name, p1Name}

	parties := map[int]mtls.PartyConfig{
		0: {Address: cfg.Party0Addr, Cert: p0},
		1: {Address: cfg.Party1Addr, Cert: p1},
	}
	nameToIndex := map[string]int{
		p0Name: 0,
		p1Name: 1,
	}

	m, err := mtls.NewMTLSMessenger(mtls.Config{
		Parties:     parties,
		CertPool:    caPool,
		TLSCert:     cert,
		NameToIndex: nameToIndex,
		SelfIndex:   cfg.RoleIndex,
	})
	if err != nil {
		return nil, nil, err
	}
	return m, pnames, nil
}

func decodeHex32(s string) ([]byte, error) {
	v := strings.TrimSpace(s)
	v = strings.TrimPrefix(v, "0x")
	b, err := hex.DecodeString(v)
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("expected 32-byte hex, got %d bytes", len(b))
	}
	return b, nil
}

func (s *state) requireReady() (*mtls.MTLSMessenger, []string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.messenger == nil {
		return nil, nil, fmt.Errorf("messenger not ready")
	}
	return s.messenger, append([]string{}, s.pnames...), nil
}

func (s *state) runKeyGen() error {
	m, pnames, err := s.requireReady()
	if err != nil {
		return err
	}
	cv, err := curve.NewSecp256k1()
	if err != nil {
		return err
	}
	// Keep curve instance for later; it holds native resources.
	s.mu.Lock()
	if s.curve == nil {
		s.curve = cv
	} else {
		cv.Free()
	}
	s.mu.Unlock()

	job, err := mpc.NewJob2P(m, s.cfg.RoleIndex, pnames)
	if err != nil {
		return err
	}
	defer job.Free()

	resp, err := mpc.ECDSA2PCKeyGen(job, &mpc.ECDSA2PCKeyGenRequest{Curve: s.curve})
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.keyShare = resp.KeyShare
	s.keyShareLoaded = true
	s.mu.Unlock()

	return s.saveKeyShare()
}

func (s *state) runSign(sessionID []byte, digest32 []byte) ([]byte, error) {
	if len(digest32) != 32 {
		return nil, fmt.Errorf("digest must be 32 bytes")
	}
	m, pnames, err := s.requireReady()
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	hasKey := s.keyShareLoaded
	key := s.keyShare
	cv := s.curve
	s.mu.Unlock()
	if !hasKey {
		return nil, fmt.Errorf("key share not initialized")
	}
	if cv == nil {
		// Should never happen because keygen initializes curve, but be defensive.
		curveObj, err := curve.NewSecp256k1()
		if err != nil {
			return nil, err
		}
		cv = curveObj
		s.mu.Lock()
		s.curve = curveObj
		s.mu.Unlock()
	}

	job, err := mpc.NewJob2P(m, s.cfg.RoleIndex, pnames)
	if err != nil {
		return nil, err
	}
	defer job.Free()

	resp, err := mpc.ECDSA2PCSign(job, &mpc.ECDSA2PCSignRequest{
		SessionID: sessionID,
		KeyShare:  key,
		Message:   digest32,
	})
	if err != nil {
		return nil, err
	}

	// Self-check: verify signature against Q.
	Q, err := key.Q()
	if err != nil {
		return nil, err
	}
	defer Q.Free()
	if err := resp.Verify(Q, digest32, cv); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	return resp.Signature, nil
}

// ---- HTTP handlers ----

func writeJSON(w http.ResponseWriter, status int, obj any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(obj)
}

func readJSON(r *http.Request, dst any) error {
	b, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, dst)
}

type startReq struct {
	SessionID string `json:"session_id"`
	DigestHex string `json:"digest_hex"`
}

func main() {
	cfg := loadConfig()

	st := &state{cfg: cfg}
	if err := st.loadKeyShareIfPresent(); err != nil {
		log.Fatalf("failed to load key share: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize messenger in background so HTTP server can come up and report status.
	go st.buildMessengerWithRetry(ctx)

	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true, "status": st.statusJSON()})
	})
	mux.HandleFunc("/internal/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, st.statusJSON())
	})

	// Address endpoint (used by ReadyTrader-Crypto RemoteSigner).
	mux.HandleFunc("/address", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		loaded := st.keyShareLoaded
		st.mu.Unlock()
		if !loaded {
			writeJSON(w, 409, map[string]any{"error": "key_not_initialized"})
			return
		}
		pubHex, addr, err := st.publicKeyAndAddress()
		if err != nil {
			writeJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"address": addr, "public_key_uncompressed_hex": pubHex})
	})

	// Leader-only orchestration endpoints
	mux.HandleFunc("/dkg", func(w http.ResponseWriter, r *http.Request) {
		if cfg.RoleIndex != 0 {
			writeJSON(w, 403, map[string]any{"error": "leader_only"})
			return
		}
		st.mu.Lock()
		loaded := st.keyShareLoaded
		st.mu.Unlock()
		if loaded {
			pubHex, addr, err := st.publicKeyAndAddress()
			if err != nil {
				writeJSON(w, 500, map[string]any{"error": err.Error()})
				return
			}
			writeJSON(w, 200, map[string]any{"ok": true, "already_initialized": true, "address": addr, "public_key_uncompressed_hex": pubHex})
			return
		}

		// Kick follower keygen asynchronously, then run locally.
		if err := postJSON(cfg.PeerHTTPURL+"/internal/start_dkg", map[string]any{}, 5*time.Second); err != nil {
			writeJSON(w, 502, map[string]any{"error": "peer_start_failed", "detail": err.Error()})
			return
		}
		if err := st.runKeyGen(); err != nil {
			writeJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		// Wait for follower to report key loaded.
		if err := waitPeerReady(cfg.PeerHTTPURL, 30*time.Second); err != nil {
			writeJSON(w, 502, map[string]any{"error": "peer_not_ready", "detail": err.Error()})
			return
		}

		pubHex, addr, err := st.publicKeyAndAddress()
		if err != nil {
			writeJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "address": addr, "public_key_uncompressed_hex": pubHex})
	})

	mux.HandleFunc("/sign_digest", func(w http.ResponseWriter, r *http.Request) {
		if cfg.RoleIndex != 0 {
			writeJSON(w, 403, map[string]any{"error": "leader_only"})
			return
		}
		var req startReq
		if err := readJSON(r, &req); err != nil {
			writeJSON(w, 400, map[string]any{"error": "bad_json", "detail": err.Error()})
			return
		}
		digest, err := decodeHex32(req.DigestHex)
		if err != nil {
			writeJSON(w, 400, map[string]any{"error": "bad_digest", "detail": err.Error()})
			return
		}
		sid := []byte(req.SessionID)
		if len(sid) == 0 {
			sid = []byte(fmt.Sprintf("sid-%d", time.Now().UnixNano()))
		}

		// Ensure DKG completed
		st.mu.Lock()
		loaded := st.keyShareLoaded
		st.mu.Unlock()
		if !loaded {
			writeJSON(w, 409, map[string]any{"error": "key_not_initialized"})
			return
		}

		// Kick follower signing in background, then sign locally (blocking).
		if err := postJSON(cfg.PeerHTTPURL+"/internal/start_sign", map[string]any{
			"session_id":  string(sid),
			"digest_hex":  "0x" + hex.EncodeToString(digest),
		}, 5*time.Second); err != nil {
			writeJSON(w, 502, map[string]any{"error": "peer_start_failed", "detail": err.Error()})
			return
		}

		sigDER, err := st.runSign(sid, digest)
		if err != nil {
			writeJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "signature_der_hex": "0x" + hex.EncodeToString(sigDER)})
	})

	// Follower-only internal control endpoints: start DKG / sign in background.
	mux.HandleFunc("/internal/start_dkg", func(w http.ResponseWriter, r *http.Request) {
		if cfg.RoleIndex != 1 {
			writeJSON(w, 403, map[string]any{"error": "follower_only"})
			return
		}
		st.mu.Lock()
		loaded := st.keyShareLoaded
		st.mu.Unlock()
		if loaded {
			writeJSON(w, 200, map[string]any{"ok": true, "already_initialized": true})
			return
		}
		go func() {
			st.clearErr()
			if err := st.runKeyGen(); err != nil {
				st.setErr(err)
			}
		}()
		writeJSON(w, 200, map[string]any{"ok": true, "started": true})
	})

	mux.HandleFunc("/internal/start_sign", func(w http.ResponseWriter, r *http.Request) {
		if cfg.RoleIndex != 1 {
			writeJSON(w, 403, map[string]any{"error": "follower_only"})
			return
		}
		var req startReq
		if err := readJSON(r, &req); err != nil {
			writeJSON(w, 400, map[string]any{"error": "bad_json", "detail": err.Error()})
			return
		}
		digest, err := decodeHex32(req.DigestHex)
		if err != nil {
			writeJSON(w, 400, map[string]any{"error": "bad_digest", "detail": err.Error()})
			return
		}
		sid := []byte(req.SessionID)
		if len(sid) == 0 {
			writeJSON(w, 400, map[string]any{"error": "missing_session_id"})
			return
		}
		go func() {
			st.clearErr()
			_, err := st.runSign(sid, digest)
			if err != nil {
				st.setErr(err)
			}
		}()
		writeJSON(w, 200, map[string]any{"ok": true})
	})

	srv := &http.Server{
		Addr:              cfg.HTTPListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	l, err := net.Listen("tcp", cfg.HTTPListenAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("mpc_signer HTTP listening on %s (role=%d)", cfg.HTTPListenAddr, cfg.RoleIndex)
	log.Fatal(srv.Serve(l))
}

func postJSON(url string, payload any, timeout time.Duration) error {
	b, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", url, strings.NewReader(string(b)))
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")
	c := &http.Client{Timeout: timeout}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("peer status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

func waitPeerReady(peerBase string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		st, err := fetchPeerStatus(peerBase, 2*time.Second)
		if err == nil {
			if v, ok := st["key_share_loaded"].(bool); ok && v {
				return nil
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for peer key_share_loaded")
}

func fetchPeerStatus(peerBase string, timeout time.Duration) (map[string]any, error) {
	c := &http.Client{Timeout: timeout}
	resp, err := c.Get(peerBase + "/internal/status")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("peer status code %d", resp.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

