// Replace placeholder with test implementations
package mpc

import (
	"crypto/sha256"
	"testing"

	"github.com/coinbase/cb-mpc/demos-go/cb-mpc-go/api/curve"
	"github.com/coinbase/cb-mpc/demos-go/cb-mpc-go/api/transport/mocknet"
	"github.com/coinbase/cb-mpc/demos-go/cb-mpc-go/internal/cgobinding"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createThresholdAccessStructure builds an in-memory AccessStructure tree
// representing a simple "threshold-of-n" policy and returns a high-level
// Go wrapper that can be passed to the MPC APIs.
func createThresholdAccessStructure(pnames []string, threshold int, cv curve.Curve) *AccessStructure {
	// Build leaf nodes for each party.
	kids := make([]*AccessNode, len(pnames))
	for i, n := range pnames {
		kids[i] = Leaf(n)
	}

	// Root is a THRESHOLD node with K=threshold.
	root := Threshold("", threshold, kids...)

	return &AccessStructure{Root: root, Curve: cv}
}

// TestECDSAMPCThresholdDKGWithMockNet exercises the high-level
// ECDSAMPCThresholdDKG wrapper across multiple parties using the in-memory mock
// network. It validates that each participant receives a non-nil key share and
// that basic invariants (party name, curve code) hold.
func TestECDSAMPCThresholdDKGWithMockNet(t *testing.T) {
	const (
		nParties  = 5
		threshold = 3
	)

	// Prepare curve instance.
	cv, err := curve.NewSecp256k1()
	require.NoError(t, err)
	defer cv.Free()

	// Prepare mock network primitives.
	pnames := mocknet.GeneratePartyNames(nParties)
	messengers := mocknet.NewMockNetwork(nParties)

	// Channel to gather per-party results.
	type result struct {
		idx  int
		resp *ECDSAMPCThresholdDKGResponse
		err  error
	}
	resCh := make(chan result, nParties)

	// Launch one goroutine per party.
	for i := 0; i < nParties; i++ {
		go func(idx int) {
			// Build JobMP wrapper for this party.
			job, err := NewJobMP(messengers[idx], nParties, idx, pnames)
			if err != nil {
				resCh <- result{idx: idx, resp: nil, err: err}
				return
			}
			defer job.Free()

			// Each party creates its own access-structure object.
			ac := createThresholdAccessStructure(pnames, threshold, cv)

			req := &ECDSAMPCThresholdDKGRequest{
				Curve:           cv,
				SessionID:       nil, // let native generate SID
				AccessStructure: ac,
			}

			r, e := ECDSAMPCThresholdDKG(job, req)
			resCh <- result{idx: idx, resp: r, err: e}
		}(i)
	}

	// Collect results.
	resp := make([]*ECDSAMPCThresholdDKGResponse, nParties)
	for i := 0; i < nParties; i++ {
		out := <-resCh
		require.NoError(t, out.err, "party %d threshold DKG should succeed", out.idx)
		require.NotNil(t, out.resp, "party %d response must not be nil", out.idx)
		resp[out.idx] = out.resp
	}

	// Basic validations.
	expectedCurveCode := curve.Code(cv)

	for i, r := range resp {
		// Key share must be non-zero.
		assert.NotEqual(t, 0, r.KeyShare, "party %d key share should not be zero", i)

		// Party name matches.
		pname, err := r.KeyShare.PartyName()
		require.NoError(t, err)
		assert.Equal(t, pnames[i], pname, "party %d pname mismatch", i)

		// Curve matches.
		c, err := r.KeyShare.Curve()
		require.NoError(t, err)
		actual := curve.Code(c)
		assert.Equal(t, expectedCurveCode, actual)
		c.Free()
	}

	// Convert a quorum of parties to additive shares under the same threshold policy
	root := Threshold("", threshold, func() []*AccessNode {
		kids := make([]*AccessNode, len(pnames))
		for i, n := range pnames {
			kids[i] = Leaf(n)
		}
		return kids
	}()...)
	asQ := &AccessStructure{Root: root, Curve: cv}
	quorumNames := pnames[:threshold]

	additive := make([]ECDSAMPCKey, threshold)
	for i := 0; i < threshold; i++ {
		as, err := resp[i].KeyShare.ToAdditiveShare(asQ, quorumNames)
		require.NoError(t, err, "party %d additive share conversion failed", i)
		additive[i] = as
	}

	// Run an ECDSA MPC signing with only the quorum parties, then verify the DER signature
	message := []byte("ecdsa threshold dkg signing")
	digest := sha256.Sum256(message)
	sigReceiver := 0

	signMessengers := mocknet.NewMockNetwork(threshold)
	type signResult struct {
		idx int
		sig []byte
		err error
	}
	signCh := make(chan signResult, threshold)

	for i := 0; i < threshold; i++ {
		go func(idx int) {
			job, err := NewJobMP(signMessengers[idx], threshold, idx, quorumNames)
			if err != nil {
				signCh <- signResult{idx: idx, err: err}
				return
			}
			defer job.Free()

			req := &ECDSAMPCSignRequest{KeyShare: additive[idx], Message: digest[:], SignatureReceiver: sigReceiver}
			r, e := ECDSAMPCSign(job, req)
			if e != nil {
				signCh <- signResult{idx: idx, err: e}
				return
			}
			signCh <- signResult{idx: idx, sig: r.Signature, err: nil}
		}(i)
	}

	sigs := make([][]byte, threshold)
	for i := 0; i < threshold; i++ {
		out := <-signCh
		require.NoError(t, out.err, "party %d signing should succeed", out.idx)
		sigs[out.idx] = out.sig
	}

	// Only the receiver should have the signature
	require.NotEmpty(t, sigs[sigReceiver])
	for i := 0; i < threshold; i++ {
		if i != sigReceiver {
			assert.Empty(t, sigs[i])
		}
	}

	// Verify signature against Q
	Q, err := resp[0].KeyShare.Q()
	require.NoError(t, err)
	// Build SEC1 uncompressed pubkey
	pad32 := func(b []byte) []byte {
		p := make([]byte, 32)
		if len(b) >= 32 {
			copy(p, b[len(b)-32:])
			return p
		}
		copy(p[32-len(b):], b)
		return p
	}
	x := pad32(Q.GetX())
	y := pad32(Q.GetY())
	pubOct := make([]byte, 1+32+32)
	pubOct[0] = 0x04
	copy(pubOct[1:33], x)
	copy(pubOct[33:], y)
	Q.Free()
	require.NoError(t, cgobinding.ECCVerifyDER(curve.Code(cv), pubOct, digest[:], sigs[sigReceiver]))
}

// TestECDSAMPC_ToAdditiveShare verifies that a subset of parties satisfying the
// quorum threshold can convert their threshold-DKG key share into an additive
// secret share without error.
func TestECDSAMPC_ToAdditiveShare(t *testing.T) {
	const (
		nParties  = 4
		threshold = 2
	)

	cv, err := curve.NewSecp256k1()
	require.NoError(t, err)
	defer cv.Free()

	pnames := mocknet.GeneratePartyNames(nParties)
	messengers := mocknet.NewMockNetwork(nParties)

	// First run threshold DKG to obtain key shares.
	type dkgResult struct {
		idx   int
		share ECDSAMPCKey
		err   error
	}
	dkgCh := make(chan dkgResult, nParties)

	for i := 0; i < nParties; i++ {
		go func(idx int) {
			job, err := NewJobMP(messengers[idx], nParties, idx, pnames)
			if err != nil {
				dkgCh <- dkgResult{idx: idx, err: err}
				return
			}
			defer job.Free()

			ac := createThresholdAccessStructure(pnames, threshold, cv)

			req := &ECDSAMPCThresholdDKGRequest{Curve: cv, AccessStructure: ac}
			resp, err := ECDSAMPCThresholdDKG(job, req)
			if err != nil {
				dkgCh <- dkgResult{idx: idx, err: err}
				return
			}
			dkgCh <- dkgResult{idx: idx, share: resp.KeyShare, err: nil}
		}(i)
	}

	shares := make([]ECDSAMPCKey, nParties)
	for i := 0; i < nParties; i++ {
		out := <-dkgCh
		require.NoError(t, out.err)
		shares[out.idx] = out.share
	}

	// Prepare quorum party names – pick the first `threshold` parties.
	quorumPNames := pnames[:threshold]

	// Build an AccessStructure representing the same threshold policy.
	root := Threshold("", threshold, func() []*AccessNode {
		kids := make([]*AccessNode, len(pnames))
		for i, n := range pnames {
			kids[i] = Leaf(n)
		}
		return kids
	}()...)

	asQ := &AccessStructure{Root: root, Curve: cv}

	// Convert shares for the quorum parties and ensure success.
	for i := 0; i < threshold; i++ {
		additive, err := shares[i].ToAdditiveShare(asQ, quorumPNames)
		require.NoError(t, err, "party %d additive share conversion failed", i)
		assert.NotEqual(t, 0, additive, "party %d additive share should not be zero", i)
		// Clean up native resources to avoid leaks.
		ref := additive.cgobindingRef()
		(&ref).Free()
	}

	// Non-quorum parties can also convert to additive shares; ensure no error
	for i := threshold; i < nParties; i++ {
		additive, err := shares[i].ToAdditiveShare(asQ, quorumPNames)
		require.NoError(t, err, "non-quorum party %d additive conversion failed", i)
		assert.NotEqual(t, 0, additive, "non-quorum party %d additive share should not be zero", i)
		ref := additive.cgobindingRef()
		(&ref).Free()
	}
}

// TestECDSAMPCThresholdDKG_SigningFailsWithTooFewParties ensures that attempting
// to sign with fewer than 3 parties (and fewer than the 3-of-5 threshold) fails.
func TestECDSAMPCThresholdDKG_SigningFailsWithTooFewParties(t *testing.T) {
	const (
		nParties  = 5
		threshold = 3
	)

	cv, err := curve.NewSecp256k1()
	require.NoError(t, err)
	defer cv.Free()

	pnames := mocknet.GeneratePartyNames(nParties)
	messengers := mocknet.NewMockNetwork(nParties)

	// Run threshold DKG across all parties
	type dkgRes struct {
		idx  int
		resp *ECDSAMPCThresholdDKGResponse
		err  error
	}
	dkgCh := make(chan dkgRes, nParties)
	for i := 0; i < nParties; i++ {
		go func(idx int) {
			job, err := NewJobMP(messengers[idx], nParties, idx, pnames)
			if err != nil {
				dkgCh <- dkgRes{idx: idx, err: err}
				return
			}
			defer job.Free()
			ac := createThresholdAccessStructure(pnames, threshold, cv)
			r, e := ECDSAMPCThresholdDKG(job, &ECDSAMPCThresholdDKGRequest{Curve: cv, AccessStructure: ac})
			dkgCh <- dkgRes{idx: idx, resp: r, err: e}
		}(i)
	}
	resp := make([]*ECDSAMPCThresholdDKGResponse, nParties)
	for i := 0; i < nParties; i++ {
		out := <-dkgCh
		require.NoError(t, out.err)
		resp[out.idx] = out.resp
	}

	// Convert to additive shares for a valid 3-of-5 quorum
	root := Threshold("", threshold, func() []*AccessNode {
		kids := make([]*AccessNode, len(pnames))
		for i, n := range pnames {
			kids[i] = Leaf(n)
		}
		return kids
	}()...)
	asQ := &AccessStructure{Root: root, Curve: cv}
	quorumNames := pnames[:threshold]
	additive := make([]ECDSAMPCKey, threshold)
	for i := 0; i < threshold; i++ {
		as, err := resp[i].KeyShare.ToAdditiveShare(asQ, quorumNames)
		require.NoError(t, err)
		additive[i] = as
	}

	// Attempt to sign with only two parties -> should fail
	signMessengers := mocknet.NewMockNetwork(2)
	signPNames := quorumNames[:2]
	type signResult struct {
		idx int
		err error
	}
	signCh := make(chan signResult, 2)
	digest := sha256.Sum256([]byte("ecdsa threshold negative test"))
	sigReceiver := 0
	for i := 0; i < 2; i++ {
		go func(idx int) {
			job, err := NewJobMP(signMessengers[idx], 2, idx, signPNames)
			if err != nil {
				signCh <- signResult{idx: idx, err: err}
				return
			}
			defer job.Free()
			_, e := ECDSAMPCSign(job, &ECDSAMPCSignRequest{KeyShare: additive[idx], Message: digest[:], SignatureReceiver: sigReceiver})
			signCh <- signResult{idx: idx, err: e}
		}(i)
	}
	for i := 0; i < 2; i++ {
		out := <-signCh
		require.Error(t, out.err, "party %d signing should fail with too few parties", out.idx)
	}
}
