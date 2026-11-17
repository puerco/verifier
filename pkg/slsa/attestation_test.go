// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package slsa_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	vattestation "github.com/slsa-framework/verifier/pkg/attestation"
	"github.com/slsa-framework/verifier/pkg/slsa"
	"github.com/slsa-framework/verifier/pkg/slsa/controls"
)

const (
	cmdTestdata    = "../../internal/cmd/testdata"
	keylessFixture = cmdTestdata + "/keyless/generator.intoto.jsonl"
	goBuilderID    = "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml"
)

func readFixture(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}

// countingTransport counts the requests it forwards to
// http.DefaultTransport.
type countingTransport struct {
	requests atomic.Int32
}

func (c *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.requests.Add(1)
	return http.DefaultTransport.RoundTrip(req)
}

// frozenRekor serves the keyless fixture's real log entry, frozen from
// rekor.sigstore.dev, so the envelope verifies offline.
func frozenRekor(t *testing.T) *httptest.Server {
	t.Helper()
	frozen := readFixture(t, cmdTestdata+"/keyless/rekor-response.json")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body) //nolint:errcheck // best-effort drain
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write(frozen)
		assert.NoError(t, err)
	}))
	t.Cleanup(ts.Close)
	return ts
}

// keylessOptions are the expectations the keyless fixture's content
// meets.
func keylessOptions(extra ...slsa.VerificationOption) []slsa.VerificationOption {
	return append([]slsa.VerificationOption{
		slsa.WithTrack(controls.TrackBuild),
		slsa.WithSkipBuildTypeChecks(true),
		slsa.WithParam("expected_source", "github.com/slsa-framework/example-package"),
		slsa.WithParam("trusted_builders", []string{goBuilderID}),
	}, extra...)
}

func controlResult(t *testing.T, res *slsa.Result, id string) *slsa.ControlResult {
	t.Helper()
	for _, cr := range res.CoreResults {
		if cr.ID == id {
			return cr
		}
	}
	require.Failf(t, "control not in the result", "%s", id)
	return nil
}

// One call verifies a signed bundle held as bytes, and returns what the
// steps it stands for return when run by hand.
func TestVerifyAttestationBundle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	data := readFixture(t, filepath.Join("testdata", "bundle", "source-provenance.sigstore.json"))
	opts := []slsa.VerificationOption{
		slsa.WithTrack(controls.TrackSource),
		slsa.WithBuildTypeControls(false),
		slsa.WithRequireSignatures(true),
		slsa.WithMinLevel(1),
	}

	v, err := slsa.New()
	require.NoError(t, err)
	res, err := v.VerifyAttestation(ctx, data, opts...)
	require.NoError(t, err)
	assert.True(t, res.Pass(), res.Message)
	assert.Equal(t, 3, res.SLSALevel)
	assert.Empty(t, res.Message, "a verified signature leaves no content-only notice")

	envs, err := vattestation.New().Parse(data)
	require.NoError(t, err)
	require.Len(t, envs, 1)
	require.NoError(t, envs[0].Verify())
	byHand, err := v.Verify(ctx, envs[0].GetStatement(), opts...)
	require.NoError(t, err)
	assert.Equal(t, byHand, res)
}

// An unsigned statement is evaluated on its content, and the result
// says so; requiring signatures refuses it.
func TestVerifyAttestationUnsigned(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	data := readFixture(t, filepath.Join("testdata", "plain", "source.intoto.json"))
	v, err := slsa.New()
	require.NoError(t, err)

	res, err := v.VerifyAttestation(ctx, data)
	require.NoError(t, err)
	assert.True(t, res.Pass())
	assert.Contains(t, res.Message, "unsigned: evaluated on content alone")

	_, err = v.VerifyAttestation(ctx, data, slsa.WithRequireSignatures(true))
	require.ErrorIs(t, err, slsa.ErrSignatureRequired)
}

// A keyless DSSE envelope is verified against the transparency log,
// queried at the URL and over the client the options name: the signer
// the log vouches for reaches the builder binding, which refuses this
// builder for signing from a branch.
func TestVerifyAttestationKeyless(t *testing.T) {
	t.Parallel()
	ts := frozenRekor(t)
	transport := &countingTransport{}
	v, err := slsa.New()
	require.NoError(t, err)

	res, err := v.VerifyAttestation(context.Background(), readFixture(t, keylessFixture), keylessOptions(
		slsa.WithRequireSignatures(true),
		slsa.WithRekorURL(ts.URL),
		slsa.WithRekorHTTPClient(&http.Client{Transport: transport}),
	)...)
	require.NoError(t, err)
	assert.Equal(t, int32(1), transport.requests.Load())
	assert.Equal(t, slsa.StatusFail, res.Status)
	binding := controlResult(t, res, slsa.BuilderBindingControlID)
	assert.Equal(t, slsa.StatusFail, binding.Status)
	assert.Contains(t, binding.Message, "not a release tag")
	assert.Equal(t, slsa.StatusPass, controlResult(t, res, "source-repo-match").Status)
}

// With the transparency log turned off no request is made and the
// envelope stays unverifiable: content-only by default, refused when
// signatures are required.
func TestVerifyAttestationKeylessOffline(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	data := readFixture(t, keylessFixture)
	transport := &countingTransport{}
	offline := []slsa.VerificationOption{
		slsa.WithTransparencyLog(false),
		slsa.WithRekorHTTPClient(&http.Client{Transport: transport}),
	}
	v, err := slsa.New()
	require.NoError(t, err)

	res, err := v.VerifyAttestation(ctx, data, keylessOptions(offline...)...)
	require.NoError(t, err)
	assert.Contains(t, res.Message, "signature not verified")
	assert.Equal(t, slsa.StatusSkipped, controlResult(t, res, slsa.BuilderBindingControlID).Status)

	_, err = v.VerifyAttestation(ctx, data, keylessOptions(append(offline, slsa.WithRequireSignatures(true))...)...)
	require.ErrorIs(t, err, slsa.ErrSignatureRequired)
	assert.Zero(t, transport.requests.Load())
}

// tamperPayload returns the DSSE envelope with one edit to the statement
// it carries, leaving the signature made over the original.
func tamperPayload(t *testing.T, envelope []byte, from, to string) []byte {
	t.Helper()
	var env map[string]any
	require.NoError(t, json.Unmarshal(envelope, &env))
	encoded, ok := env["payload"].(string)
	require.True(t, ok, "the envelope has a payload")
	payload, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err)
	edited := strings.Replace(string(payload), from, to, 1)
	require.NotEqual(t, string(payload), edited)
	env["payload"] = base64.StdEncoding.EncodeToString([]byte(edited))
	out, err := json.Marshal(env)
	require.NoError(t, err)
	return out
}

// A signature that is checked and refuted fails the verification
// whether or not signatures are required: here the statement was
// edited after it was signed. The check runs with the transparency log
// lookup on, as without it a keyless envelope is not checked at all.
func TestVerifyAttestationRefutedSignature(t *testing.T) {
	t.Parallel()
	ts := frozenRekor(t)
	tampered := tamperPayload(t, readFixture(t, keylessFixture), "example-package", "another-package")
	v, err := slsa.New()
	require.NoError(t, err)

	_, err = v.VerifyAttestation(context.Background(), tampered,
		keylessOptions(slsa.WithRekorURL(ts.URL))...)
	require.ErrorIs(t, err, slsa.ErrSignatureUnverified)
}

// Among several attestations the one of the track being verified is
// picked: a commit's note holds its source provenance next to a VSA.
func TestVerifyAttestationSelects(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	data := readFixture(t, cmdTestdata+"/source-note.jsonl")
	v, err := slsa.New()
	require.NoError(t, err)

	for name, opts := range map[string][]slsa.VerificationOption{
		"the source track": {slsa.WithTrack(controls.TrackSource), slsa.WithBuildTypeControls(false)},
		"no track":         nil,
	} {
		t.Run(name+" takes the source provenance", func(t *testing.T) {
			t.Parallel()
			res, err := v.VerifyAttestation(ctx, data, opts...)
			require.NoError(t, err)
			assert.Equal(t, "1.2", res.SpecVersion)
			assert.NotEmpty(t, res.CoreResults)
		})
	}
	t.Run("the build track finds no build provenance", func(t *testing.T) {
		t.Parallel()
		_, err := v.VerifyAttestation(ctx, data, slsa.WithTrack(controls.TrackBuild))
		require.ErrorIs(t, err, vattestation.ErrNoApplicableAttestation)
	})
}

// VerifyEnvelopes starts from parsed envelopes, as a caller reading
// them from a path has them.
func TestVerifyEnvelopes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	v, err := slsa.New()
	require.NoError(t, err)

	envs, err := vattestation.New().Fetch(ctx, filepath.Join("testdata", "plain", "source.intoto.json"))
	require.NoError(t, err)
	res, err := v.VerifyEnvelopes(ctx, envs)
	require.NoError(t, err)
	assert.True(t, res.Pass())

	_, err = v.VerifyEnvelopes(ctx, nil)
	require.ErrorIs(t, err, vattestation.ErrNoApplicableAttestation)
}

func TestVerifyAttestationNoData(t *testing.T) {
	t.Parallel()
	v, err := slsa.New()
	require.NoError(t, err)
	_, err = v.VerifyAttestation(context.Background(), nil)
	require.Error(t, err)
}
