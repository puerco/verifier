// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testdataDir = "../../internal/cmd/testdata"

func TestFetch(t *testing.T) {
	t.Parallel()
	v := New()
	ctx := context.Background()

	t.Run("a JSON lines file yields every attestation", func(t *testing.T) {
		t.Parallel()
		envs, err := v.Fetch(ctx, testdataDir+"/source-note.jsonl")
		require.NoError(t, err)
		assert.Len(t, envs, 2)
	})
	t.Run("a directory yields the attestations of every file", func(t *testing.T) {
		t.Parallel()
		envs, err := v.Fetch(ctx, testdataDir)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(envs), 3, "the note's two plus the DSSE VSAs")
	})
	t.Run("a single-attestation file", func(t *testing.T) {
		t.Parallel()
		envs, err := v.Fetch(ctx, testdataDir+"/forged-vsa.dsse.json")
		require.NoError(t, err)
		assert.Len(t, envs, 1)
	})
	t.Run("a missing path", func(t *testing.T) {
		t.Parallel()
		_, err := v.Fetch(ctx, testdataDir+"/missing.json")
		require.Error(t, err)
	})
	t.Run("Load wants exactly one", func(t *testing.T) {
		t.Parallel()
		_, err := v.Load(testdataDir + "/source-note.jsonl")
		require.ErrorContains(t, err, "expected one attestation, got 2")
		env, err := v.Load(testdataDir + "/forged-vsa.dsse.json")
		require.NoError(t, err)
		assert.NotNil(t, env)
	})
}

// Parse reads from bytes what Fetch reads from a path.
func TestParse(t *testing.T) {
	t.Parallel()
	v := New()

	for _, tc := range []struct {
		name string
		path string
		want int
	}{
		{"JSON lines yield every attestation", testdataDir + "/source-note.jsonl", 2},
		{"a single-line JSON lines file", testdataDir + "/keyless/generator.intoto.jsonl", 1},
		{"a DSSE envelope", testdataDir + "/forged-vsa.dsse.json", 1},
		{"a sigstore bundle", "../slsa/testdata/bundle/source-provenance.sigstore.json", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			data, err := os.ReadFile(tc.path)
			require.NoError(t, err)
			envs, err := v.Parse(data)
			require.NoError(t, err)
			require.Len(t, envs, tc.want)

			fetched, err := v.Fetch(context.Background(), tc.path)
			require.NoError(t, err)
			require.Len(t, fetched, tc.want)
			for i := range envs {
				assert.Equal(t,
					fetched[i].GetStatement().GetPredicateType(),
					envs[i].GetStatement().GetPredicateType(),
				)
				assert.NotNil(t, envs[i].GetStatement().GetPredicate().GetParsed(), "the predicate is parsed")
				assert.Len(t, envs[i].GetSignatures(), len(fetched[i].GetSignatures()))
			}
		})
	}

	t.Run("a bare statement", func(t *testing.T) {
		t.Parallel()
		envs, err := v.Parse([]byte(`{
			"_type": "https://in-toto.io/Statement/v1",
			"subject": [{"name": "app", "digest": {"sha256": "abc"}}],
			"predicateType": "https://slsa.dev/verification_summary/v1",
			"predicate": {"verifier": {"id": "https://example.com/verifier"}}
		}`))
		require.NoError(t, err)
		require.Len(t, envs, 1)
		assert.Empty(t, envs[0].GetSignatures())
	})

	for name, data := range map[string][]byte{
		"no data":               nil,
		"blank data":            []byte("\n\n"),
		"data that is not JSON": []byte("not an attestation\n"),
	} {
		t.Run(name+" holds no attestation", func(t *testing.T) {
			t.Parallel()
			_, err := v.Parse(data)
			require.Error(t, err)
		})
	}
}
