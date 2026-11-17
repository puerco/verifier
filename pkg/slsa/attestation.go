// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package slsa

import (
	"context"
	"errors"
	"fmt"
	"slices"

	signeroptions "github.com/policylabs/signer/options"

	"github.com/slsa-framework/verifier/pkg/attestation"
	"github.com/slsa-framework/verifier/pkg/slsa/controls"
	"github.com/slsa-framework/verifier/pkg/slsa/eval"
)

// Predicate types of the attestations the verifier evaluates, used to
// pick the one a verification is about out of several.
var (
	buildProvenanceTypes = []string{
		eval.PredicateProvenanceV1, eval.PredicateProvenanceV02, eval.PredicateProvenanceV01,
	}
	sourceProvenanceTypes = []string{eval.PredicateSourceProvenanceV1, eval.PredicateSourceProvenance}
	tagProvenanceTypes    = []string{eval.PredicateTagProvenanceV1, eval.PredicateTagProvenance}
)

// VerifyAttestation verifies the attestation held in data from start to
// finish: it parses the data, picks the attestation the verification
// is about, verifies its signatures and evaluates it. It is the one
// call a program needs to verify an attestation it holds as bytes, and
// it touches no file: the only network request it can make is the
// transparency log lookup of a keyless DSSE envelope (see
// WithTransparencyLog).
//
// The data is a Sigstore bundle, a DSSE envelope, a bare in-toto
// statement or JSON lines of them, as attestation.Parse reads it. See
// VerifyEnvelopes for how the attestation is picked and verified.
func (v *Verifier) VerifyAttestation(ctx context.Context, data []byte, opts ...VerificationOption) (*Result, error) {
	envs, err := attestation.New().Parse(data)
	if err != nil {
		return nil, err
	}
	return v.VerifyEnvelopes(ctx, envs, opts...)
}

// VerifyEnvelopes verifies an attestation among already parsed
// envelopes, as attestation.Parse or Fetch return them. It runs, in
// order, the steps a verification must not skip:
//
//  1. Pick the envelope the verification is about. One envelope is
//     taken as is. Among several, the one whose predicate is of the
//     track being verified (WithTrack; build and source provenance
//     both, when none is set) and which is about the expected subjects
//     (WithSubjects). On the source track, tag provenance wins over
//     source provenance when an expected_tag parameter is set, and
//     loses otherwise. No candidate, or more than one, is an error
//     (attestation.ErrNoApplicableAttestation,
//     attestation.ErrAmbiguousAttestation).
//  2. Verify the envelope's signatures: DSSE signatures with the keys
//     given (WithKeys), Sigstore bundles against the embedded trust
//     roots, and keyless DSSE envelopes against the transparency log.
//  3. Evaluate the statement as Verify does, which reads the outcome
//     of step 2: a refuted signature fails with ErrSignatureUnverified
//     and, under WithRequireSignatures, so does anything short of a
//     verified one, with ErrSignatureRequired.
//
// Without WithRequireSignatures an unsigned or unverifiable attestation
// is evaluated on its content alone and the Result's Message says so.
func (v *Verifier) VerifyEnvelopes(ctx context.Context, envs []attestation.Envelope, opts ...VerificationOption) (*Result, error) {
	vopts, err := v.verificationOptions(opts)
	if err != nil {
		return nil, err
	}

	env, err := attestation.Select(envs, selection(vopts))
	if err != nil {
		return nil, err
	}

	if err := env.Verify(signatureArgs(vopts)...); err != nil {
		return nil, fmt.Errorf("verifying envelope signatures: %w", err)
	}

	statement := env.GetStatement()
	if statement == nil {
		return nil, errors.New("envelope produced no statement")
	}
	return v.verify(ctx, statement, vopts)
}

// selection describes the attestation a verification with these
// options is about.
func selection(vopts *VerificationOptions) *attestation.Selection {
	sel := &attestation.Selection{
		Subjects:           vopts.Subjects,
		NoGitDigestAliases: vopts.NoGitDigestAliases,
	}
	switch vopts.ForceTrack {
	case controls.TrackBuild:
		sel.Kind = "build provenance"
		sel.PredicateTypes = buildProvenanceTypes
	case controls.TrackSource:
		sel.Kind = "source attestation"
		// A revision carries source provenance and, when it was tagged,
		// tag provenance: verify the one the caller's expectation is
		// about.
		if tag, ok := vopts.Params["expected_tag"].(string); ok && tag != "" {
			sel.Prefer = slices.Concat(tagProvenanceTypes, sourceProvenanceTypes)
		} else {
			sel.Prefer = slices.Concat(sourceProvenanceTypes, tagProvenanceTypes)
		}
		sel.PredicateTypes = sel.Prefer
	default:
		sel.Kind = "SLSA provenance"
		sel.PredicateTypes = slices.Concat(buildProvenanceTypes, sourceProvenanceTypes, tagProvenanceTypes)
	}
	return sel
}

// signatureArgs returns the arguments of the envelope's Verify: the
// keys and, unless it is turned off, the transparency log lookup.
func signatureArgs(vopts *VerificationOptions) []any {
	if vopts.NoTransparencyLog {
		return []any{vopts.Keys}
	}
	client := vopts.RekorHTTPClient
	if client == nil {
		client = attestation.DefaultRekorHTTPClient()
	}
	return []any{
		vopts.Keys,
		signeroptions.WithRekorVerification(true),
		signeroptions.WithRekorURL(vopts.RekorURL),
		signeroptions.WithRekorHTTPClient(client),
	}
}
