// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !js

package attestation

import "net/http"

// DefaultRekorHTTPClient returns the HTTP client the transparency log
// is queried with on this platform when the caller names none.
// Everywhere but js it is nil: the query is left to the signer's own
// client, which dials its connections and retries failed requests.
func DefaultRekorHTTPClient() *http.Client {
	return nil
}
