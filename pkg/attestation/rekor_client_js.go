// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"net/http"
	"time"
)

// rekorQueryTimeout bounds one transparency log query.
const rekorQueryTimeout = 30 * time.Second

// DefaultRekorHTTPClient returns the HTTP client the transparency log
// is queried with on this platform when the caller names none.
// The signer's own client dials its connections, which js/wasm cannot
// do: a client on the default transport goes through the Fetch API
// instead.
func DefaultRekorHTTPClient() *http.Client {
	return &http.Client{Timeout: rekorQueryTimeout}
}
