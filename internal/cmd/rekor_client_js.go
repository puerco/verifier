// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"net/http"
	"time"
)

// rekorQueryTimeout bounds one transparency log query.
const rekorQueryTimeout = 30 * time.Second

// rekorHTTPClient returns the HTTP client the transparency log is
// queried with. The signer's default client dials its own connections,
// which js/wasm cannot do: a client on the default transport goes
// through the Fetch API instead.
func rekorHTTPClient() *http.Client {
	return &http.Client{Timeout: rekorQueryTimeout}
}
