// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !js

package cmd

import "net/http"

// rekorHTTPClient returns the HTTP client the transparency log is
// queried with. Nil leaves it to the signer's default, which retries
// failed requests.
func rekorHTTPClient() *http.Client {
	return nil
}
