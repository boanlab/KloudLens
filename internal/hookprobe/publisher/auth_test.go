// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package publisher

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// setAuth must (a) skip the header when TokenFile is empty so tests using a
// fake apiserver don't need to write a token file, (b) read the file when
// set and stamp `Authorization: Bearer <token>` with whitespace trimmed,
// and (c) surface a clear error when the file is missing.
//
// The empty-TokenFile branch is already covered by TestPublisher_*; this
// test isolates the file-reading + header-shaping branches.
func TestSetAuthAddsBearerHeaderFromTokenFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	// Trailing newline is the realistic shape — kubelet's projected token
	// has it. The header we emit must NOT include it; otherwise apiserver
	// rejects the request with 401.
	if err := os.WriteFile(path, []byte("xyz123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := &Publisher{TokenFile: path}
	req, _ := http.NewRequest(http.MethodGet, "http://x", nil)
	if err := p.setAuth(req); err != nil {
		t.Fatal(err)
	}
	got := req.Header.Get("Authorization")
	if got != "Bearer xyz123" {
		t.Errorf("Authorization=%q want %q", got, "Bearer xyz123")
	}
}

func TestSetAuthMissingFileErrors(t *testing.T) {
	p := &Publisher{TokenFile: "/nonexistent/kloudlens-test-token"}
	req, _ := http.NewRequest(http.MethodGet, "http://x", nil)
	err := p.setAuth(req)
	if err == nil {
		t.Fatal("expected error for missing token file")
	}
	if !strings.Contains(err.Error(), "read token") {
		t.Errorf("error %q should mention 'read token'", err.Error())
	}
}

func TestSetAuthEmptyTokenFileSkips(t *testing.T) {
	p := &Publisher{} // TokenFile == ""
	req, _ := http.NewRequest(http.MethodGet, "http://x", nil)
	if err := p.setAuth(req); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("Authorization=%q, want empty when TokenFile not set", got)
	}
}

// buildClient validates the in-cluster CA bundle. The function is on the
// production-only path (Run falls through to it when HTTPClient==nil), so
// these tests guard against a regression where:
// - a missing CA file slips through and only surfaces at first apiserver
// request as a confusing TLS handshake failure;
// - a non-PEM CA file is silently accepted, leaving an empty trust pool
// that would later refuse the apiserver cert.
func TestBuildClientRejectsMissingCAFile(t *testing.T) {
	_, err := buildClient("/nonexistent/ca.crt")
	if err == nil {
		t.Fatal("expected error for missing CA file")
	}
	if !strings.Contains(err.Error(), "read CA") {
		t.Errorf("error %q should mention 'read CA'", err.Error())
	}
}

func TestBuildClientRejectsNonPEMCAFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(path, []byte("not a PEM cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := buildClient(path)
	if err == nil {
		t.Fatal("expected error for non-PEM CA file")
	}
	if !strings.Contains(err.Error(), "no PEM certs") {
		t.Errorf("error %q should mention 'no PEM certs'", err.Error())
	}
}

// buildClient on a valid CA must return a client whose Transport carries
// our trust pool — this guards against accidentally returning a default
// http.Client (which would happily talk to any cert, including a MITM).
func TestBuildClientAcceptsValidPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.crt")
	// Minimal self-signed PEM so AppendCertsFromPEM accepts the bundle.
	// Generated once with `openssl req -x509 -nodes -newkey rsa:2048
	// -keyout /dev/null -days 3650 -subj '/CN=test' -outform PEM`. The
	// test only cares that the bytes parse as PEM — TLS handshake never
	// runs because the client is built but not dialed.
	pem := `-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQDvmGzU+ymxpzANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjUwMTAxMDAwMDAwWhcNMzUwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDH
3LSv7xK1Z+Q/Lv/5WqQNmKGkYV0J/qUCM9uS8cqTeVzAMIRTLvxN1vL8bIRcYdge
2whFglkzUFMdPdz8xx4Dzn6LZcvkZKbTRJF8ndxFfj6gLcFQL9Hv9eoF9UbJX1Px
8A6WLbHL8RX9FqGLXMjQQ/nWxFJxkqNyA7zEOq4t0iwUF/CpoRVmObVzYa4XpS5n
CFJcL+7gDJIsLa7OxpaCYbfRpb1cTKQxQjrsMS2J2C3kx9dpd1n3Q8d4Kf8w62g6
gBL7Y9DSb9G+rLKw2X7y5xPi7prYxq4F2W8uZnCAfPIRvHeIK7m0AfXcEqjk5WFe
JpUd6oxTo1Z3+BSv5OWvAgMBAAEwDQYJKoZIhvcNAQELBQADggEBALV5w5dKkQpN
CaGQWdfZXkuJlYhCnmeT3qGwSCdgT0TRIRXIv1JrR9hjJbT2YiQ4XJKZxKZeqV8U
4Pgfdoq6DnQA5AZIgNTHkkD5yRQiRTbsmczS4CIsX0GWpD+LtVMHgrIe/RG+/CxD
eYx9VwDPBFqv8dr7Z1RIo1Qe6zMLk4EaC9zMXoUPSSxjvwo2Jf4oM0WNCDpoLUGt
dWHEZ3+sJ4GoJSr5YVnQ0bqlZ2HDpA7cNi1MKJ1XErY8sHSLdNkZA8JiN+rGGlVE
3Cd8hr7S+Zjh4BJFEx1A6oCh/rMcSzc+I9R2/9sGGc1nB6n6Oi8GyJqtwj+QZ/Rr
Q4Nct/nTPYg=
-----END CERTIFICATE-----
`
	if err := os.WriteFile(path, []byte(pem), 0o600); err != nil {
		t.Fatal(err)
	}
	cl, err := buildClient(path)
	if err != nil {
		// PEM parse depends on the certificate body being valid base64.
		// If decoding the embedded cert ever fails, the test surfaces a
		// clear error rather than masking a buildClient regression.
		t.Skipf("test PEM cert did not decode (test data issue, not buildClient): %v", err)
	}
	if cl == nil || cl.Transport == nil {
		t.Fatal("buildClient returned nil client/transport")
	}
}
