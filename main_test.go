package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestExtractHostname(t *testing.T) {
	tests := []struct {
		name   string
		config string
		want   string
	}{
		{"normal", "set system host-name fr1\nset system root-authentication foo", "fr1"},
		{"mixed case value", "set system host-name FR1-Core", "FR1-Core"},
		{"missing", "set system root-authentication foo", ""},
		{"multiple spaces", "set  system  host-name  router1", "router1"},
		{"mid-config", "set version 1\nset system host-name sw2\nset interfaces ge-0/0/0", "sw2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractHostname(tt.config)
			if got != tt.want {
				t.Errorf("extractHostname() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSanitizeHostname(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"FR1", "fr1"},
		{"my-router.lab", "my-router.lab"},
		{"host name!@#", "host_name___"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := sanitizeHostname(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeHostname(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestBuildRedactTerms(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		terms := buildRedactTerms(nil, nil)
		if len(terms) != 4 {
			t.Fatalf("expected 4 default terms, got %d", len(terms))
		}
	})
	t.Run("add", func(t *testing.T) {
		terms := buildRedactTerms([]string{"community"}, nil)
		if len(terms) != 5 {
			t.Fatalf("expected 5 terms, got %d", len(terms))
		}
	})
	t.Run("remove", func(t *testing.T) {
		terms := buildRedactTerms(nil, []string{"local-name"})
		if len(terms) != 3 {
			t.Fatalf("expected 3 terms, got %d", len(terms))
		}
		for _, term := range terms {
			if term == "local-name" {
				t.Error("local-name should have been removed")
			}
		}
	})
}

func TestRedactConfig(t *testing.T) {
	config := `set system host-name fr1
set system root-authentication encrypted-password "$6$abc"
set groups TPL interfaces pp0 unit 0 ppp-options chap default-chap-secret "$9$xyz"
set groups TPL interfaces pp0 unit 0 ppp-options chap local-name "user@isp"
set groups TPL interfaces pp0 unit 0 ppp-options pap local-password "$9$abc"
set interfaces ge-0/0/0 unit 0 encapsulation ppp-over-ether
set security zones security-zone INTERNET`

	terms := buildRedactTerms(nil, nil)
	result := redactConfig(config, terms)

	if bytes.Contains([]byte(result), []byte("encrypted-password")) {
		t.Error("encrypted-password line should be redacted")
	}
	if bytes.Contains([]byte(result), []byte("chap-secret")) {
		t.Error("secret line should be redacted")
	}
	if bytes.Contains([]byte(result), []byte("local-name")) {
		t.Error("local-name line should be redacted")
	}
	if bytes.Contains([]byte(result), []byte("local-password")) {
		t.Error("local-password line should be redacted")
	}
	if !bytes.Contains([]byte(result), []byte("host-name fr1")) {
		t.Error("host-name line should be preserved")
	}
	if !bytes.Contains([]byte(result), []byte("ppp-over-ether")) {
		t.Error("interface line should be preserved")
	}
}

func TestRedactCaseInsensitive(t *testing.T) {
	config := "set system root-authentication ENCRYPTED-PASSWORD \"$6$abc\"\nset interfaces ge-0/0/0"
	result := redactConfig(config, []string{"encrypted-password"})
	if bytes.Contains([]byte(result), []byte("ENCRYPTED-PASSWORD")) {
		t.Error("case-insensitive match should redact")
	}
	if !bytes.Contains([]byte(result), []byte("ge-0/0/0")) {
		t.Error("non-matching line should be preserved")
	}
}

func TestTryDecompress(t *testing.T) {
	original := []byte("set system host-name test1")

	t.Run("plain text passthrough", func(t *testing.T) {
		out, err := tryDecompress(original)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out, original) {
			t.Error("plain text should pass through unchanged")
		}
	})

	t.Run("gzip decompression", func(t *testing.T) {
		var buf bytes.Buffer
		w := gzip.NewWriter(&buf)
		w.Write(original)
		w.Close()

		out, err := tryDecompress(buf.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out, original) {
			t.Errorf("got %q, want %q", out, original)
		}
	})
}

func TestHandleUpload(t *testing.T) {
	pusher := &githubPusher{
		queue: make(chan commitRequest, 10),
	}
	terms := buildRedactTerms(nil, nil)

	config := "set system host-name TestRouter\nset system root-authentication encrypted-password \"$6$x\"\nset interfaces ge-0/0/0"

	t.Run("PUT accepted", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/archive", bytes.NewReader([]byte(config)))
		w := httptest.NewRecorder()
		handleUpload(w, req, pusher, terms)

		if w.Code != http.StatusCreated {
			t.Errorf("status = %d, want %d", w.Code, http.StatusCreated)
		}

		cr := <-pusher.queue
		if cr.path != "config-testrouter.txt" {
			t.Errorf("path = %q, want %q", cr.path, "config-testrouter.txt")
		}
		if bytes.Contains(cr.content, []byte("encrypted-password")) {
			t.Error("committed content should be redacted")
		}
		if !bytes.Contains(cr.content, []byte("ge-0/0/0")) {
			t.Error("non-sensitive lines should be preserved")
		}
	})

	t.Run("GET rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/archive", nil)
		w := httptest.NewRecorder()
		handleUpload(w, req, pusher, terms)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
		}
	})

	t.Run("gzipped body", func(t *testing.T) {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		gz.Write([]byte(config))
		gz.Close()

		req := httptest.NewRequest(http.MethodPut, "/archive", &buf)
		w := httptest.NewRecorder()
		handleUpload(w, req, pusher, terms)

		if w.Code != http.StatusCreated {
			t.Errorf("status = %d, want %d", w.Code, http.StatusCreated)
		}
		cr := <-pusher.queue
		if cr.path != "config-testrouter.txt" {
			t.Errorf("path = %q, want %q", cr.path, "config-testrouter.txt")
		}
	})

	t.Run("unknown hostname", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/archive", bytes.NewReader([]byte("set interfaces ge-0/0/0")))
		w := httptest.NewRecorder()
		handleUpload(w, req, pusher, terms)

		if w.Code != http.StatusCreated {
			t.Errorf("status = %d, want %d", w.Code, http.StatusCreated)
		}
		cr := <-pusher.queue
		if cr.path != "config-unknown.txt" {
			t.Errorf("path = %q, want %q", cr.path, "config-unknown.txt")
		}
	})
}

func TestStateFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	sf, err := openStateFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer sf.close()

	// Initially empty
	items, err := sf.load()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("expected 0 items, got %d", len(items))
	}

	// Save some items
	commits := []commitRequest{
		{path: "config-r1.txt", content: []byte("set system host-name r1"), message: "[R1] 2026-04-04 00:00:00", time: time.Now().UTC()},
		{path: "config-r2.txt", content: []byte("set system host-name r2"), message: "[R2] 2026-04-04 00:01:00", time: time.Now().UTC()},
	}
	if err := sf.save(commits); err != nil {
		t.Fatal(err)
	}

	// Verify file is not empty
	info, _ := sf.file.Stat()
	if info.Size() == 0 {
		t.Fatal("state file should not be empty after save")
	}

	// Load back
	loaded, err := sf.load()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 2 {
		t.Fatalf("expected 2 items, got %d", len(loaded))
	}
	if loaded[0].path != "config-r1.txt" {
		t.Errorf("path = %q, want %q", loaded[0].path, "config-r1.txt")
	}
	if string(loaded[0].content) != "set system host-name r1" {
		t.Errorf("content mismatch")
	}
	if loaded[1].message != "[R2] 2026-04-04 00:01:00" {
		t.Errorf("message = %q", loaded[1].message)
	}

	// File should be truncated after load
	info, _ = sf.file.Stat()
	if info.Size() != 0 {
		t.Fatalf("state file should be empty after load, size=%d", info.Size())
	}
}

func TestStateFileDirPermissions(t *testing.T) {
	dir := t.TempDir()
	sf, err := openStateFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer sf.close()

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	perm := info.Mode().Perm()
	if perm&0007 != 0 {
		t.Errorf("state dir should have o-rwx, got %o", perm)
	}
}

func TestStateFileLock(t *testing.T) {
	dir := t.TempDir()
	sf1, err := openStateFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer sf1.close()

	// Second open should fail due to lock
	_, err = openStateFile(dir)
	if err == nil {
		t.Fatal("expected lock error on second open")
	}
}

func TestCheckRepoVisibility(t *testing.T) {
	t.Run("private repo allowed", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]bool{"private": true})
		}))
		defer srv.Close()
		p := &githubPusher{apiBase: srv.URL, token: "test"}
		if err := p.checkRepoVisibility(false); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("public repo rejected", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]bool{"private": false})
		}))
		defer srv.Close()
		p := &githubPusher{apiBase: srv.URL, token: "test"}
		if err := p.checkRepoVisibility(false); err == nil {
			t.Error("expected error for public repo")
		}
	})

	t.Run("public repo allowed with flag", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]bool{"private": false})
		}))
		defer srv.Close()
		p := &githubPusher{apiBase: srv.URL, token: "test"}
		if err := p.checkRepoVisibility(true); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestCommitAndRetry(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if r.Method == http.MethodGet {
			// getFileSHA — file not found
			w.WriteHeader(404)
			return
		}
		// PUT — create file
		body, _ := io.ReadAll(r.Body)
		var payload map[string]interface{}
		json.Unmarshal(body, &payload)
		if payload["message"] == nil {
			t.Error("missing commit message")
		}
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]string{"content": "{}"})
	}))
	defer srv.Close()

	p := &githubPusher{
		apiBase: srv.URL,
		token:   "test",
		branch:  "main",
	}

	cr := commitRequest{
		path:    "config-test.txt",
		content: []byte("set system host-name test"),
		message: "[TEST] 2026-04-04 00:00:00",
	}

	if err := p.commit(cr); err != nil {
		t.Errorf("commit failed: %v", err)
	}
	if callCount != 2 { // 1 GET + 1 PUT
		t.Errorf("expected 2 API calls, got %d", callCount)
	}
}

func TestCommit4xxError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(404)
			return
		}
		w.WriteHeader(403)
		w.Write([]byte(`{"message":"forbidden"}`))
	}))
	defer srv.Close()

	p := &githubPusher{apiBase: srv.URL, token: "bad", branch: "main"}
	err := p.commit(commitRequest{path: "test.txt", content: []byte("x"), message: "test"})
	if err == nil {
		t.Fatal("expected error")
	}
	ce, ok := err.(*commitError)
	if !ok {
		t.Fatal("expected *commitError")
	}
	if !ce.is4xx {
		t.Error("expected is4xx=true for 403")
	}
}
