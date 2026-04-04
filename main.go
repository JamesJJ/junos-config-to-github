package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/charmbracelet/ssh"
	"github.com/charmbracelet/wish"
	"github.com/charmbracelet/wish/scp"
)

var version = "dev"
var debug bool

var hostnameRe = regexp.MustCompile(`(?m)(?:^set\s+system\s+host-name\s+(\S+)|^\s*host-name\s+(\S+?)\s*;)`)
var sanitizeRe = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ", ") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	showVersion := flag.Bool("version", false, "Print version and exit")
	httpPort := flag.Int("http-port", 0, "HTTP port to listen on (enables HTTP listener)")
	scpPort := flag.Int("scp-port", 0, "SCP/SSH port to listen on (enables SCP listener)")
	scpPasswordFile := flag.String("scp-password-file", "", "Path to file containing SCP password (required when --scp-port is set)")
	scpUsername := flag.String("scp-username", "archive", "Required SCP username")
	scpHostKeyPath := flag.String("scp-host-key", ".junos/id_ed25519", "Path to SSH host key for SCP server")
	repoURL := flag.String("repo-url", "", "GitHub repo URL (required, e.g. https://github.com/user/repo)")
	patTokenFile := flag.String("pat-token-file", "", "Path to file containing GitHub PAT token (required)")
	branch := flag.String("branch", "main", "Git branch")
	retryInterval := flag.Duration("retry-interval", 900*time.Second, "Retry interval for failed pushes (connection errors)")
	allowPublic := flag.Bool("allow-public-repo", false, "Allow pushing to public repositories")
	stateDir := flag.String("state-dir", "", "Directory to store state file for pending pushes across restarts")
	debugFlag := flag.Bool("debug", false, "Enable debug logging")
	logTime := flag.Bool("log-time", false, "Include date-time prefix in log messages")
	var addTerms, removeTerms stringList
	flag.Var(&addTerms, "add-redact-term", "Add a term to the redaction list (repeatable)")
	flag.Var(&removeTerms, "remove-redact-term", "Remove a term from the default redaction list (repeatable)")
	flag.Parse()

	if !*logTime {
		log.SetFlags(0)
	}
	debug = *debugFlag

	if *showVersion {
		fmt.Println(version)
		os.Exit(0)
	}
	if *repoURL == "" || *patTokenFile == "" {
		fmt.Fprintln(os.Stderr, "Error: --repo-url and --pat-token-file are required")
		flag.Usage()
		os.Exit(1)
	}
	if *httpPort == 0 && *scpPort == 0 {
		fmt.Fprintln(os.Stderr, "Error: at least one of --http-port or --scp-port is required")
		flag.Usage()
		os.Exit(1)
	}
	if *scpPort != 0 && *scpPasswordFile == "" {
		fmt.Fprintln(os.Stderr, "Error: --scp-password-file is required when --scp-port is set")
		flag.Usage()
		os.Exit(1)
	}

	patToken, err := readTokenFile(*patTokenFile)
	if err != nil {
		log.Fatalf("Read PAT token: %v", err)
	}

	var scpPassword string
	if *scpPasswordFile != "" {
		scpPassword, err = readTokenFile(*scpPasswordFile)
		if err != nil {
			log.Fatalf("Read SCP password: %v", err)
		}
	}

	redactTerms := buildRedactTerms(addTerms, removeTerms)
	log.Printf("Redaction terms: %v", redactTerms)

	var sf *stateFile
	if *stateDir != "" {
		sf, err = openStateFile(*stateDir)
		if err != nil {
			log.Fatalf("State file: %v", err)
		}
		defer sf.close()
	}

	pusher := newGitHubPusher(*repoURL, patToken, *branch, *retryInterval)

	if err := pusher.checkRepoVisibility(*allowPublic); err != nil {
		log.Fatalf("Repo visibility check: %v", err)
	}

	if sf != nil {
		items, err := sf.load()
		if err != nil {
			log.Fatalf("Load state: %v", err)
		}
		if len(items) > 0 {
			log.Printf("Restored %d pending commit(s) from state file", len(items))
			for _, cr := range items {
				pusher.enqueue(cr)
			}
		}
	}

	go pusher.run()

	// Signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	hupCh := make(chan os.Signal, 1)
	signal.Notify(hupCh, syscall.SIGHUP)
	go func() {
		for range hupCh {
			t, err := readTokenFile(*patTokenFile)
			if err != nil {
				log.Printf("SIGHUP: failed to reload PAT token: %v", err)
				continue
			}
			pusher.setToken(t)
			log.Println("SIGHUP: reloaded PAT token")
		}
	}()

	// HTTP listener
	var httpSrv *http.Server
	if *httpPort != 0 {
		mux := http.NewServeMux()
		mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		mux.HandleFunc("/archive", func(w http.ResponseWriter, r *http.Request) {
			handleUpload(w, r, pusher, redactTerms)
		})
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		})
		httpAddr := fmt.Sprintf(":%d", *httpPort)
		httpSrv = &http.Server{Addr: httpAddr, Handler: mux}
		log.Printf("version=%s, HTTP listening on %s/archive, repo=%s, branch=%s", version, httpAddr, *repoURL, *branch)
		go func() {
			if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("HTTP server: %v", err)
			}
		}()
	}

	// SCP listener
	var sshSrv *ssh.Server
	if *scpPort != 0 {
		handler := &scpHandler{pusher: pusher, redactTerms: redactTerms}
		scpAddr := net.JoinHostPort("", fmt.Sprintf("%d", *scpPort))
		pw := scpPassword
		user := *scpUsername
		sshSrv, err = wish.NewServer(
			wish.WithAddress(scpAddr),
			wish.WithHostKeyPath(*scpHostKeyPath),
			wish.WithPasswordAuth(func(ctx ssh.Context, pass string) bool {
				return ctx.User() == user && pass == pw
			}),
			wish.WithMiddleware(scp.Middleware(nil, handler)),
		)
		if err != nil {
			log.Fatalf("SCP server: %v", err)
		}
		log.Printf("version=%s, SCP listening on %s, repo=%s, branch=%s", version, scpAddr, *repoURL, *branch)
		if pubKey, err := os.ReadFile(*scpHostKeyPath + ".pub"); err == nil {
			keyStr := strings.TrimSpace(string(pubKey))
			keyStr = strings.Replace(keyStr, "ssh-ed25519", "ed25519-key", 1)
			log.Printf("SCP host public key: %s", keyStr)
		}
		go func() {
			if err := sshSrv.ListenAndServe(); err != nil && !errors.Is(err, ssh.ErrServerClosed) {
				log.Fatalf("SCP server: %v", err)
			}
		}()
	}

	if *httpPort == 0 && *scpPort == 0 {
		log.Fatal("No listeners configured")
	}

	// Wait for shutdown signal
	<-sigCh
	log.Println("Shutting down...")
	if sf != nil {
		pending := pusher.drainPending()
		if len(pending) > 0 {
			if err := sf.save(pending); err != nil {
				log.Printf("Failed to save state: %v", err)
			} else {
				log.Printf("Saved %d pending commit(s) to state file", len(pending))
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if httpSrv != nil {
		httpSrv.Shutdown(ctx)
	}
	if sshSrv != nil {
		sshSrv.Shutdown(ctx)
	}
}

// SCP handler — receives files from clients

type scpHandler struct {
	pusher      *githubPusher
	redactTerms []string
}

func (h *scpHandler) Mkdir(_ ssh.Session, _ *scp.DirEntry) error {
	return nil // ignore directory creation
}

func (h *scpHandler) Write(s ssh.Session, entry *scp.FileEntry) (int64, error) {
	data, err := io.ReadAll(entry.Reader)
	if err != nil {
		return 0, fmt.Errorf("read SCP file: %w", err)
	}

	if debug {
		log.Printf("[DEBUG] SCP user=%s, remote=%s, filepath=%s, name=%s, mode=%o, compressed_size=%d",
			s.User(), s.RemoteAddr(), entry.Filepath, entry.Name, entry.Mode, len(data))
	}

	scpFilename := extractSCPFilename(entry.Filepath, entry.Name)
	processConfig(data, h.pusher, h.redactTerms, scpFilename)
	return int64(len(data)), nil
}

func extractSCPFilename(filepath, name string) string {
	// Strip the name suffix from filepath, then take the rightmost non-empty segment
	trimmed := strings.TrimSuffix(filepath, "/"+name)
	parts := strings.Split(trimmed, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] != "" {
			return parts[i]
		}
	}
	return name
}

// Shared config processing

func processConfig(data []byte, pusher *githubPusher, redactTerms []string, scpFilename string) {
	content, _ := tryDecompress(data)

	if debug {
		log.Printf("[DEBUG] compressed_size=%d, uncompressed_size=%d", len(data), len(content))
	}

	hostname := extractHostname(string(content))
	if hostname == "" {
		hostname = "unknown"
	}

	if debug {
		log.Printf("[DEBUG] hostname=%s", hostname)
	}

	redacted := redactConfig(string(content), redactTerms)

	now := time.Now().UTC()
	sanitized := sanitizeHostname(hostname)
	path := fmt.Sprintf("config-%s.txt", sanitized)

	var msg string
	if scpFilename != "" {
		safeName := sanitizeRe.ReplaceAllString(scpFilename, "_")
		msg = fmt.Sprintf("[%s] %s", strings.ToUpper(hostname), safeName)
	} else {
		msg = fmt.Sprintf("[%s] %s", strings.ToUpper(hostname), now.Format("2006-01-02 15:04:05"))
	}

	pusher.enqueue(commitRequest{
		path:    path,
		content: []byte(redacted),
		message: msg,
		time:    now,
	})

	log.Printf("Queued config from %s", strings.ToUpper(hostname))
}

// HTTP handler

func handleUpload(w http.ResponseWriter, r *http.Request, pusher *githubPusher, redactTerms []string) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Failed to read body: %v", err)
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	if debug {
		log.Printf("[DEBUG] HTTP %s %s remote=%s content-length=%d", r.Method, r.URL.Path, r.RemoteAddr, len(body))
		for name, values := range r.Header {
			log.Printf("[DEBUG] HTTP header %s: %s", name, strings.Join(values, ", "))
		}
	}

	processConfig(body, pusher, redactTerms, "")
	w.WriteHeader(http.StatusCreated)
}

// stateFile manages persistent state for pending commits.

func readTokenFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("token file %s is empty", path)
	}
	return token, nil
}

const stateFileName = "pending.json"

type stateFile struct {
	path string
	file *os.File
}

type persistedCommit struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Message string `json:"message"`
	Time    string `json:"time"`
}

func openStateFile(dir string) (*stateFile, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create state dir: %w", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, fmt.Errorf("chmod state dir: %w", err)
	}

	path := filepath.Join(dir, stateFileName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open state file: %w", err)
	}

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("lock state file (another instance running?): %w", err)
	}

	if _, err := f.WriteString(""); err != nil {
		f.Close()
		return nil, fmt.Errorf("test write to state file: %w", err)
	}

	log.Printf("State file: %s", path)
	return &stateFile{path: path, file: f}, nil
}

func (sf *stateFile) load() ([]commitRequest, error) {
	info, err := sf.file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() == 0 {
		return nil, nil
	}

	if _, err := sf.file.Seek(0, 0); err != nil {
		return nil, err
	}

	var items []persistedCommit
	if err := json.NewDecoder(sf.file).Decode(&items); err != nil {
		return nil, fmt.Errorf("decode state file: %w", err)
	}

	if err := sf.file.Truncate(0); err != nil {
		return nil, fmt.Errorf("truncate state file: %w", err)
	}
	if _, err := sf.file.Seek(0, 0); err != nil {
		return nil, err
	}

	var result []commitRequest
	for _, item := range items {
		content, err := base64.StdEncoding.DecodeString(item.Content)
		if err != nil {
			log.Printf("Skipping corrupt state entry for %s: %v", item.Path, err)
			continue
		}
		t, _ := time.Parse(time.RFC3339, item.Time)
		result = append(result, commitRequest{
			path:    item.Path,
			content: content,
			message: item.Message,
			time:    t,
		})
	}
	return result, nil
}

func (sf *stateFile) save(items []commitRequest) error {
	var persisted []persistedCommit
	for _, cr := range items {
		persisted = append(persisted, persistedCommit{
			Path:    cr.path,
			Content: base64.StdEncoding.EncodeToString(cr.content),
			Message: cr.message,
			Time:    cr.time.Format(time.RFC3339),
		})
	}

	if err := sf.file.Truncate(0); err != nil {
		return err
	}
	if _, err := sf.file.Seek(0, 0); err != nil {
		return err
	}

	enc := json.NewEncoder(sf.file)
	enc.SetIndent("", "  ")
	if err := enc.Encode(persisted); err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	return sf.file.Sync()
}

func (sf *stateFile) close() {
	syscall.Flock(int(sf.file.Fd()), syscall.LOCK_UN)
	sf.file.Close()
}

// Redaction and config parsing

var defaultRedactTerms = []string{"secret", "local-name", "local-password", "encrypted-password"}

func buildRedactTerms(add, remove []string) []string {
	removeSet := make(map[string]bool)
	for _, t := range remove {
		removeSet[strings.ToLower(t)] = true
	}
	var terms []string
	for _, t := range defaultRedactTerms {
		if !removeSet[strings.ToLower(t)] {
			terms = append(terms, strings.ToLower(t))
		}
	}
	for _, t := range add {
		terms = append(terms, strings.ToLower(t))
	}
	return terms
}

func redactConfig(content string, terms []string) string {
	var out []string
	for _, line := range strings.Split(content, "\n") {
		lower := strings.ToLower(line)
		matched := false
		for _, term := range terms {
			if strings.Contains(lower, term) {
				matched = true
				break
			}
		}
		if !matched {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

func tryDecompress(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return data, nil
	}
	defer r.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		return data, nil
	}
	return out, nil
}

func extractHostname(config string) string {
	m := hostnameRe.FindStringSubmatch(config)
	if len(m) < 3 {
		return ""
	}
	// Group 1 = set format, Group 2 = curly-brace format
	if m[1] != "" {
		return m[1]
	}
	return m[2]
}

func sanitizeHostname(h string) string {
	return sanitizeRe.ReplaceAllString(strings.ToLower(h), "_")
}

// Commit queue and GitHub pusher

type commitRequest struct {
	path    string
	content []byte
	message string
	time    time.Time
	retryAt time.Time
	is4xx   bool
}

const minRetry4xx = 7200 * time.Second

type githubPusher struct {
	apiBase       string
	tokenMu       sync.RWMutex
	token         string
	branch        string
	retryInterval time.Duration
	queue         chan commitRequest
	mu            sync.Mutex
	pending       []commitRequest
}

func newGitHubPusher(repoURL, token, branch string, retryInterval time.Duration) *githubPusher {
	repoURL = strings.TrimSuffix(strings.TrimSuffix(repoURL, ".git"), "/")
	apiBase := strings.Replace(repoURL, "https://github.com/", "https://api.github.com/repos/", 1)
	return &githubPusher{
		apiBase:       apiBase,
		token:         token,
		branch:        branch,
		retryInterval: retryInterval,
		queue:         make(chan commitRequest, 1000),
	}
}

func (g *githubPusher) getToken() string {
	g.tokenMu.RLock()
	defer g.tokenMu.RUnlock()
	return g.token
}

func (g *githubPusher) setToken(t string) {
	g.tokenMu.Lock()
	defer g.tokenMu.Unlock()
	g.token = t
}

func (g *githubPusher) checkRepoVisibility(allowPublic bool) error {
	req, err := http.NewRequest(http.MethodGet, g.apiBase, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+g.getToken())
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach GitHub API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GitHub API %d: %s", resp.StatusCode, string(body))
	}

	var repo struct {
		Private bool `json:"private"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&repo); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	if !repo.Private && !allowPublic {
		return fmt.Errorf("repository is public; use --allow-public-repo to override")
	}
	if !repo.Private {
		log.Println("WARNING: pushing to a public repository")
	}
	return nil
}

type commitError struct {
	err   error
	is4xx bool
}

func (e *commitError) Error() string { return e.err.Error() }

func (g *githubPusher) enqueue(cr commitRequest) {
	g.queue <- cr
}

func (g *githubPusher) drainPending() []commitRequest {
	g.mu.Lock()
	defer g.mu.Unlock()
	for {
		select {
		case cr := <-g.queue:
			g.pending = append(g.pending, cr)
		default:
			items := g.pending
			g.pending = nil
			return items
		}
	}
}

func (g *githubPusher) run() {
	retryTicker := time.NewTicker(g.retryInterval)
	defer retryTicker.Stop()
	for {
		select {
		case cr := <-g.queue:
			if err := g.commit(cr); err != nil {
				ce := err.(*commitError)
				delay := g.retryInterval
				if ce.is4xx && delay < minRetry4xx {
					delay = minRetry4xx
				}
				cr.retryAt = time.Now().Add(delay)
				cr.is4xx = ce.is4xx
				log.Printf("Commit failed for %s, next retry in %s: %v", cr.path, delay, err)
				g.mu.Lock()
				g.pending = append(g.pending, cr)
				g.mu.Unlock()
			}
		case <-retryTicker.C:
			g.retryPending()
		}
	}
}

func (g *githubPusher) retryPending() {
	g.mu.Lock()
	items := g.pending
	g.pending = nil
	g.mu.Unlock()

	now := time.Now()
	for _, cr := range items {
		if now.Before(cr.retryAt) {
			g.mu.Lock()
			g.pending = append(g.pending, cr)
			g.mu.Unlock()
			continue
		}
		if err := g.commit(cr); err != nil {
			ce := err.(*commitError)
			delay := g.retryInterval
			if ce.is4xx && delay < minRetry4xx {
				delay = minRetry4xx
			}
			cr.retryAt = time.Now().Add(delay)
			cr.is4xx = ce.is4xx
			log.Printf("Retry failed for %s, next retry in %s: %v", cr.path, delay, err)
			g.mu.Lock()
			g.pending = append(g.pending, cr)
			g.mu.Unlock()
		}
	}
}

func (g *githubPusher) commit(cr commitRequest) error {
	sha, err := g.getFileSHA(cr.path)
	if err != nil {
		return &commitError{err: fmt.Errorf("get file SHA: %w", err), is4xx: isHTTP4xx(err)}
	}

	payload := map[string]interface{}{
		"message": cr.message,
		"content": base64.StdEncoding.EncodeToString(cr.content),
		"branch":  g.branch,
		"committer": map[string]string{
			"name":  "junos-config-archiver",
			"email": "junos-config-archiver@noreply",
		},
	}
	if sha != "" {
		payload["sha"] = sha
	}

	body, _ := json.Marshal(payload)
	url := fmt.Sprintf("%s/contents/%s", g.apiBase, cr.path)

	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		return &commitError{err: err, is4xx: false}
	}
	req.Header.Set("Authorization", "Bearer "+g.getToken())
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return &commitError{err: fmt.Errorf("HTTP request: %w", err), is4xx: false}
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		respBody, _ := io.ReadAll(resp.Body)
		return &commitError{
			err:   fmt.Errorf("GitHub API %d: %s", resp.StatusCode, string(respBody)),
			is4xx: resp.StatusCode >= 400 && resp.StatusCode < 500,
		}
	}

	log.Printf("Committed %s: %s", cr.path, cr.message)
	return nil
}

func isHTTP4xx(err error) bool {
	return strings.Contains(err.Error(), "GitHub API 4")
}

func (g *githubPusher) getFileSHA(path string) (string, error) {
	url := fmt.Sprintf("%s/contents/%s?ref=%s", g.apiBase, path, g.branch)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+g.getToken())
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return "", nil
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("GitHub API %d", resp.StatusCode)
	}

	var result struct {
		SHA string `json:"sha"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	return result.SHA, nil
}
