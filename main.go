package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

var version = "dev"

var hostnameRe = regexp.MustCompile(`(?m)^set\s+system\s+host-name\s+(\S+)`)
var sanitizeRe = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ", ") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	showVersion := flag.Bool("version", false, "Print version and exit")
	port := flag.Int("port", 8000, "HTTP port to listen on")
	repoURL := flag.String("repo-url", "", "GitHub repo URL (required, e.g. https://github.com/user/repo)")
	patToken := flag.String("pat-token", "", "GitHub PAT token (required)")
	branch := flag.String("branch", "main", "Git branch")
	retryInterval := flag.Duration("retry-interval", 900*time.Second, "Retry interval for failed pushes (connection errors)")
	allowPublic := flag.Bool("allow-public-repo", false, "Allow pushing to public repositories")
	stateDir := flag.String("state-dir", "", "Directory to store state file for pending pushes across restarts")
	var addTerms, removeTerms stringList
	flag.Var(&addTerms, "add-redact-term", "Add a term to the redaction list (repeatable)")
	flag.Var(&removeTerms, "remove-redact-term", "Remove a term from the default redaction list (repeatable)")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		os.Exit(0)
	}
	if *repoURL == "" || *patToken == "" {
		fmt.Fprintln(os.Stderr, "Error: --repo-url and --pat-token are required")
		flag.Usage()
		os.Exit(1)
	}

	redactTerms := buildRedactTerms(addTerms, removeTerms)
	log.Printf("Redaction terms: %v", redactTerms)

	var sf *stateFile
	if *stateDir != "" {
		var err error
		sf, err = openStateFile(*stateDir)
		if err != nil {
			log.Fatalf("State file: %v", err)
		}
		defer sf.close()
	}

	pusher := newGitHubPusher(*repoURL, *patToken, *branch, *retryInterval)

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

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	http.HandleFunc("/archive", func(w http.ResponseWriter, r *http.Request) {
		handleUpload(w, r, pusher, redactTerms)
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("version=%s, listening on %s/archive, repo=%s, branch=%s", version, addr, *repoURL, *branch)

	srv := &http.Server{Addr: addr}
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
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
		srv.Shutdown(ctx)
	}()

	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

// stateFile manages persistent state for pending commits.

const stateFileName = "pending.json"

type stateFile struct {
	path string
	file *os.File
}

type persistedCommit struct {
	Path    string `json:"path"`
	Content string `json:"content"` // base64-encoded
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

	// Test write
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

	// Truncate immediately after reading
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

// redaction and config parsing

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

	content, err := tryDecompress(body)
	if err != nil {
		log.Printf("Failed to decompress: %v", err)
		http.Error(w, "Failed to decompress", http.StatusBadRequest)
		return
	}

	hostname := extractHostname(string(content))
	if hostname == "" {
		hostname = "unknown"
	}

	redacted := redactConfig(string(content), redactTerms)

	now := time.Now().UTC()
	sanitized := sanitizeHostname(hostname)
	path := fmt.Sprintf("config-%s.txt", sanitized)
	msg := fmt.Sprintf("[%s] %s", strings.ToUpper(hostname), now.Format("2006-01-02 15:04:05"))

	pusher.enqueue(commitRequest{
		path:    path,
		content: []byte(redacted),
		message: msg,
		time:    now,
	})

	log.Printf("Queued config from %s", strings.ToUpper(hostname))
	w.WriteHeader(http.StatusCreated)
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
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

func sanitizeHostname(h string) string {
	return sanitizeRe.ReplaceAllString(strings.ToLower(h), "_")
}

// commit queue and GitHub pusher

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

func (g *githubPusher) checkRepoVisibility(allowPublic bool) error {
	req, err := http.NewRequest(http.MethodGet, g.apiBase, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+g.token)
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

	// Drain the queue channel too
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
	req.Header.Set("Authorization", "Bearer "+g.token)
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
	req.Header.Set("Authorization", "Bearer "+g.token)
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
