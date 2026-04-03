# junos-config-to-github

HTTP server that receives Junos device configuration archives and commits them directly to a GitHub repository via the GitHub API. No local git checkout or disk writes required.

## Features

- Receives gzip-compressed or plain-text Junos configs via HTTP PUT/POST
- Extracts hostname from `set system host-name` in the config
- Redacts sensitive lines (secrets, passwords, credentials) before committing
- Commits directly to GitHub using the Contents API (no local git)
- Serialized commit queue preserves the order configs were received
- Automatic retry for failed GitHub pushes
- Refuses to push to public repos unless explicitly allowed
- Configurable redaction term list

## Usage

```
junos-config-to-github \
  --repo-url https://github.com/youruser/junos-configs \
  --pat-token ghp_xxxxxxxxxxxx \
  --port 8000 \
  --branch main \
  --retry-interval 30s
```

### CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--repo-url` | (required) | GitHub repository URL |
| `--pat-token` | (required) | GitHub Personal Access Token |
| `--port` | `8000` | HTTP listen port |
| `--branch` | `main` | Git branch to commit to |
| `--retry-interval` | `900s` | Retry interval for connection-related failures |

### Retry Behavior

Failed GitHub pushes are retried automatically. The retry interval depends on the type of error:

- Connection errors (timeouts, DNS failures, resets): retried at `--retry-interval` (default 900s)
- HTTP 4xx errors (authentication failures, invalid requests, permission denied): retried at a minimum of 7200s (2 hours), since these typically require manual intervention to resolve

### State Persistence

When `--state-dir` is specified, pending commits that haven't been pushed to GitHub are saved to a JSON state file (`pending.json`) on graceful shutdown (SIGINT/SIGTERM). On the next startup, these are loaded back into the push queue.

- The state directory is set to `o-rwx` (mode 0700) at startup
- An exclusive file lock prevents multiple instances from using the same state directory
- The state file is truncated to empty immediately after loading pending items into the queue
- The state file remains empty during normal operation; it is only written during shutdown
| `--allow-public-repo` | `false` | Allow pushing to public repositories |
| `--state-dir` | | Directory to persist pending pushes across restarts |
| `--add-redact-term` | | Add a redaction term (repeatable) |
| `--remove-redact-term` | | Remove a default redaction term (repeatable) |
| `--version` | | Print version and exit |

### Redaction

Lines containing any of the following terms (case-insensitive) are removed before committing:

- `secret`
- `local-name`
- `local-password`
- `encrypted-password`

Customize with `--add-redact-term` and `--remove-redact-term`:

```
junos-config-to-github \
  --repo-url https://github.com/youruser/junos-configs \
  --pat-token ghp_xxxxxxxxxxxx \
  --add-redact-term "community" \
  --add-redact-term "pre-shared-key" \
  --remove-redact-term "local-name"
```

### Endpoints

| Path | Method | Description |
|------|--------|-------------|
| `/archive` | PUT, POST | Receive Junos config archive |
| `/health` | GET | Health check |

## GitHub PAT Token

Create a fine-grained Personal Access Token at https://github.com/settings/tokens with:

- Repository access: select the target repo
- Permissions: Contents (Read and write)

## Junos Configuration

Configure the SRX/Junos device to archive configs on commit:

```junos
set system archival configuration transfer-on-commit
set system archival configuration archive-sites "http://<server-ip>:8000/archive"
```

Replace `<server-ip>` with the IP address or hostname of the server running junos-config-to-github.

## Output

Each config is stored as `config-<hostname>.txt` in the repo root. Commit messages follow the format:

```
[FR1] 2026-04-03 14:30:00
```

## Building

```
go build -o junos-config-to-github .
```

Cross-compile for Linux:

```
GOOS=linux GOARCH=amd64 go build -o junos-config-to-github-linux-amd64 .
GOOS=linux GOARCH=arm64 go build -o junos-config-to-github-linux-arm64 .
```
