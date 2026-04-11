# junos-config-to-github

HTTP and SCP server that receives Junos device configuration archives and commits them directly to a GitHub repository via the GitHub API. No local git checkout or disk writes required.

## Features

- Receives gzip-compressed or plain-text Junos configs via HTTP PUT/POST or SCP
- Extracts hostname from `set system host-name` in the config
- Redacts sensitive lines (secrets, passwords, credentials) before committing
- Commits directly to GitHub using the Contents API (no local git)
- Serialized commit queue preserves the order configs were received
- Automatic retry for failed GitHub pushes
- Refuses to push to public repos unless explicitly allowed
- Configurable redaction term list
- Optional state persistence for pending pushes across restarts

## Usage

HTTP only:

```
junos-config-to-github \
  --repo-url https://github.com/youruser/junos-configs \
  --pat-token-file /path/to/pat-token.txt \
  --http-port 8000
```

SCP only:

```
junos-config-to-github \
  --repo-url https://github.com/youruser/junos-configs \
  --pat-token-file /path/to/pat-token.txt \
  --scp-port 2222 \
  --scp-password-file /path/to/scp-password.txt \
  --scp-host-key /path/to/id_ed25519
```

Both listeners:

```
junos-config-to-github \
  --repo-url https://github.com/youruser/junos-configs \
  --pat-token-file /path/to/pat-token.txt \
  --http-port 8000 \
  --scp-port 2222 \
  --scp-password-file /path/to/scp-password.txt
```

### CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--repo-url` | (required) | GitHub repository URL |
| `--pat-token-file` | (required) | Path to file containing GitHub PAT token |
| `--http-port` | | HTTP port (enables HTTP listener when set) |
| `--scp-port` | | SCP/SSH port (enables SCP listener when set) |
| `--scp-password-file` | | Path to file containing SCP password (required with `--scp-port`) |
| `--scp-username` | `archive` | Required SCP username |
| `--scp-host-key` | `.junos/id_ed25519` | Path to SSH host key for SCP server |
| `--branch` | `main` | Git branch to commit to |
| `--repo-path` | `config-${hostname}.txt` | Path template for config files in the repo (`${hostname}` is replaced with the sanitized hostname) |
| `--retry-interval` | `900s` | Retry interval for connection-related failures |
| `--allow-public-repo` | `false` | Allow pushing to public repositories |
| `--state-dir` | | Directory to persist pending pushes across restarts |
| `--add-redact-term` | | Add a redaction term (repeatable) |
| `--remove-redact-term` | | Remove a default redaction term (repeatable) |
| `--debug` | `false` | Log HTTP headers, SCP details, compressed/uncompressed sizes |
| `--log-time` | `false` | Include date-time prefix in log messages |
| `--version` | | Print version and exit |

At least one of `--http-port` or `--scp-port` must be specified.

### HTTP Endpoints

| Path | Method | Description |
|------|--------|-------------|
| `/archive` | PUT, POST | Receive Junos config archive |
| `/health` | GET | Health check |

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
  --pat-token-file /path/to/pat-token.txt \
  --http-port 8000 \
  --add-redact-term "community" \
  --add-redact-term "pre-shared-key" \
  --remove-redact-term "local-name"
```

## GitHub PAT Token

Create a fine-grained Personal Access Token at https://github.com/settings/tokens with:

- Repository access: select the target repo
- Repository permissions:
  - Contents: Read and write (commit config files)
  - Metadata: Read-only (check repo visibility; granted by default)

Store the token in a file (e.g. `/etc/junos-config-to-github/pat-token.txt`) and pass the path via `--pat-token-file`.

Send `SIGHUP` to reload the token file without restarting the server (e.g. after rotating the PAT):

```
kill -HUP $(pidof junos-config-to-github)
```

## Junos Configuration

### HTTP archival

```junos
set system archival configuration transfer-on-commit
set system archival configuration archive-sites "http://<server-ip>:8000/archive"
```

### SCP archival

```junos
set system archival configuration transfer-on-commit
set system archival configuration archive-sites "scp://archive:<password>@<server-ip>:2222/archive/"
```

Replace `<server-ip>` with the IP address or hostname of the server. The username must match `--scp-username` (default `archive`).

### SCP Host Key

The SSH host key is read from `--scp-host-key` (default `.junos/id_ed25519`). If the file doesn't exist, it is auto-generated on first run. The base64 public key is logged at startup for use with Junos `ssh-known-hosts`:

```junos
set security ssh-known-hosts host <server-ip> ed25519-key <base64-key>
```

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
