# DevSecret

**Local, encrypted vault for API keys and 2FA recovery codes** — one master password, no cloud, no daemons.

## Features

- **AES-256-GCM** vault files with **PBKDF2-HMAC-SHA256** key derivation (600k iterations)
- **API keys** per site + username, optional **expiry** (default 90 days) with stderr warnings (14-day window)
- **Recovery codes** stored separately from API keys; batch input via flags, stdin, or interactive prompt
- **Plaintext sidecar index** (`vault.enc.index.json`) listing only site/username + expiry metadata — enables `list-keys` without decrypting secrets
- Optional **auto-delete** of expired API keys when the vault is loaded (configurable)

## Requirements

- Python **3.10+**
- [cryptography](https://pypi.org/project/cryptography/) ≥ 42

## Install

```bash
git clone <repository-url>
cd Crypto_Project
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

The `devsecret` command is provided via `[project.scripts]` (editable install).


## Example usage

Use `--vault PATH` or set **`DEVSECRET_VAULT`** to override the default vault path.

**`add-key`** — prompts for master password, then API key (hidden). Default expiry is 90 days unless you override:

```bash
devsecret add-key --site api.openai.com --username work
devsecret add-key --site github.com --username alice --expiry 2026-12-31
devsecret add-key --site internal.corp --username bot --no-expiry
devsecret add-key --site aws --username root --vault ~/.config/devsecret/prod.enc
```

**`add-recovery`** — codes via flags (comma-separated or repeated `--codes`), or omit flags to read from stdin / interactive lines:

```bash
devsecret add-recovery --site github.com --username alice --codes ABCD-EFGH,IJKL-MNOP
devsecret add-recovery --site gitlab.com --username alice --codes CODE1 --codes CODE2
printf '%s\n' '11111-11111' '22222-22222' | devsecret add-recovery --site dropbox.com --username bob
```

**`list-keys`** — site and username only (reads `vault.enc.index.json`; no API key material):

```bash
devsecret list-keys
devsecret list-keys --vault ~/.config/devsecret/prod.enc
```

**`get-key`** — prints the secret to **stdout**; expiry warnings / expiry line go to **stderr**:

```bash
export OPENAI_API_KEY="$(devsecret get-key --site api.openai.com --username work)"
devsecret get-key --site github.com --username alice
```

**`get-recovery`** — prints stored codes, one per line (master password required):

```bash
devsecret get-recovery --site github.com --username alice
```

## Vault location

| Priority | Source |
|----------|--------|
| 1 | `--vault PATH` |
| 2 | `DEVSECRET_VAULT` |
| 3 | `~/.devsecret/vault.enc` |

## Commands

| Command | Purpose |
|---------|---------|
| `init` | Create an empty vault (`--force` to overwrite) |
| `add-key` | Store an API key (`--expiry YYYY-MM-DD`, `--no-expiry`, or default 90 days) |
| `add-recovery` | Store recovery codes (`--codes` repeatable or comma-separated; else stdin / prompt) |
| `list-keys` | Print site/username for API keys (uses sidecar index) |
| `list-recovery` | Print site/username for recovery entries (decrypts vault) |
| `get-key` | Print API key to stdout; expiry on stderr when set |
| `get-recovery` | Print recovery codes |
| `configure` | `--enable-auto-delete-expired-api-keys` / `--disable-auto-delete-expired-api-keys` |

Global option: **`--vault PATH`** on any command.

## Security notes

- Protect the **vault file** and **master password** like any secret material; anyone with both can read the data.
- The **index file** is not encrypted: it only exposes site, username, and expiry strings — not key material.
- This tool does **not** replace a full secrets manager for teams or HSM-backed workflows; it is aimed at **local developer** use.

## Development

```bash
pip install -e ".[dev]"
pytest
```
